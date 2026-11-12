// Commande logstore : service de stockage et de consultation des journaux.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ngxops/logstore/internal/api"
	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/config"
	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "logstore :", err)
		os.Exit(1)
	}
}

// healthcheck interroge /v1/health en boucle locale (HEALTHCHECK du conteneur,
// l'image n'a pas de shell). Aucun secret n'est envoyé ; la vérification du
// certificat est omise car la cible est toujours 127.0.0.1.
func healthcheck() int {
	cfg, _ := config.FromEnv(nil)
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || port == "" {
		port = "8443"
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if cfg.TLSCert != "" {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // boucle locale uniquement
	}
	resp, err := client.Get(scheme + "://127.0.0.1:" + port + "/v1/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.FromEnv(nil)
	if err != nil {
		return err
	}
	lvl := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, store.Options{
		AdminURL: cfg.DatabaseURL, ReadURL: cfg.DatabaseRead, WriteURL: cfg.DatabaseWrite,
		QueryTimeout: cfg.QueryTimeout, RequireTimescale: cfg.RequireTimescale,
		SeedRetentionDays: cfg.RetentionDays, SeedIPMode: cfg.IPMode,
		PseudoKeyPresent: ipmode.New(cfg.PseudoKey).HasKey(),
	}, log)
	if err != nil {
		return err
	}
	defer st.Close()

	var boot []byte
	if cfg.AdminToken != "" {
		boot = auth.Hash(cfg.AdminToken)
	}
	if err := st.EnsureBootstrapAdmin(ctx, boot); err != nil {
		return err
	}

	srv := api.New(cfg, st, log)
	if err := srv.ReloadTokens(ctx); err != nil {
		return err
	}

	go background(ctx, cfg, srv, st, log)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("log store démarré", "listen", cfg.Listen, "tls", cfg.TLSCert != "", "timescale", st.Timescale(), "version", api.Version)
		if cfg.TLSCert != "" {
			errc <- hs.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			log.Warn("HTTP sans TLS (LOGSTORE_INSECURE_HTTP) : à réserver à un réseau interne ou derrière un proxy TLS")
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}
	return nil
}

// background : rechargement des jetons et réglages, usage des jetons, purge.
func background(ctx context.Context, cfg config.Config, srv *api.Server, st *store.Store, log *slog.Logger) {
	fast := time.NewTicker(15 * time.Second)
	slow := time.NewTicker(10 * time.Minute)
	defer fast.Stop()
	defer slow.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			if err := srv.ReloadTokens(ctx); err != nil {
				log.Warn("rechargement des jetons", "err", "base indisponible")
			}
			if err := st.Refresh(ctx); err != nil {
				log.Warn("rechargement des réglages", "err", "base indisponible")
			}
			srv.FlushTokenUsage(ctx)
		case <-slow.C:
			if err := st.Maintain(ctx); err != nil {
				log.Warn("maintenance", "err", "échec (voir base)")
			}
			if cfg.MaintenanceEnabled && st.MaintenanceDue(cfg.MaintenanceInterval) {
				go func() {
					mctx, cancel := context.WithTimeout(ctx, time.Hour)
					defer cancel()
					if _, err := st.RunMaintenance(mctx, "schedule"); err != nil && !errors.Is(err, store.ErrMaintenanceBusy) {
						log.Warn("VACUUM planifié", "err", "échec (voir /v1/maintenance)")
					}
				}()
			}
		}
	}
}
