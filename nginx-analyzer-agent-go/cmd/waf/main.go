// Command waf : WAF emule (Coraza DetectionOnly + OWASP CRS) qui analyse a posteriori les logs
// d'acces nginx. Jamais de blocage direct : il produit hits, alertes et listes d'IP
// (challenge / block) consommees par le dashboard. API HTTP interne (X-WAF-Token) sur PORT.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"nginx-analyzer-go/internal/decisions"
	"nginx-analyzer-go/internal/waf/httpapi"
	"nginx-analyzer-go/internal/waf/service"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		log.Printf("[waf] %s invalide (%q), valeur par defaut %d", name, v, def)
		return def
	}
	return n
}

func pattern(name, def string) *regexp.Regexp {
	raw := env(name, def)
	re, err := regexp.Compile(raw)
	if err != nil {
		log.Printf("[waf] %s invalide, motif par defaut utilise", name)
		re = regexp.MustCompile(def)
	}
	return re
}

func main() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(60)
	}
	log.Printf("[waf] demarrage (%s/%s, %s)", runtime.GOOS, runtime.GOARCH, runtime.Version())
	port := envInt("PORT", 9101, 1, 65535)
	token := os.Getenv("WAF_TOKEN")
	if token == "" {
		log.Printf("[waf] ATTENTION : WAF_TOKEN vide, l'API n'est pas authentifiee (reseau interne uniquement)")
	}
	cfg := service.Config{
		Version:             env("APP_VERSION", "dev"),
		LogsDir:             env("LOGS_DIR", "/nginx/logs"),
		LogPattern:          pattern("LOG_PATTERN", `(^|[._])access\.log$`),
		WafLogPattern:       pattern("WAF_LOG_PATTERN", `(^|[._-])wafemu\.log$`),
		DataDir:             env("DATA_DIR", "/waf"),
		RulesDir:            env("RULES_DIR", "/waf-rules"),
		CRSVersion:          env("CRS_VERSION", "v4.8.0"),
		CRSURLTemplate:      env("CRS_URL_TEMPLATE", ""),
		HitRetentionDays:    envInt("HIT_RETENTION_DAYS", 30, 1, 3650),
		DBCompactOnStart:    env("DB_COMPACT_ON_START", "auto"),
		DBCompactMinFreeMb:  envInt("DB_COMPACT_MIN_FREE_MB", 16, 1, 1_000_000),
		DBCompactMinFreePct: envInt("DB_COMPACT_MIN_FREE_PCT", 20, 1, 100),
		AlertRetentionDays:  envInt("ALERT_RETENTION_DAYS", 90, 1, 3650),
		Workers:             envInt("WAF_WORKERS", 0, 0, 64), // 0 = GOMAXPROCS-1
	}
	// Decisions vers le log store, via l'API locale du shipper (SHIPPER_URL vide = desactive).
	dec, err := decisions.New(decisions.Config{URL: os.Getenv("SHIPPER_URL"), Token: os.Getenv("SHIPPER_TOKEN"), Logger: slog.Default()})
	if err != nil {
		log.Printf("[waf] envoi des decisions desactive : %v", err)
	}
	decCtx, decStop := context.WithCancel(context.Background())
	decDone := make(chan struct{})
	if dec != nil {
		cfg.Decisions = dec
		go func() { dec.Run(decCtx); close(decDone) }()
		log.Printf("[waf] decisions envoyees au shipper local")
	} else {
		close(decDone)
	}
	svc, err := service.New(cfg)
	if err != nil {
		log.Fatalf("[waf] initialisation : %v", err)
	}

	// L'API est ouverte AVANT le chargement du moteur (et du telechargement eventuel du CRS).
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("[waf] impossible d'ecouter sur :%d : %v", port, err)
	}
	srv := &http.Server{
		Handler:           httpapi.New(svc, token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[waf] %v", err)
		}
	}()
	svc.Start()
	log.Printf("[waf] :%d  logs=%s  donnees=%s  regles=%s", port, cfg.LogsDir, cfg.DataDir, cfg.RulesDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Printf("[waf] arret en cours")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	svc.Close()
	decStop() // apres svc.Close() : les derniers hits sont deja en file
	<-decDone
	log.Printf("[waf] arrete")
}
