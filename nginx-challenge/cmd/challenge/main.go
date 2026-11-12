// Commande nginx-challenge : voir internal/challenge.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nginx-challenge/internal/challenge"
	"nginx-challenge/internal/decisions"
)

func main() {
	cfg, err := challenge.LoadConfig(os.Getenv)
	if err != nil {
		log.Fatalf("configuration invalide : %v", err)
	}
	if cfg.SecretGenerated {
		log.Printf("ATTENTION : NC_SECRET absent — secret aléatoire tiré au démarrage ; les cookies de vérification seront invalidés à chaque redémarrage (et ne sont pas partagés entre instances).")
	}
	srv, err := challenge.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	// Decisions vers le log store, via l'API locale du shipper (NC_SHIPPER_URL vide = desactive).
	decCtx, decStop := context.WithCancel(context.Background())
	decDone := make(chan struct{})
	dec, derr := decisions.New(decisions.Config{URL: cfg.ShipperURL, Token: cfg.ShipperToken})
	if derr != nil {
		log.Printf("envoi des décisions désactivé : %v", derr)
	}
	if dec != nil {
		srv.SetEmitter(dec)
		go func() { dec.Run(decCtx); close(decDone) }()
		log.Printf("décisions envoyées au shipper local")
	} else {
		close(decDone)
	}
	var pers *challenge.Persister
	if cfg.RedisURL != "" {
		pers, err = challenge.NewPersister(cfg.RedisURL, cfg.RedisPassword, cfg.RedisPrefix, srv)
		if err != nil {
			log.Fatalf("NC_REDIS_URL : %v", err)
		}
		if rerr := pers.Restore(); rerr != nil {
			log.Printf("Redis %s injoignable (%v) — démarrage sans persistance, nouvelle tentative à chaque sauvegarde", pers.Addr(), rerr)
		} else {
			log.Printf("Redis %s : état restauré %v", pers.Addr(), pers.Restored)
		}
	}
	hs := &http.Server{
		Addr: cfg.Bind, Handler: srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	go func() {
		log.Printf("nginx-challenge à l'écoute sur %s (difficulté %d bits, cookie %s) — %s", cfg.Bind, cfg.Bits, cfg.CookieTTL, cfg.Offenders.Describe())
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	flushStop := make(chan struct{})
	flushDone := make(chan struct{})
	go func() { srv.Stats().RunFlusher(flushStop, time.Minute); close(flushDone) }()
	persStop := make(chan struct{})
	persDone := make(chan struct{})
	if pers != nil {
		go func() { pers.Run(persStop); close(persDone) }()
	} else {
		close(persDone)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	close(flushStop)
	<-flushDone
	close(persStop)
	<-persDone
	decStop() // après l'arrêt du serveur : les dernières décisions sont déjà en file
	<-decDone
}
