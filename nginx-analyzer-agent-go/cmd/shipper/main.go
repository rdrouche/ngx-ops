// Commande shipper : lit les access logs nginx et les expédie au log store.
// Sous-commande « healthcheck » : interroge /healthz de l'instance locale (HEALTHCHECK Docker).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"nginx-analyzer-go/internal/shipper"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := shipper.FromEnv()
	if err != nil {
		log.Error("configuration invalide", "err", err.Error())
		os.Exit(2)
	}
	s, err := shipper.New(cfg, log)
	if err != nil {
		log.Error("démarrage impossible", "err", err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Error("arrêt sur erreur", "err", err.Error())
		os.Exit(1)
	}
	log.Info("shipper arrêté")
}

func healthcheck() int {
	addr := strings.TrimSpace(os.Getenv("LOGSHIP_LISTEN"))
	if addr == "" {
		addr = "127.0.0.1:9181"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck : injoignable")
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}
