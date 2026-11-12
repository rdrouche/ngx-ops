// Package config lit la configuration du log store depuis l'environnement.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ngxops/logstore/internal/ipmode"
)

// Bornes de la rétention des journaux bruts (jours).
const (
	MinRetentionDays = 7
	MaxRetentionDays = 30
)

// Config est la configuration du service.
type Config struct {
	Listen        string
	DatabaseURL   string // rôle administrateur (DDL, réglages, jetons)
	DatabaseRead  string // rôle SELECT seul (défaut : DatabaseURL)
	DatabaseWrite string // rôle INSERT seul (défaut : DatabaseURL)

	TLSCert, TLSKey string
	InsecureHTTP    bool

	AdminToken string // jeton d'amorçage (haché au premier démarrage)
	PseudoKey  string

	IPMode           ipmode.Mode // valeur d'amorçage (réglage ensuite en base)
	RetentionDays    int         // valeur d'amorçage
	RequireTimescale bool

	MaxBodyBytes   int64
	MaxBatchEvents int
	RateRead       float64 // requêtes/s par jeton de lecture
	RateWrite      float64 // requêtes/s par jeton d'écriture
	QueryTimeout   time.Duration
	LogLevel       string
	UIEnabled      bool // interface web de gestion des jetons (/ui/), LOGSTORE_UI=false pour la couper

	MaintenanceEnabled  bool          // VACUUM (ANALYZE) planifié (#96), LOGSTORE_MAINTENANCE=false pour le couper
	MaintenanceInterval time.Duration // LOGSTORE_MAINTENANCE_HOURS (défaut 24)
}

// FromEnv construit la configuration. get permet les tests (os.Getenv par défaut).
func FromEnv(get func(string) string) (Config, error) {
	if get == nil {
		get = os.Getenv
	}
	str := func(k, d string) string {
		if v := strings.TrimSpace(get(k)); v != "" {
			return v
		}
		return d
	}
	var errs []error
	num := func(k string, d float64) float64 {
		v := strings.TrimSpace(get(k))
		if v == "" {
			return d
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 {
			errs = append(errs, fmt.Errorf("%s invalide : %q", k, v))
			return d
		}
		return f
	}

	c := Config{
		Listen:           str("LOGSTORE_LISTEN", ":8443"),
		DatabaseURL:      str("LOGSTORE_DATABASE_URL", ""),
		TLSCert:          str("LOGSTORE_TLS_CERT", ""),
		TLSKey:           str("LOGSTORE_TLS_KEY", ""),
		InsecureHTTP:     strings.EqualFold(str("LOGSTORE_INSECURE_HTTP", ""), "true"),
		AdminToken:       str("LOGSTORE_ADMIN_TOKEN", ""),
		PseudoKey:        str("LOGSTORE_PSEUDO_KEY", ""),
		RequireTimescale: strings.EqualFold(str("LOGSTORE_REQUIRE_TIMESCALE", ""), "true"),
		MaxBodyBytes:     int64(num("LOGSTORE_MAX_BODY_BYTES", 4<<20)),
		MaxBatchEvents:   int(num("LOGSTORE_MAX_BATCH_EVENTS", 5000)),
		RateRead:         num("LOGSTORE_RATE_READ", 20),
		RateWrite:        num("LOGSTORE_RATE_WRITE", 10),
		QueryTimeout:     time.Duration(num("LOGSTORE_QUERY_TIMEOUT_SECONDS", 15) * float64(time.Second)),
		LogLevel:         strings.ToLower(str("LOGSTORE_LOG_LEVEL", "info")),
		UIEnabled:        !strings.EqualFold(str("LOGSTORE_UI", "true"), "false"),

		MaintenanceEnabled:  !strings.EqualFold(str("LOGSTORE_MAINTENANCE", "true"), "false"),
		MaintenanceInterval: time.Duration(num("LOGSTORE_MAINTENANCE_HOURS", 24) * float64(time.Hour)),
	}
	c.DatabaseRead = str("LOGSTORE_DATABASE_URL_READ", c.DatabaseURL)
	c.DatabaseWrite = str("LOGSTORE_DATABASE_URL_WRITE", c.DatabaseURL)

	m, err := ipmode.Parse(str("LOGSTORE_IP_MODE", string(ipmode.Clear)))
	if err != nil {
		errs = append(errs, err)
	}
	c.IPMode = m
	c.RetentionDays = int(num("LOGSTORE_RETENTION_DAYS", MaxRetentionDays))
	if c.RetentionDays < MinRetentionDays || c.RetentionDays > MaxRetentionDays {
		errs = append(errs, fmt.Errorf("LOGSTORE_RETENTION_DAYS doit être entre %d et %d", MinRetentionDays, MaxRetentionDays))
	}

	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("LOGSTORE_DATABASE_URL est obligatoire"))
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("LOGSTORE_TLS_CERT et LOGSTORE_TLS_KEY vont ensemble"))
	}
	if c.TLSCert == "" && !c.InsecureHTTP {
		errs = append(errs, errors.New("TLS requis : fournir LOGSTORE_TLS_CERT/KEY, ou LOGSTORE_INSECURE_HTTP=true derrière un proxy TLS de confiance"))
	}
	if c.PseudoKey != "" && len(c.PseudoKey) < ipmode.MinKeyLen {
		errs = append(errs, fmt.Errorf("LOGSTORE_PSEUDO_KEY trop courte (min %d caractères)", ipmode.MinKeyLen))
	}
	if c.IPMode == ipmode.Pseudonymized && c.PseudoKey == "" {
		errs = append(errs, errors.New("LOGSTORE_IP_MODE=pseudonymized exige LOGSTORE_PSEUDO_KEY"))
	}
	if c.AdminToken != "" && len(c.AdminToken) < 32 {
		errs = append(errs, errors.New("LOGSTORE_ADMIN_TOKEN trop court (min 32 caractères)"))
	}
	return c, errors.Join(errs...)
}
