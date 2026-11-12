package shipper

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/logsink"
)

// Version du shipper (indépendante de celle de l'analyseur).
const Version = "0.1.0"

// Config du shipper. Toutes les valeurs viennent de variables d'environnement
// (FromEnv) ; aucun secret n'est jamais journalisé ni renvoyé par /status.
type Config struct {
	Dir          string         // LOGSHIP_DIR (défaut LOGS_DIR puis /nginx/logs)
	Pattern      *regexp.Regexp // LOGSHIP_PATTERN
	PollMs       int            // LOGSHIP_POLL_MS
	StateFile    string         // LOGSHIP_STATE_FILE
	Listen       string         // LOGSHIP_LISTEN
	LocalToken   string         // LOGSHIP_LOCAL_TOKEN (vide = entrée locale désactivée)
	WithCountry  bool           // LOGSHIP_COUNTRY
	WithBotClass bool           // LOGSHIP_BOTCLASS
	MaxQueue     int            // LOGSHIP_MAX_QUEUE_EVENTS

	// Journal dédié des hits de blocklist (blocklist-hits.log, écrit par nginx).
	WithBlocklist    bool           // LOGSHIP_BLOCKLIST (défaut true ; sans fichier, sans effet)
	BlocklistPattern *regexp.Regexp // LOGSHIP_BLOCKLIST_PATTERN (défaut BLOCKLIST_LOG_PATTERN)
	BlocklistState   string         // LOGSHIP_BLOCKLIST_STATE_FILE (défaut : <state>-blocklist.json)
	AnalyzerURL      string         // LOGSHIP_ANALYZER_URL : API de l'analyseur (attribution du nom de liste aux hits blocklist, #110) ; vide = désactivé
	AnalyzerToken    string         // LOGSHIP_ANALYZER_TOKEN (X-Analyzer-Token) ; jamais journalisé
	Sink             logsink.Config // LOGSINK_*
}

func str(name, def string) string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = v[1 : len(v)-1]
	}
	return v
}

func intEnv(name string, def int) int {
	if s := str(name, ""); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return def
}

func boolEnv(name string, def bool) bool {
	switch strings.ToLower(str(name, "")) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// FromEnv lit et valide la configuration.
func FromEnv() (Config, error) {
	c := Config{
		Dir:          str("LOGSHIP_DIR", str("LOGS_DIR", "/nginx/logs")),
		PollMs:       intEnv("LOGSHIP_POLL_MS", intEnv("POLL_MS", 1000)),
		StateFile:    str("LOGSHIP_STATE_FILE", "/data/offsets.json"),
		Listen:       str("LOGSHIP_LISTEN", "127.0.0.1:9181"),
		LocalToken:   str("LOGSHIP_LOCAL_TOKEN", ""),
		WithCountry:  boolEnv("LOGSHIP_COUNTRY", false),
		WithBotClass: boolEnv("LOGSHIP_BOTCLASS", true),
		MaxQueue:     intEnv("LOGSHIP_MAX_QUEUE_EVENTS", 200000),
	}
	raw := str("LOGSHIP_PATTERN", str("LOG_PATTERN", `(^|[._])access\.log$`))
	re, err := regexp.Compile(raw)
	if err != nil {
		return c, fmt.Errorf("LOGSHIP_PATTERN invalide : %w", err)
	}
	c.Pattern = re
	c.WithBlocklist = boolEnv("LOGSHIP_BLOCKLIST", true)
	braw := str("LOGSHIP_BLOCKLIST_PATTERN", str("BLOCKLIST_LOG_PATTERN", `^blocklist-hits\.log$`))
	bre, err := regexp.Compile(braw)
	if err != nil {
		return c, fmt.Errorf("LOGSHIP_BLOCKLIST_PATTERN invalide : %w", err)
	}
	c.BlocklistPattern = bre
	c.AnalyzerURL = str("LOGSHIP_ANALYZER_URL", "")
	c.AnalyzerToken = str("LOGSHIP_ANALYZER_TOKEN", "")
	c.BlocklistState = str("LOGSHIP_BLOCKLIST_STATE_FILE", strings.TrimSuffix(c.StateFile, ".json")+"-blocklist.json")
	c.Sink = logsink.Config{
		URL:           str("LOGSINK_URL", ""),
		Token:         str("LOGSINK_TOKEN", ""),
		InstanceName:  str("LOGSINK_INSTANCE", ""),
		SpoolDir:      str("LOGSINK_SPOOL_DIR", "/data/spool"),
		SpoolMaxBytes: int64(intEnv("LOGSINK_SPOOL_MAX_MB", 256)) << 20,
		SpoolMaxAge:   time.Duration(intEnv("LOGSINK_SPOOL_MAX_HOURS", 24)) * time.Hour,
		BatchSize:     intEnv("LOGSINK_BATCH_SIZE", 500),
		AllowInsecure: boolEnv("LOGSINK_ALLOW_INSECURE", false),
		Timeout:       time.Duration(intEnv("LOGSINK_TIMEOUT_S", 15)) * time.Second,
	}
	return c, c.Validate()
}

// Validate vérifie la cohérence (sans réseau).
func (c Config) Validate() error {
	if strings.TrimSpace(c.Sink.URL) == "" {
		return errors.New("LOGSINK_URL requis")
	}
	if c.Sink.Token == "" {
		return errors.New("LOGSINK_TOKEN requis (jeton « write » du log store)")
	}
	if c.Dir == "" || c.StateFile == "" {
		return errors.New("LOGSHIP_DIR et LOGSHIP_STATE_FILE requis")
	}
	if c.LocalToken != "" && len(c.LocalToken) < 24 {
		return errors.New("LOGSHIP_LOCAL_TOKEN : 24 caractères minimum")
	}
	if c.LocalToken == "" && c.Listen != "" {
		// pas une erreur : seule /healthz est servie
		return nil
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil && c.Listen != "" {
		return fmt.Errorf("LOGSHIP_LISTEN invalide : %w", err)
	}
	return nil
}
