// Package settings porte le modele de reglages du WAF emule (contrat WAF-CONTRACT.md) :
// structure JSON, valeurs par defaut, fusion/validation stricte (PUT), persistance
// atomique dans DATA_DIR/settings.json et une vue "compilee" immuable utilisee par le
// chemin chaud (resolution des regles desactivees, mode/paranoia par vhost, IP exclues).
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nginx-analyzer-go/internal/cidr"
)

// Thresholds : seuils de la somme des scores par IP dans la fenetre.
type Thresholds struct {
	Challenge int `json:"challenge"`
	Block     int `json:"block"`
}

// ListHours : duree de maintien en liste.
type ListHours struct {
	Challenge int `json:"challenge"`
	Block     int `json:"block"`
}

// VhostSettings : surcharges par vhost (tous les champs sont optionnels).
type VhostSettings struct {
	Analyze       *bool  `json:"analyze,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Paranoia      int    `json:"paranoia,omitempty"`
	DisabledRules []int  `json:"disabledRules,omitempty"`
}

// Exception : desactivation ciblee d'une regle.
type Exception struct {
	ID         string `json:"id"`
	Rule       int    `json:"rule"`
	Vhost      string `json:"vhost"`
	PathPrefix string `json:"pathPrefix"`
	UaContains string `json:"uaContains"`
	IP         string `json:"ip"`
	Reason     string `json:"reason"`
	CreatedAt  string `json:"createdAt"`
}

// Settings est le document persiste et echange via GET/PUT /api/settings.
type Settings struct {
	Enable        bool                     `json:"enable"`
	Mode          string                   `json:"mode"`
	Paranoia      int                      `json:"paranoia"`
	Thresholds    Thresholds               `json:"thresholds"`
	WindowMinutes int                      `json:"windowMinutes"`
	ListHours     ListHours                `json:"listHours"`
	AlertMinScore int                      `json:"alertMinScore"`
	VhostMode     string                   `json:"vhostMode"`
	Vhosts        map[string]VhostSettings `json:"vhosts"`
	DisabledRules []int                    `json:"disabledRules"`
	Exceptions    []Exception              `json:"exceptions"`
	IgnoreStatus  []int                    `json:"ignoreStatus"`
	ExcludeIps    []string                 `json:"excludeIps"`
}

// Bornes de validation (aussi utilisees par les tests).
const (
	MaxVhosts       = 1000
	MaxDisabled     = 2000
	MaxExceptions   = 1000
	MaxExcludeIps   = 1000
	MaxIgnoreStatus = 100
	MaxRuleID       = 99999999
)

// Default renvoie les reglages par defaut du contrat.
func Default() Settings {
	return Settings{
		Enable:        true,
		Mode:          "observe",
		Paranoia:      1,
		Thresholds:    Thresholds{Challenge: 10, Block: 25},
		WindowMinutes: 60,
		ListHours:     ListHours{Challenge: 24, Block: 72},
		AlertMinScore: 10,
		VhostMode:     "all",
		Vhosts:        map[string]VhostSettings{},
		DisabledRules: []int{},
		Exceptions:    []Exception{},
		IgnoreStatus:  []int{},
		ExcludeIps:    []string{},
	}
}

var (
	reVhostName = regexp.MustCompile(`^[a-z0-9._*:\-]{1,253}$`)
	reExID      = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,40}$`)
)

// NormalizeVhost met un nom de vhost en minuscules ; ok=false s'il est invalide.
func NormalizeVhost(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !reVhostName.MatchString(v) {
		return "", false
	}
	return v, true
}

func hasCtl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func strictUnmarshal(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("donnees superflues")
	}
	return nil
}

// Patch fusionne un corps JSON (partiel ou complet) sur s, valide strictement et renvoie
// les reglages normalises. Les cles de premier niveau fournies REMPLACENT la valeur
// courante (sauf thresholds/listHours : fusion champ a champ). Toute erreur => message.
func (s Settings) Patch(body []byte) (Settings, error) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&top); err != nil {
		return s, fmt.Errorf("JSON invalide : %v", err)
	}
	if dec.More() {
		return s, errors.New("JSON invalide : donnees superflues")
	}
	if top == nil {
		return s, errors.New("objet JSON attendu")
	}
	out := s.clone()
	for k, raw := range top {
		var err error
		switch k {
		case "enable":
			err = strictUnmarshal(raw, &out.Enable)
		case "mode":
			err = strictUnmarshal(raw, &out.Mode)
		case "paranoia":
			err = strictUnmarshal(raw, &out.Paranoia)
		case "thresholds":
			err = strictUnmarshal(raw, &out.Thresholds)
		case "windowMinutes":
			err = strictUnmarshal(raw, &out.WindowMinutes)
		case "listHours":
			err = strictUnmarshal(raw, &out.ListHours)
		case "alertMinScore":
			err = strictUnmarshal(raw, &out.AlertMinScore)
		case "vhostMode":
			err = strictUnmarshal(raw, &out.VhostMode)
		case "vhosts":
			var m map[string]VhostSettings
			if err = strictUnmarshal(raw, &m); err == nil {
				out.Vhosts = m
			}
		case "disabledRules":
			var l []int
			if err = strictUnmarshal(raw, &l); err == nil {
				out.DisabledRules = l
			}
		case "exceptions":
			var l []Exception
			if err = strictUnmarshal(raw, &l); err == nil {
				out.Exceptions = l
			}
		case "ignoreStatus":
			var l []int
			if err = strictUnmarshal(raw, &l); err == nil {
				out.IgnoreStatus = l
			}
		case "excludeIps":
			var l []string
			if err = strictUnmarshal(raw, &l); err == nil {
				out.ExcludeIps = l
			}
		default:
			return s, fmt.Errorf("champ inconnu : %q", truncate(k, 40))
		}
		if err != nil {
			return s, fmt.Errorf("champ %q invalide : %v", k, err)
		}
	}
	if err := out.Normalize(); err != nil {
		return s, err
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s Settings) clone() Settings {
	c := s
	c.Vhosts = make(map[string]VhostSettings, len(s.Vhosts))
	for k, v := range s.Vhosts {
		v.DisabledRules = append([]int(nil), v.DisabledRules...)
		if v.Analyze != nil {
			b := *v.Analyze
			v.Analyze = &b
		}
		c.Vhosts[k] = v
	}
	c.DisabledRules = append([]int(nil), s.DisabledRules...)
	c.Exceptions = append([]Exception(nil), s.Exceptions...)
	c.IgnoreStatus = append([]int(nil), s.IgnoreStatus...)
	c.ExcludeIps = append([]string(nil), s.ExcludeIps...)
	return c
}

func normRules(l []int, what string) ([]int, error) {
	if len(l) > MaxDisabled {
		return nil, fmt.Errorf("%s : trop de regles (max %d)", what, MaxDisabled)
	}
	seen := make(map[int]bool, len(l))
	out := make([]int, 0, len(l))
	for _, id := range l {
		if id < 1 || id > MaxRuleID {
			return nil, fmt.Errorf("%s : identifiant de regle invalide (%d)", what, id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Ints(out)
	return out, nil
}

// Normalize valide et normalise s en place (tri, dedoublonnage, minuscules...).
func (s *Settings) Normalize() error {
	if s.Mode != "observe" && s.Mode != "remediate" {
		return errors.New("mode doit valoir observe ou remediate")
	}
	if s.Paranoia < 1 || s.Paranoia > 4 {
		return errors.New("paranoia doit etre compris entre 1 et 4")
	}
	if s.Thresholds.Challenge < 1 || s.Thresholds.Challenge > 100000 {
		return errors.New("thresholds.challenge doit etre compris entre 1 et 100000")
	}
	if s.Thresholds.Block < s.Thresholds.Challenge || s.Thresholds.Block > 100000 {
		return errors.New("thresholds.block doit etre >= thresholds.challenge et <= 100000")
	}
	if s.WindowMinutes < 1 || s.WindowMinutes > 10080 {
		return errors.New("windowMinutes doit etre compris entre 1 et 10080")
	}
	if s.ListHours.Challenge < 1 || s.ListHours.Challenge > 8760 || s.ListHours.Block < 1 || s.ListHours.Block > 8760 {
		return errors.New("listHours.* doit etre compris entre 1 et 8760")
	}
	if s.AlertMinScore < 1 || s.AlertMinScore > 100000 {
		return errors.New("alertMinScore doit etre compris entre 1 et 100000")
	}
	if s.VhostMode != "all" && s.VhostMode != "selected" {
		return errors.New("vhostMode doit valoir all ou selected")
	}
	if len(s.Vhosts) > MaxVhosts {
		return fmt.Errorf("trop de vhosts (max %d)", MaxVhosts)
	}
	vh := make(map[string]VhostSettings, len(s.Vhosts))
	for name, v := range s.Vhosts {
		n, ok := NormalizeVhost(name)
		if !ok {
			return fmt.Errorf("nom de vhost invalide : %q", truncate(name, 60))
		}
		if _, dup := vh[n]; dup {
			return fmt.Errorf("vhost en double : %q", n)
		}
		if v.Mode != "" && v.Mode != "observe" && v.Mode != "remediate" {
			return fmt.Errorf("vhosts[%s].mode doit valoir observe ou remediate", n)
		}
		if v.Paranoia != 0 && (v.Paranoia < 1 || v.Paranoia > 4) {
			return fmt.Errorf("vhosts[%s].paranoia doit etre compris entre 1 et 4", n)
		}
		dr, err := normRules(v.DisabledRules, "vhosts["+n+"].disabledRules")
		if err != nil {
			return err
		}
		v.DisabledRules = dr
		vh[n] = v
	}
	s.Vhosts = vh
	dr, err := normRules(s.DisabledRules, "disabledRules")
	if err != nil {
		return err
	}
	s.DisabledRules = dr

	if len(s.Exceptions) > MaxExceptions {
		return fmt.Errorf("trop d'exceptions (max %d)", MaxExceptions)
	}
	ids := map[string]bool{}
	now := time.Now().UTC().Format(time.RFC3339)
	exs := make([]Exception, 0, len(s.Exceptions))
	for i, e := range s.Exceptions {
		if e.Rule < 1 || e.Rule > MaxRuleID {
			return fmt.Errorf("exceptions[%d].rule invalide", i)
		}
		if e.ID == "" {
			e.ID = fmt.Sprintf("ex%d", time.Now().UnixNano()%1e12+int64(i))
		}
		if !reExID.MatchString(e.ID) {
			return fmt.Errorf("exceptions[%d].id invalide (lettres, chiffres, _ et - ; 40 car. max)", i)
		}
		if ids[e.ID] {
			return fmt.Errorf("exceptions : id en double %q", e.ID)
		}
		ids[e.ID] = true
		if e.Vhost != "" {
			n, ok := NormalizeVhost(e.Vhost)
			if !ok {
				return fmt.Errorf("exceptions[%d].vhost invalide", i)
			}
			e.Vhost = n
		}
		if len(e.PathPrefix) > 512 || hasCtl(e.PathPrefix) {
			return fmt.Errorf("exceptions[%d].pathPrefix invalide (512 car. max, sans caractere de controle)", i)
		}
		if e.PathPrefix != "" && !strings.HasPrefix(e.PathPrefix, "/") {
			return fmt.Errorf("exceptions[%d].pathPrefix doit commencer par / (sous-chaine litterale, pas de regex)", i)
		}
		if len(e.UaContains) > 256 || hasCtl(e.UaContains) {
			return fmt.Errorf("exceptions[%d].uaContains invalide (256 car. max, sans caractere de controle)", i)
		}
		e.IP = strings.TrimSpace(e.IP)
		if e.IP != "" && !cidr.IsValidPattern(e.IP) {
			return fmt.Errorf("exceptions[%d].ip : IP/CIDR invalide", i)
		}
		if len(e.Reason) > 500 || hasCtl(e.Reason) {
			return fmt.Errorf("exceptions[%d].reason invalide (500 car. max)", i)
		}
		if e.CreatedAt == "" {
			e.CreatedAt = now
		} else if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
			return fmt.Errorf("exceptions[%d].createdAt doit etre une date ISO 8601", i)
		}
		exs = append(exs, e)
	}
	s.Exceptions = exs

	if len(s.IgnoreStatus) > MaxIgnoreStatus {
		return fmt.Errorf("ignoreStatus : trop de valeurs (max %d)", MaxIgnoreStatus)
	}
	seenSt := map[int]bool{}
	st := make([]int, 0, len(s.IgnoreStatus))
	for _, c := range s.IgnoreStatus {
		if c < 100 || c > 599 {
			return fmt.Errorf("ignoreStatus : code HTTP invalide (%d)", c)
		}
		if !seenSt[c] {
			seenSt[c] = true
			st = append(st, c)
		}
	}
	sort.Ints(st)
	s.IgnoreStatus = st

	if len(s.ExcludeIps) > MaxExcludeIps {
		return fmt.Errorf("excludeIps : trop de valeurs (max %d)", MaxExcludeIps)
	}
	seenIP := map[string]bool{}
	ips := make([]string, 0, len(s.ExcludeIps))
	for _, ip := range s.ExcludeIps {
		ip = strings.TrimSpace(ip)
		if ip == "" || !cidr.IsValidPattern(ip) {
			return fmt.Errorf("excludeIps : IP/CIDR invalide (%q)", truncate(ip, 60))
		}
		if !seenIP[ip] {
			seenIP[ip] = true
			ips = append(ips, ip)
		}
	}
	s.ExcludeIps = ips
	return nil
}

// Load lit settings.json (valeurs par defaut si absent). Un fichier corrompu renvoie
// une erreur ET les valeurs par defaut, pour que l'appelant puisse continuer.
func Load(path string) (Settings, error) {
	d := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	s, err := d.Patch(b)
	if err != nil {
		return d, fmt.Errorf("settings.json invalide, valeurs par defaut utilisees : %v", err)
	}
	return s, nil
}

// Save ecrit s de facon atomique (fichier temporaire + rename).
func Save(path string, s Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// Holder garde la vue compilee courante (lecture sans verrou) et persiste les changements.
type Holder struct {
	path string
	mu   sync.Mutex // serialise les Update
	cur  atomic.Pointer[Compiled]
}

// NewHolder charge settings.json (path vide = pas de persistance).
func NewHolder(path string) (*Holder, error) {
	h := &Holder{path: path}
	s := Default()
	var lerr error
	if path != "" {
		s, lerr = Load(path)
	}
	h.cur.Store(Compile(s))
	return h, lerr
}

// Get renvoie la vue compilee courante (immuable).
func (h *Holder) Get() *Compiled { return h.cur.Load() }

// Update applique un PUT (fusion + validation), persiste puis publie. Renvoie
// (ancienne, nouvelle) vues.
func (h *Holder) Update(body []byte) (old, cur *Compiled, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old = h.cur.Load()
	ns, err := old.S.Patch(body)
	if err != nil {
		return old, old, &ValidationError{err}
	}
	if h.path != "" {
		if err := Save(h.path, ns); err != nil {
			return old, old, fmt.Errorf("ecriture de settings.json : %w", err)
		}
	}
	cur = Compile(ns)
	h.cur.Store(cur)
	return old, cur, nil
}

// ValidationError distingue un rejet de validation (HTTP 400) d'une erreur interne.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }
