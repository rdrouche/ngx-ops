// Package engine enveloppe Coraza (DetectionOnly) + OWASP CRS : chargement tolerant fichier
// par fichier, rechargement a chaud par echange atomique d'instance, evaluation d'une
// requete synthetique. Aucune regle n'est retiree cote Coraza : le post-filtrage est fait
// par l'appelant a partir des hits bruts (avec leur niveau de paranoia).
package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"

	"nginx-analyzer-go/internal/waf/crs"
)

// Request est la requete synthetique soumise au moteur.
type Request struct {
	Method  string
	URI     string
	Proto   string
	IP      string
	Host    string
	Headers [][2]string // en-tetes (hors Host, deja ajoute)
}

// Hit est une regle declenchee (brute, avant post-filtrage).
type Hit struct {
	ID       int
	Msg      string
	Severity string // CRITICAL|ERROR|WARNING|NOTICE
	Score    int
	Paranoia int
	Tags     []string // tags publics (attack-*)
	Data     string   // <= 200 caracteres
}

// FileIgnored : fichier .conf que le moteur n'a pas pu charger.
type FileIgnored struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// Info decrit l'instance chargee.
type Info struct {
	Paranoia     int
	RulesLoaded  int
	FilesIgnored []FileIgnored
	LoadedAt     time.Time
	CRSVersion   string
	Rules        []crs.RuleMeta // regles avec msg : fichiers charges, ignores, 922 et personnalises
	IgnoredFiles map[string]bool
	AllIDs       map[int]bool // tous les ids connus (y compris regles sans msg)
	Unreliable   map[string][]int
	CustomIDs    map[int]bool
}

type instance struct {
	waf       coraza.WAF
	info      *Info
	byID      map[int]crs.RuleMeta
	customIDs map[int]bool
	crsFiles  []string // chemins relatifs a RootFS, charges
	custFiles []string
	par       int
}

// ErrNotReady : aucune instance chargee.
var ErrNotReady = errors.New("moteur non charge")

// Engine : instance courante echangeable atomiquement.
type Engine struct {
	rulesDir string
	mu       sync.Mutex // serialise Reload
	cur      atomic.Pointer[instance]
	lastErr  atomic.Pointer[string]
	loading  atomic.Bool
}

// New cree un moteur (non charge) pour rulesDir (contient crs/ et custom/).
func New(rulesDir string) *Engine { return &Engine{rulesDir: rulesDir} }

// Ready : une instance est chargee.
func (e *Engine) Ready() bool { return e.cur.Load() != nil }

// Loading : un (re)chargement est en cours.
func (e *Engine) Loading() bool { return e.loading.Load() }

// Err : derniere erreur de chargement (nil si OK).
func (e *Engine) Err() error {
	if p := e.lastErr.Load(); p != nil && *p != "" {
		return errors.New(*p)
	}
	return nil
}

// Info renvoie les informations de l'instance courante (nil si non chargee).
func (e *Engine) Info() *Info {
	if in := e.cur.Load(); in != nil {
		return in.info
	}
	return nil
}

// Paranoia renvoie le niveau de paranoia charge (0 si non charge).
func (e *Engine) Paranoia() int {
	if in := e.cur.Load(); in != nil {
		return in.par
	}
	return 0
}

// Version renvoie la version du module Coraza (build info) ou 3.3.3.
func Version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/corazawaf/coraza/v3" {
				return strings.TrimPrefix(d.Version, "v")
			}
		}
	}
	return "3.3.3"
}

var reSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,150}$`)

// excluded : fichiers REQUEST-* jamais charges (922 multipart : sans corps ni log fiable ;
// 949 evaluation de blocage : inutile en DetectionOnly ; 900 : exemples).
func excluded(name string) bool {
	return strings.HasPrefix(name, "REQUEST-922") || strings.HasPrefix(name, "REQUEST-949") || strings.HasPrefix(name, "REQUEST-900")
}

func crsVersionNumber(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 4)
	if len(parts) >= 3 {
		return parts[0] + parts[1] + parts[2]
	}
	return "480"
}

func preamble(par int, version string) string {
	var b strings.Builder
	b.WriteString("SecRuleEngine DetectionOnly\n")
	b.WriteString("SecRequestBodyAccess Off\n")
	b.WriteString("SecResponseBodyAccess Off\n")
	b.WriteString("SecDefaultAction \"phase:1,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:2,log,auditlog,pass\"\n")
	fmt.Fprintf(&b, "SecAction \"id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=%s,"+
		"setvar:tx.detection_paranoia_level=%d,setvar:tx.blocking_paranoia_level=%d,"+
		"setvar:tx.inbound_anomaly_score_threshold=1000000,setvar:tx.outbound_anomaly_score_threshold=1000000,"+
		"setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\"\n",
		crsVersionNumber(version), par, par)
	return b.String()
}

func newWAF(directives string, root fs.FS) (w coraza.WAF, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panique pendant le chargement : %v", r)
		}
	}()
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(directives).
		WithRootFS(root).
		WithErrorCallback(func(types.MatchedRule) {}).
		WithDebugLogger(debuglog.Noop()))
}

func listConf(dir fs.FS, sub string, skip func(string) bool) []string {
	ents, err := fs.ReadDir(dir, sub)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".conf") || !reSafeName.MatchString(n) {
			continue
		}
		if skip != nil && skip(n) {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Reload (re)construit le moteur avec le paranoia donne et l'echange atomiquement.
// Chargement tolerant : un fichier qui ne compile pas est ignore (et signale), jamais fatal.
// L'ancienne instance reste active pendant la construction et en cas d'echec total.
func (e *Engine) Reload(ctx context.Context, paranoia int, crsVersion string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loading.Store(true)
	defer e.loading.Store(false)
	in, err := e.build(ctx, paranoia, crsVersion)
	if err != nil {
		msg := err.Error()
		e.lastErr.Store(&msg)
		return err
	}
	empty := ""
	e.lastErr.Store(&empty)
	e.cur.Store(in)
	return nil
}

func (e *Engine) build(ctx context.Context, par int, crsVersion string) (*instance, error) {
	if par < 1 || par > 4 {
		par = 1
	}
	root := os.DirFS(e.rulesDir)
	crsFiles := listConf(root, "crs/rules", func(n string) bool {
		return !strings.HasPrefix(n, "REQUEST-9") || excluded(n)
	})
	if len(crsFiles) == 0 {
		return nil, errors.New("CRS non installe (crs/rules/REQUEST-9*.conf introuvable)")
	}
	custFiles := listConf(root, "custom", nil)

	in := &instance{par: par, byID: map[int]crs.RuleMeta{}, customIDs: map[int]bool{}}
	info := &Info{Paranoia: par, CRSVersion: crsVersion, IgnoredFiles: map[string]bool{}, AllIDs: map[int]bool{}, CustomIDs: in.customIDs}
	in.info = info

	pre := preamble(par, crsVersion)
	type cand struct {
		rel  string // chemin relatif a RootFS
		name string
		cust bool
	}
	var cands []cand
	for _, n := range crsFiles {
		cands = append(cands, cand{"crs/rules/" + n, n, false})
	}
	for _, n := range custFiles {
		cands = append(cands, cand{"custom/" + n, "custom/" + n, true})
	}
	incl := func(files []string) string {
		var b strings.Builder
		for _, f := range files {
			b.WriteString("Include " + f + "\n")
		}
		return b.String()
	}

	// Voie rapide : tout charger d'un coup.
	var all []string
	for _, c := range cands {
		all = append(all, c.rel)
	}
	waf, err := newWAF(pre+incl(all), root)
	var accepted []string
	if err == nil {
		accepted = all
	} else {
		// Voie tolerante : ajout fichier par fichier, on garde le dernier chargement valide.
		waf = nil
		for _, c := range cands {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			try := append(append([]string(nil), accepted...), c.rel)
			w, lerr := newWAF(pre+incl(try), root)
			if lerr != nil {
				info.FilesIgnored = append(info.FilesIgnored, FileIgnored{File: c.name, Reason: trimErr(lerr)})
				info.IgnoredFiles[c.name] = true
				continue
			}
			accepted, waf = try, w
		}
		if waf == nil {
			return nil, fmt.Errorf("aucun fichier de regles n'a pu etre charge (%d ignores)", len(info.FilesIgnored))
		}
	}
	in.waf = waf
	for _, r := range accepted {
		if strings.HasPrefix(r, "custom/") {
			in.custFiles = append(in.custFiles, r)
		} else {
			in.crsFiles = append(in.crsFiles, r)
		}
	}

	// Metadonnees : fichiers charges, ignores, 922 (desactives systeme) et personnalises.
	acc := map[string]bool{}
	for _, a := range accepted {
		acc[a] = true
	}
	parse := func(rel, label string, cust bool) {
		f, err := root.Open(rel)
		if err != nil {
			return
		}
		defer f.Close()
		loaded := acc[rel]
		for _, m := range crs.ParseFile(label, f) {
			info.AllIDs[m.ID] = true
			if loaded {
				info.RulesLoaded++
			}
			if m.Msg == "" {
				continue
			}
			if cust {
				m.Category = "other"
				m.Tags = crs.PublicTags(m.Tags, true)
				in.customIDs[m.ID] = true
			} else {
				m.Tags = crs.PublicTags(m.Tags, false)
			}
			if m.Tags == nil {
				m.Tags = []string{}
			}
			if cust || strings.HasPrefix(label, "REQUEST-9") {
				info.Rules = append(info.Rules, m)
			}
			if loaded {
				in.byID[m.ID] = m
			}
		}
	}
	allCrs := listConf(root, "crs/rules", func(n string) bool { return !strings.HasPrefix(n, "REQUEST-9") })
	for _, n := range allCrs {
		if strings.HasPrefix(n, "REQUEST-949") || strings.HasPrefix(n, "REQUEST-900") {
			continue
		}
		parse("crs/rules/"+n, n, false)
	}
	for _, n := range custFiles {
		parse("custom/"+n, "custom/"+n, true)
	}
	sort.Slice(info.Rules, func(i, j int) bool { return info.Rules[i].ID < info.Rules[j].ID })
	info.LoadedAt = time.Now()
	info.Unreliable = unreliableLists(info.AllIDs)
	return in, nil
}

// TestCompile verifie qu'un texte SecLang utilisateur compile avec le CRS installe (moteur
// temporaire, jetable). custom/user.conf n'est pas inclus (il est remplace par text).
func (e *Engine) TestCompile(text string) error {
	in := e.cur.Load()
	par, ver := 1, ""
	var files []string
	if in != nil {
		par, ver = in.par, in.info.CRSVersion
		files = append(files, in.crsFiles...)
		for _, c := range in.custFiles {
			if c != "custom/user.conf" {
				files = append(files, c)
			}
		}
	}
	var b strings.Builder
	b.WriteString(preamble(par, ver))
	for _, f := range files {
		b.WriteString("Include " + f + "\n")
	}
	b.WriteString(text)
	b.WriteString("\n")
	_, err := newWAF(b.String(), os.DirFS(e.rulesDir))
	if err != nil {
		return errors.New(trimErr(err))
	}
	return nil
}

const maxDataLen = 200

func truncRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func isAttackID(id int, custom map[int]bool) bool {
	return (id >= 911000 && id <= 944999) || custom[id]
}

// Eval soumet la requete synthetique et renvoie les hits bruts (dedoublonnes par id).
func (e *Engine) Eval(req Request) (hits []Hit, err error) {
	in := e.cur.Load()
	if in == nil {
		return nil, ErrNotReady
	}
	defer func() {
		if r := recover(); r != nil {
			hits, err = nil, fmt.Errorf("panique du moteur : %v", r)
		}
	}()
	tx := in.waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(req.IP, 0, "", 0)
	tx.ProcessURI(req.URI, req.Method, req.Proto)
	if req.Host != "" {
		tx.SetServerName(req.Host)
		tx.AddRequestHeader("Host", req.Host)
	}
	for _, h := range req.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		return nil, err
	}
	var seen map[int]bool
	for _, m := range tx.MatchedRules() {
		if m.Message() == "" {
			continue
		}
		rule := m.Rule()
		id := rule.ID()
		if !isAttackID(id, in.customIDs) {
			continue
		}
		if seen == nil {
			seen = map[int]bool{}
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		h := Hit{ID: id, Msg: truncRunes(m.Message(), 300)}
		if meta, ok := in.byID[id]; ok {
			h.Severity, h.Paranoia, h.Tags = meta.Severity, meta.Paranoia, meta.Tags
		} else {
			h.Severity = crs.NormSeverity(rule.Severity().String())
			tags := rule.Tags()
			h.Paranoia = crs.ParanoiaFromTags(tags)
			h.Tags = crs.PublicTags(tags, in.customIDs[id])
		}
		h.Score = crs.SeverityScore(h.Severity)
		data := m.Data()
		if data == "" {
			if md := m.MatchedDatas(); len(md) > 0 {
				data = fmt.Sprintf("Matched Data: %s found within %s: %s", md[0].Key(), md[0].Variable().Name(), md[0].Value())
			}
		}
		h.Data = truncRunes(data, maxDataLen)
		hits = append(hits, h)
	}
	return hits, nil
}
