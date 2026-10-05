// Package crs : metadonnees des regles OWASP CRS / personnalisees (parseur SecLang leger),
// categories, et installation/telechargement du CRS.
package crs

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// RuleMeta decrit une regle (de tete de chaine) lue dans un fichier .conf.
type RuleMeta struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Severity string   `json:"severity"`
	Score    int      `json:"score"`
	Paranoia int      `json:"paranoia"`
	Tags     []string `json:"tags"`
	Category string   `json:"category"`
	File     string   `json:"file"`
}

// SeverityScore : CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2 (contrat). EMERGENCY/ALERT
// comptent comme CRITICAL, INFO/DEBUG comme NOTICE ; inconnue => WARNING.
func SeverityScore(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "EMERGENCY", "ALERT":
		return 5
	case "ERROR":
		return 4
	case "WARNING":
		return 3
	case "NOTICE", "INFO", "DEBUG":
		return 2
	}
	return 3
}

// NormSeverity ramene une severite SecLang a l'un des 4 libelles du contrat.
func NormSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "EMERGENCY", "ALERT":
		return "CRITICAL"
	case "ERROR":
		return "ERROR"
	case "NOTICE", "INFO", "DEBUG":
		return "NOTICE"
	}
	return "WARNING"
}

var reParanoiaTag = regexp.MustCompile(`^paranoia-level/(\d)$`)

// ParanoiaFromTags renvoie le niveau de paranoia d'une regle (tag paranoia-level/N, defaut 1).
func ParanoiaFromTags(tags []string) int {
	for _, t := range tags {
		if m := reParanoiaTag.FindStringSubmatch(t); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n >= 1 && n <= 4 {
				return n
			}
		}
	}
	return 1
}

// PublicTags garde les tags utiles a l'affichage : attack-* (CRS). Pour les regles
// utilisateur (all=true) tous les tags sont conserves.
func PublicTags(tags []string, all bool) []string {
	out := make([]string, 0, 2)
	for _, t := range tags {
		if all || strings.HasPrefix(t, "attack-") {
			out = append(out, t)
		}
	}
	return out
}

// ParseFile lit un fichier SecLang et renvoie TOUTES les regles ayant un id (y compris
// celles sans msg : regles d'initialisation / de saut). Les maillons de chaine (sans id)
// sont ignores : seule la regle de tete compte. file = nom de base (pour la categorie).
func ParseFile(file string, r io.Reader) []RuleMeta {
	var out []RuleMeta
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		if m, ok := parseDirective(cur.String()); ok {
			m.File = file
			m.Category = CategoryOfFile(file)
			if m.Category == "other" {
				m.Category = CategoryOfID(m.ID)
			}
			out = append(out, m)
		}
		cur.Reset()
	}
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if cur.Len() == 0 && (trim == "" || strings.HasPrefix(trim, "#")) {
			continue
		}
		if strings.HasSuffix(trim, "\\") {
			cur.WriteString(strings.TrimSuffix(trim, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(trim)
		flush()
	}
	flush()
	return out
}

// SplitArgs decoupe une directive SecLang en arguments (guillemets doubles, \" echappe).
func SplitArgs(s string) []string {
	var args []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var b strings.Builder
		if s[i] == '"' {
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				b.WriteByte(s[i])
				i++
			}
		}
		args = append(args, b.String())
	}
	return args
}

// SplitActions decoupe une chaine d'actions SecLang sur les virgules hors apostrophes.
func SplitActions(s string) []string {
	var out []string
	var b strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && inq:
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			i++
		case c == '\'':
			inq = !inq
			b.WriteByte(c)
		case c == ',' && !inq:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if t := strings.TrimSpace(b.String()); t != "" {
		out = append(out, t)
	}
	return out
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `\'`, `'`)
	}
	return v
}

func parseDirective(d string) (RuleMeta, bool) {
	args := SplitArgs(d)
	if len(args) < 2 {
		return RuleMeta{}, false
	}
	var actions string
	switch strings.ToLower(args[0]) {
	case "secrule":
		if len(args) < 4 {
			return RuleMeta{}, false
		}
		actions = args[3]
	case "secaction":
		actions = args[1]
	default:
		return RuleMeta{}, false
	}
	var m RuleMeta
	var rawSev string
	for _, a := range SplitActions(actions) {
		k, v, _ := strings.Cut(a, ":")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "id":
			id, err := strconv.Atoi(unquote(v))
			if err != nil {
				return RuleMeta{}, false
			}
			m.ID = id
		case "msg":
			m.Msg = unquote(v)
		case "severity":
			rawSev = unquote(v)
		case "tag":
			m.Tags = append(m.Tags, unquote(v))
		}
	}
	if m.ID == 0 {
		return RuleMeta{}, false
	}
	m.Paranoia = ParanoiaFromTags(m.Tags)
	if rawSev != "" {
		m.Severity = NormSeverity(rawSev)
	} else {
		m.Severity = "WARNING"
	}
	m.Score = SeverityScore(m.Severity)
	return m, true
}
