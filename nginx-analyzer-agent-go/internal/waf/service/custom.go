package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginx-analyzer-go/internal/waf/crs"
)

const (
	maxCustomBytes = 256 << 10
	customMinID    = 9100000
)

// Directives autorisees dans custom/user.conf (liste blanche) ; tout le reste est refuse
// (Include, SecRuleEngine, SecAuditLog, SecDataDir... : pas d'effet de bord sur le disque ni
// sur le comportement global du moteur).
var allowedDirectives = map[string]bool{
	"secrule": true, "secaction": true, "secmarker": true,
	"secruleremovebyid": true, "secruleremovebytag": true, "secruleremovebymsg": true,
	"secruleupdateactionbyid": true, "secruleupdatetargetbyid": true,
	"secruleupdatetargetbytag": true, "secruleupdatetargetbymsg": true,
}

// ValidateCustomRules controle le texte SecLang utilisateur avant compilation.
func ValidateCustomRules(text string) error {
	if len(text) > maxCustomBytes {
		return fmt.Errorf("texte trop long (%d Ko max)", maxCustomBytes>>10)
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return errors.New("texte invalide (UTF-8 attendu, pas d'octet nul)")
	}
	var cur strings.Builder
	n := 0
	check := func() error {
		d := strings.TrimSpace(cur.String())
		cur.Reset()
		if d == "" {
			return nil
		}
		n++
		name := strings.ToLower(strings.Fields(d)[0])
		switch name {
		case "include":
			return errors.New("directive interdite : Include")
		case "secruleengine":
			return errors.New("directive interdite : SecRuleEngine")
		}
		if !allowedDirectives[name] {
			return fmt.Errorf("directive interdite : %s", truncate(strings.Fields(d)[0], 40))
		}
		args := crs.SplitArgs(d)
		var actions string
		switch name {
		case "secaction":
			if len(args) >= 2 {
				actions = args[1]
			}
		case "secrule":
			if len(args) >= 4 {
				actions = args[3]
			}
		}
		lower := strings.ToLower(actions)
		if strings.Contains(lower, "ctl:ruleengine") || strings.Contains(lower, "ctl:requestbodyaccess") {
			return errors.New("action interdite : ctl:ruleEngine / ctl:requestBodyAccess")
		}
		if name == "secaction" {
			id := 0
			for _, a := range crs.SplitActions(actions) {
				k, v, _ := strings.Cut(a, ":")
				if strings.EqualFold(strings.TrimSpace(k), "id") {
					id, _ = strconv.Atoi(strings.Trim(strings.TrimSpace(v), "'"))
				}
			}
			if id < customMinID {
				return fmt.Errorf("SecAction : id >= %d obligatoire", customMinID)
			}
		}
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if cur.Len() == 0 && (t == "" || strings.HasPrefix(t, "#")) {
			continue
		}
		if strings.HasSuffix(t, "\\") {
			cur.WriteString(strings.TrimSuffix(t, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		if err := check(); err != nil {
			return err
		}
	}
	if cur.Len() > 0 {
		return errors.New("continuation de ligne (\\) non terminee")
	}
	return nil
}

func (s *Service) customPath() string { return filepath.Join(s.cfg.RulesDir, "custom", "user.conf") }

// CustomRules renvoie le contenu de custom/user.conf (vide si absent).
func (s *Service) CustomRules() (string, error) {
	b, err := os.ReadFile(s.customPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return string(b), err
}

// PutCustomRules valide, compile dans un moteur temporaire, ecrit atomiquement puis recharge.
// En cas d'echec du rechargement l'ancien fichier est restaure.
func (s *Service) PutCustomRules(text string) error {
	s.customMu.Lock()
	defer s.customMu.Unlock()
	if err := ValidateCustomRules(text); err != nil {
		return &BadRequest{Msg: err.Error()}
	}
	if strings.TrimSpace(text) != "" {
		if err := s.eng.TestCompile(text); err != nil {
			return &BadRequest{Msg: "compilation refusee : " + err.Error()}
		}
	}
	path := s.customPath()
	old, oldErr := os.ReadFile(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(text)); err != nil {
		return err
	}
	if s.crs.Empty() {
		return nil // pas de CRS : le fichier sera charge avec le moteur
	}
	if err := s.ReloadEngine(); err != nil {
		if oldErr == nil {
			_ = writeFileAtomic(path, old)
		} else {
			_ = os.Remove(path)
		}
		_ = s.ReloadEngine()
		return &BadRequest{Msg: "rechargement refuse : " + err.Error()}
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".user-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
