package settings

import (
	"net/netip"
	"strings"

	"nginx-analyzer-go/internal/cidr"
)

// Compiled est une vue immuable de Settings prete pour le chemin chaud.
type Compiled struct {
	S Settings

	global       map[int]struct{}
	vhost        map[string]map[int]struct{}
	exByRule     map[int][]compiledException
	excl         []*cidr.Block
	ignoreStatus map[int]struct{}
	effParanoia  int
}

type compiledException struct {
	Exception
	block *cidr.Block
	ua    string // uaContains en minuscules
}

// Compile construit la vue compilee (s doit deja etre normalise).
func Compile(s Settings) *Compiled {
	c := &Compiled{
		S:            s,
		global:       map[int]struct{}{},
		vhost:        map[string]map[int]struct{}{},
		exByRule:     map[int][]compiledException{},
		ignoreStatus: map[int]struct{}{},
	}
	for _, id := range s.DisabledRules {
		c.global[id] = struct{}{}
	}
	for n, v := range s.Vhosts {
		if len(v.DisabledRules) > 0 {
			m := make(map[int]struct{}, len(v.DisabledRules))
			for _, id := range v.DisabledRules {
				m[id] = struct{}{}
			}
			c.vhost[n] = m
		}
	}
	for _, e := range s.Exceptions {
		ce := compiledException{Exception: e, ua: strings.ToLower(e.UaContains)}
		if e.IP != "" {
			ce.block = cidr.ParseCidr(e.IP)
		}
		c.exByRule[e.Rule] = append(c.exByRule[e.Rule], ce)
	}
	for _, ip := range s.ExcludeIps {
		if b := cidr.ParseCidr(ip); b != nil {
			c.excl = append(c.excl, b)
		}
	}
	for _, st := range s.IgnoreStatus {
		c.ignoreStatus[st] = struct{}{}
	}
	c.effParanoia = c.computeParanoia()
	return c
}

// VhostAnalyzed : vhostMode all => tous sauf analyze=false ; selected => analyze=true seulement.
func (c *Compiled) VhostAnalyzed(vhost string) bool {
	v, ok := c.S.Vhosts[vhost]
	if c.S.VhostMode == "selected" {
		return ok && v.Analyze != nil && *v.Analyze
	}
	return !(ok && v.Analyze != nil && !*v.Analyze)
}

// Mode renvoie le mode effectif du vhost.
func (c *Compiled) Mode(vhost string) string {
	if v, ok := c.S.Vhosts[vhost]; ok && v.Mode != "" {
		return v.Mode
	}
	return c.S.Mode
}

// Paranoia renvoie le niveau de paranoia effectif du vhost.
func (c *Compiled) Paranoia(vhost string) int {
	if v, ok := c.S.Vhosts[vhost]; ok && v.Paranoia != 0 {
		return v.Paranoia
	}
	return c.S.Paranoia
}

// EffectiveParanoia est le paranoia maximal a charger dans le moteur.
func (c *Compiled) EffectiveParanoia() int { return c.effParanoia }

func (c *Compiled) computeParanoia() int {
	max := 0
	anyAnalyzed := false
	for n, v := range c.S.Vhosts {
		if !c.VhostAnalyzed(n) {
			continue
		}
		anyAnalyzed = true
		p := c.Paranoia(n)
		if v.Paranoia == 0 {
			p = c.S.Paranoia
		}
		if p > max {
			max = p
		}
	}
	if c.S.VhostMode == "all" || !anyAnalyzed {
		if c.S.Paranoia > max {
			max = c.S.Paranoia
		}
	}
	if max < 1 {
		max = 1
	}
	return max
}

// IgnoredStatus : statut de reponse a ignorer.
func (c *Compiled) IgnoredStatus(st int) bool {
	_, ok := c.ignoreStatus[st]
	return ok
}

// IsPrivateIP : IP privee/loopback/lien-local/non specifiee (toujours ignoree).
func IsPrivateIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

// IPExcluded : IP privee/loopback ou couverte par excludeIps.
func (c *Compiled) IPExcluded(ip string) bool {
	if IsPrivateIP(ip) {
		return true
	}
	if len(c.excl) == 0 {
		return false
	}
	addr := cidr.ToBytes(ip)
	if addr == nil {
		return false
	}
	for _, b := range c.excl {
		if cidr.ContainsParsed(addr, b) {
			return true
		}
	}
	return false
}

// Suppression applique, dans l'ordre du contrat, exception > vhost > global.
// Renvoie "exception", "vhost", "global" ou "" (non supprimee par les reglages).
func (c *Compiled) Suppression(rule int, vhost, ip, path, ua string) string {
	if exs, ok := c.exByRule[rule]; ok {
		var addr *cidr.Addr
		var uaLower string
		uaDone := false
		for i := range exs {
			e := &exs[i]
			if e.Vhost != "" && e.Vhost != vhost {
				continue
			}
			if e.PathPrefix != "" && !strings.HasPrefix(path, e.PathPrefix) {
				continue
			}
			if e.ua != "" {
				if !uaDone {
					uaLower, uaDone = strings.ToLower(ua), true
				}
				if !strings.Contains(uaLower, e.ua) {
					continue
				}
			}
			if e.block != nil {
				if addr == nil {
					addr = cidr.ToBytes(ip)
				}
				if addr == nil || !cidr.ContainsParsed(addr, e.block) {
					continue
				}
			}
			return "exception"
		}
	}
	if m, ok := c.vhost[vhost]; ok {
		if _, ok := m[rule]; ok {
			return "vhost"
		}
	}
	if _, ok := c.global[rule]; ok {
		return "global"
	}
	return ""
}

// DisabledForVhost : regle desactivee pour ce vhost (surcharge vhost ou globale).
func (c *Compiled) DisabledForVhost(rule int, vhost string) bool {
	if m, ok := c.vhost[vhost]; ok {
		if _, ok := m[rule]; ok {
			return true
		}
	}
	_, ok := c.global[rule]
	return ok
}

// ExceptionCount : nombre d'exceptions visant la regle.
func (c *Compiled) ExceptionCount(rule int) int { return len(c.exByRule[rule]) }

// GloballyDisabled / DisabledVhosts : etat d'une regle pour /api/rules.
func (c *Compiled) GloballyDisabled(rule int) bool {
	_, ok := c.global[rule]
	return ok
}

// DisabledVhosts liste (triee) les vhosts qui desactivent la regle.
func (c *Compiled) DisabledVhosts(rule int) []string {
	out := []string{}
	for n, m := range c.vhost {
		if _, ok := m[rule]; ok {
			out = append(out, n)
		}
	}
	sortStrings(out)
	return out
}

// ExceptionMatchesEvidence : utilise pour filtrer les alertes a la lecture. Une exception
// masque la regle si vhost et ip correspondent et si TOUS les chemins / User-Agent de
// l'alerte satisfont pathPrefix / uaContains (l'evidence ne garde pas le detail par regle).
func (c *Compiled) ExceptionMatchesEvidence(rule int, vhost, ip string, paths, uas []string) bool {
	exs := c.exByRule[rule]
	for i := range exs {
		e := &exs[i]
		if e.Vhost != "" && e.Vhost != vhost {
			continue
		}
		if e.block != nil {
			a := cidr.ToBytes(ip)
			if a == nil || !cidr.ContainsParsed(a, e.block) {
				continue
			}
		}
		if e.PathPrefix != "" {
			if len(paths) == 0 {
				continue
			}
			all := true
			for _, p := range paths {
				if !strings.HasPrefix(p, e.PathPrefix) {
					all = false
					break
				}
			}
			if !all {
				continue
			}
		}
		if e.ua != "" {
			if len(uas) == 0 {
				continue
			}
			all := true
			for _, u := range uas {
				if !strings.Contains(strings.ToLower(u), e.ua) {
					all = false
					break
				}
			}
			if !all {
				continue
			}
		}
		return true
	}
	return false
}
