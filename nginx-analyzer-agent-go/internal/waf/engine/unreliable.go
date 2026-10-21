package engine

import "sort"

// Regles "non fiables" pour les formats combined/vhost : leur resultat depend d'en-tetes ou
// d'un corps que le log d'acces ne contient pas (faux positifs garantis). Liste du contrat.
var unreliableCombined = map[int]bool{
	920280: true, 920290: true, 920300: true, 920310: true, 920311: true, 920330: true,
	920340: true, 920341: true, 920350: true, 920420: true, 920480: true, 920500: true, 920510: true,
}

// IsUnreliable indique si la regle est desactivee "par le systeme" pour ce format
// (combined|vhost|waf_json). hasContentLength : le log fournissait Content-Length (waf_json).
func IsUnreliable(format string, id int, hasContentLength bool) bool {
	if id/1000 == 922 {
		return true
	}
	if format == "waf_json" {
		return (id == 920340 || id == 920341) && !hasContentLength
	}
	return unreliableCombined[id]
}

// unreliableLists calcule la liste exposee dans /api/status.unreliableRules : les ids de la
// liste du contrat PRESENTS dans le CRS installe, plus tous les 922xxx installes.
func unreliableLists(installed map[int]bool) map[string][]int {
	comb := []int{}
	js := []int{}
	for id := range installed {
		if id/1000 == 922 {
			comb = append(comb, id)
			js = append(js, id)
		} else if unreliableCombined[id] {
			comb = append(comb, id)
		}
	}
	sort.Ints(comb)
	sort.Ints(js)
	return map[string][]int{"combined": comb, "waf_json": js}
}
