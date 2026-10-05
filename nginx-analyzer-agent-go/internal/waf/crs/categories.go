package crs

import (
	"regexp"
	"strconv"
)

// Category : cle + libelle francais.
type Category struct {
	Key   string
	Label string
}

// Categories dans l'ordre d'affichage.
var Categories = []Category{
	{"sqli", "Injection SQL"},
	{"xss", "XSS (injection de script)"},
	{"lfi", "Inclusion de fichier local (LFI)"},
	{"rfi", "Inclusion de fichier distant (RFI)"},
	{"rce", "Execution de commande (RCE)"},
	{"php", "Injection PHP"},
	{"generic", "Attaques generiques"},
	{"java", "Injection Java"},
	{"scanner", "Detection de scanners"},
	{"protocol", "Protocole HTTP"},
	{"session-fixation", "Fixation de session"},
	{"method", "Methodes HTTP"},
	{"multipart", "Multipart"},
	{"other", "Autres"},
}

// CategoryLabel renvoie le libelle FR d'une categorie.
func CategoryLabel(key string) string {
	for _, c := range Categories {
		if c.Key == key {
			return c.Label
		}
	}
	return key
}

var byNumber = map[int]string{
	911: "method",
	913: "scanner",
	920: "protocol",
	921: "protocol",
	922: "multipart",
	930: "lfi",
	931: "rfi",
	932: "rce",
	933: "php",
	934: "generic",
	941: "xss",
	942: "sqli",
	943: "session-fixation",
	944: "java",
}

var reReqFile = regexp.MustCompile(`^REQUEST-(\d{3})-`)

// CategoryOfFile deduit la categorie du nom de fichier REQUEST-9xx-... ("other" sinon).
func CategoryOfFile(name string) string {
	if m := reReqFile.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[1])
		if c, ok := byNumber[n]; ok {
			return c
		}
	}
	return "other"
}

// CategoryOfID deduit la categorie de l'identifiant (911xxx -> method...). Regles
// utilisateur (>= 9100000) et inconnues : "other".
func CategoryOfID(id int) string {
	if id >= 9100000 {
		return "other"
	}
	if c, ok := byNumber[id/1000]; ok {
		return c
	}
	return "other"
}
