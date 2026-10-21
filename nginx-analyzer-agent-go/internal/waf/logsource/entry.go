// Package logsource transforme les lignes de log nginx (combined, vhost, waf_json) en
// requetes synthetiques pour le moteur, et suit les fichiers (internal/tail).
package logsource

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/waf/engine"
)

// Formats connus.
const (
	FormatCombined = "combined"
	FormatVhost    = "vhost"
	FormatWafJSON  = "waf_json"
)

// Entry est une requete lue dans un log (avant injection des en-tetes neutres).
type Entry struct {
	TS      int64 // epoch ms
	Format  string
	Vhost   string
	IP      string
	Method  string
	URI     string // URI nginx deja convertie (\xNN -> %NN)
	Proto   string
	Status  int
	UA      string
	Referer string
	Skip    bool // ligne sans requete exploitable ("-")
	WafJSON bool
	CT      string
	CL      string
	HasCL   bool
	Accept  string
	AcceptL string
	AcceptE string
	Origin  string
	XRW     string
	XFF     string
}

// FixURI remplace les sequences \xNN (echappement nginx) par %NN.
func FixURI(u string) string {
	if !strings.Contains(u, `\x`) {
		return u
	}
	var b strings.Builder
	b.Grow(len(u))
	for i := 0; i < len(u); i++ {
		if u[i] == '\\' && i+3 < len(u)+0 && u[i+1] == 'x' && isHex(u[i+2]) && isHex(u[i+3]) {
			b.WriteByte('%')
			b.WriteByte(u[i+2])
			b.WriteByte(u[i+3])
			i += 3
			continue
		}
		b.WriteByte(u[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// protoFromLine extrait le protocole de la requete ("GET /x HTTP/1.1") d'une ligne combined.
func protoFromLine(line string) string {
	i := strings.Index(line, `] "`)
	if i < 0 {
		return "HTTP/1.1"
	}
	rest := line[i+3:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return "HTTP/1.1"
	}
	f := strings.Fields(rest[:j])
	if len(f) >= 3 && strings.HasPrefix(f[len(f)-1], "HTTP/") {
		return f[len(f)-1]
	}
	return "HTTP/1.1"
}

// ParseAccess traite une ligne combined / vhost via le parseur existant.
func ParseAccess(line, format, defaultVhost string) (*Entry, bool) {
	e, ok := parse.ParseLine(line, format, defaultVhost)
	if !ok {
		return nil, false
	}
	out := &Entry{TS: e.TS, Format: format, Vhost: e.Vhost, IP: e.IP, Status: e.Status}
	if e.Method == nil || e.Path == nil {
		out.Skip = true
		return out, true
	}
	out.Method = *e.Method
	out.URI = FixURI(*e.Path)
	out.Proto = protoFromLine(line)
	if e.UA != nil {
		out.UA = *e.UA
	}
	if e.Referer != nil {
		out.Referer = *e.Referer
	}
	return out, true
}

type jsonLine struct {
	T     string  `json:"t"`
	Vhost string  `json:"vhost"`
	IP    string  `json:"ip"`
	M     string  `json:"m"`
	U     string  `json:"u"`
	P     string  `json:"p"`
	S     flexInt `json:"s"`
	UA    string  `json:"ua"`
	Ref   string  `json:"ref"`
	CT    string  `json:"ct"`
	CL    string  `json:"cl"`
	XFF   string  `json:"xff"`
	Acc   string  `json:"acc"`
	AL    string  `json:"al"`
	AE    string  `json:"ae"`
	Org   string  `json:"org"`
	XRW   string  `json:"xrw"`
}

// flexInt accepte 404 ou "404" (ou "-").
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	n, err := strconv.Atoi(s)
	if err != nil {
		*f = 0
		return nil
	}
	*f = flexInt(n)
	return nil
}

// ParseJSON traite une ligne waf_json (champs absents ou "" = en-tete non envoye).
func ParseJSON(line, defaultVhost string) (*Entry, bool) {
	if len(line) < 10 || line[0] != '{' {
		return nil, false
	}
	var j jsonLine
	if err := json.Unmarshal([]byte(line), &j); err != nil {
		return nil, false
	}
	ts := time.Now().UnixMilli()
	if j.T != "" {
		if t, err := time.Parse(time.RFC3339, j.T); err == nil {
			ts = t.UnixMilli()
		} else if t, err := time.Parse("2006-01-02T15:04:05-07:00", j.T); err == nil {
			ts = t.UnixMilli()
		} else {
			return nil, false
		}
	}
	e := &Entry{
		TS: ts, Format: FormatWafJSON, WafJSON: true, Vhost: j.Vhost, IP: j.IP, Status: int(j.S),
		Method: j.M, URI: FixURI(j.U), Proto: j.P, UA: dash(j.UA), Referer: dash(j.Ref),
		CT: dash(j.CT), CL: dash(j.CL), Accept: dash(j.Acc), AcceptL: dash(j.AL), AcceptE: dash(j.AE),
		Origin: dash(j.Org), XRW: dash(j.XRW), XFF: dash(j.XFF),
	}
	e.HasCL = e.CL != ""
	if e.Vhost == "" || e.Vhost == "-" || e.Vhost == "_" {
		e.Vhost = defaultVhost
	}
	if e.Method == "" || e.URI == "" || e.IP == "" {
		e.Skip = true
	}
	return e, true
}

// Request construit la requete synthetique : donnees du log + en-tetes neutres pour ce qui
// est inconnu (contrat, section « Regles non fiables »).
func (e *Entry) Request() engine.Request {
	proto := e.Proto
	if !strings.HasPrefix(proto, "HTTP/") {
		proto = "HTTP/1.1"
	}
	host := e.Vhost
	if host == "" {
		host = "localhost"
	}
	r := engine.Request{Method: e.Method, URI: e.URI, Proto: proto, IP: e.IP, Host: host}
	h := make([][2]string, 0, 10)
	if e.UA != "" {
		h = append(h, [2]string{"User-Agent", e.UA})
	}
	if e.Referer != "" {
		h = append(h, [2]string{"Referer", e.Referer})
	}
	h = append(h, [2]string{"Accept", orDefault(e.Accept, "*/*")})
	h = append(h, [2]string{"Accept-Language", orDefault(e.AcceptL, "en")})
	h = append(h, [2]string{"Accept-Encoding", orDefault(e.AcceptE, "gzip")})
	if e.Origin != "" {
		h = append(h, [2]string{"Origin", e.Origin})
	}
	if e.XRW != "" {
		h = append(h, [2]string{"X-Requested-With", e.XRW})
	}
	if e.XFF != "" {
		h = append(h, [2]string{"X-Forwarded-For", e.XFF})
	}
	switch e.Method {
	case "POST", "PUT", "PATCH":
		h = append(h, [2]string{"Content-Type", orDefault(e.CT, "application/x-www-form-urlencoded")})
		h = append(h, [2]string{"Content-Length", orDefault(e.CL, "0")})
	default:
		if e.CT != "" {
			h = append(h, [2]string{"Content-Type", e.CT})
		}
		if e.CL != "" {
			h = append(h, [2]string{"Content-Length", e.CL})
		}
	}
	r.Headers = h
	return r
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Path renvoie le chemin de l'URI (sans query).
func (e *Entry) Path() string { return parse.NormalizePath(e.URI) }
