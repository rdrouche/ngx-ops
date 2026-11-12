package api

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/model"
	"ngxops/logstore/pkg/wire"
)

var idemRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

const (
	maxLineBytes     = 256 << 10
	gzipExpandFactor = 8 // plafond de la taille décompressée = MaxBodyBytes × 8
)

func (s *Server) ingest(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	key := r.Header.Get(wire.HeaderIdempotencyKey)
	if !idemRe.MatchString(key) {
		writeErr(w, 400, "idempotency_key_required", "en-tête Idempotency-Key de 8 à 128 caractères [A-Za-z0-9._:-]")
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	capDecoded := s.cfg.MaxBodyBytes * gzipExpandFactor
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			if tooBig(err) {
				writeErr(w, 413, "body_too_large", "")
				return
			}
			writeErr(w, 400, "bad_gzip", "")
			return
		}
		defer gz.Close()
		body = gz
	}
	body = &capReader{r: body, left: capDecoded}

	set := s.store.Settings()
	p := model.Params{Now: time.Now(), MaxAge: time.Duration(set.RetentionDays) * 24 * time.Hour, Mode: set.IPMode, T: s.ip}

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var (
		rows   []model.Row
		res    wire.Result
		lineNo int
		lines  int
	)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		if lines > s.cfg.MaxBatchEvents {
			writeErr(w, 413, "batch_too_large", "")
			return
		}
		var ev wire.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			addReject(&res, lineNo, "bad_json")
			continue
		}
		row, err := model.Normalize(ev, p)
		if err != nil {
			addReject(&res, lineNo, err.Error())
			continue
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		switch {
		case tooBig(err), errors.Is(err, bufio.ErrTooLong), errors.Is(err, errCapExceeded):
			writeErr(w, 413, "body_too_large", "")
		default:
			writeErr(w, 400, "bad_body", "")
		}
		return
	}
	if lines == 0 {
		writeErr(w, 400, "empty_batch", "")
		return
	}

	dup, err := s.store.Ingest(r.Context(), id.InstanceID, instanceName(r.Header.Get(wire.HeaderInstanceName)), key, rows)
	if err != nil {
		s.log.Error("ingestion en échec", "instance", id.InstanceID, "err", sqlClass(err))
		w.Header().Set("Retry-After", "5")
		writeErr(w, 503, "storage_unavailable", "")
		return
	}
	res.Duplicate = dup
	if !dup {
		res.Accepted = len(rows)
	}
	writeJSON(w, 200, res)
}

func addReject(res *wire.Result, line int, reason string) {
	res.RejectedTotal++
	if len(res.Rejected) < wire.MaxRejectedListed {
		res.Rejected = append(res.Rejected, wire.Reject{Line: line, Reason: reason})
	}
}

func tooBig(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

var errCapExceeded = errors.New("taille décompressée excessive")

// capReader borne la taille décompressée (protection contre les bombes gzip).
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errCapExceeded
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// instanceName nettoie le libellé facultatif de l'instance.
func instanceName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// sqlClass journalise la classe d'erreur sans détail pouvant contenir un secret.
func sqlClass(err error) string {
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) {
		return "SQLSTATE " + pe.SQLState()
	}
	return "erreur base (réseau/contexte)"
}
