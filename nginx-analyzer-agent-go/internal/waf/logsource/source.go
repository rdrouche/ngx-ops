package logsource

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"nginx-analyzer-go/internal/parse"
	"nginx-analyzer-go/internal/tail"
)

// DetectFormat : waf_json si la premiere ligne non vide commence par '{', sinon detection
// combined/vhost de l'analyseur. Echantillon vide => "" (re-detecte a l'arrivee des donnees).
func DetectFormat(sample []string) string {
	nonEmpty := false
	for _, l := range sample {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		nonEmpty = true
		if l[0] == '{' {
			return FormatWafJSON
		}
		break
	}
	if !nonEmpty {
		return ""
	}
	return parse.DetectFormat(sample)
}

// Options de la source de logs.
type Options struct {
	Dir        string
	Pattern    *regexp.Regexp // fichiers combined / vhost
	WafPattern *regexp.Regexp // fichiers waf_json
	PollMs     int
	Offsets    tail.OffsetStore
	// OnEntry est appele depuis la goroutine du tailer : il ne doit JAMAIS bloquer.
	OnEntry func(*Entry)
}

// Source suit les deux familles de fichiers.
type Source struct {
	tailers []*tail.Tailer
	wafTail *tail.Tailer // tailer des fichiers waf_json (nil si non configure)
	skipped atomic.Int64

	smu     sync.Mutex
	samples []string // dernieres lignes non comprises (tronquees), pour le diagnostic
}

// noteUnparsed garde un echantillon (5 max, 200 caracteres) des lignes illisibles.
func (s *Source) noteUnparsed(line string) {
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	s.smu.Lock()
	if len(s.samples) >= 5 {
		s.samples = s.samples[1:]
	}
	s.samples = append(s.samples, line)
	s.smu.Unlock()
}

// UnparsedSamples renvoie une copie des derniers echantillons.
func (s *Source) UnparsedSamples() []string {
	s.smu.Lock()
	defer s.smu.Unlock()
	return append([]string(nil), s.samples...)
}

// New construit la source (sans la demarrer).
func New(o Options) *Source {
	s := &Source{}
	mk := func(pat *regexp.Regexp, vhostFn tail.VhostFromFilenameFunc) *tail.Tailer {
		return tail.New(tail.Options{
			Dir: o.Dir, Pattern: pat, Store: o.Offsets, PollMs: o.PollMs,
			DetectFormat: DetectFormat,
			ParseLine: func(line, format, defaultVhost string) (any, bool) {
				var e *Entry
				var ok bool
				if format == FormatWafJSON {
					e, ok = ParseJSON(line, defaultVhost)
				} else {
					e, ok = ParseAccess(line, format, defaultVhost)
				}
				if !ok {
					s.noteUnparsed(line)
					return nil, false
				}
				return e, true
			},
			VhostFromFilename: vhostFn,
			OnEntry: func(v any) {
				if e, ok := v.(*Entry); ok && o.OnEntry != nil {
					o.OnEntry(e)
				}
			},
		})
	}
	if o.Pattern != nil {
		s.tailers = append(s.tailers, mk(o.Pattern, parse.VhostFromFilename))
	}
	if o.WafPattern != nil {
		s.wafTail = mk(o.WafPattern, func(string) string { return "" })
		s.tailers = append(s.tailers, s.wafTail)
	}
	return s
}

// WafFilesFollowed : au moins un fichier waf_json est suivi (meme encore vide). Sert au dedoublonnage :
// il doit etre actif des la premiere ligne, avant que le format du fichier soit detecte.
func (s *Source) WafFilesFollowed() bool {
	if s.wafTail == nil {
		return false
	}
	st, _ := s.wafTail.Status()
	return st.Files > 0
}

// Start demarre le suivi (un premier Poll est execute de facon synchrone).
func (s *Source) Start() {
	for _, t := range s.tailers {
		t.Start()
	}
}

// Stop arrete le suivi.
func (s *Source) Stop() {
	for _, t := range s.tailers {
		t.Stop()
	}
}

// Poll force une passe (tests).
func (s *Source) Poll() {
	for _, t := range s.tailers {
		t.Poll()
	}
}

// Status agrege l'etat des tailers.
type Status struct {
	Files   int
	Formats map[string]int
	Lines   int
	Dropped int
}

// Status renvoie l'etat agrege (fichiers, formats, lignes lues, lignes non comprises).
func (s *Source) Status() Status {
	st := Status{Formats: map[string]int{"combined": 0, "vhost": 0, "waf_json": 0}}
	for _, t := range s.tailers {
		stats, files := t.Status()
		st.Files += stats.Files
		st.Lines += stats.Lines
		st.Dropped += stats.Dropped
		for _, f := range files {
			if f.Format != "" {
				st.Formats[f.Format]++
			}
		}
	}
	return st
}
