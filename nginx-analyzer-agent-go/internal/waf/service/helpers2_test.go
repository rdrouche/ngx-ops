package service

import (
	"fmt"
	"time"

	"nginx-analyzer-go/internal/waf/logsource"
	"nginx-analyzer-go/internal/waf/store"
)

func entryFor(ip string, i int) *logsource.Entry {
	return &logsource.Entry{TS: time.Now().UnixMilli(), Format: "combined", Vhost: "a.example.com", IP: ip, Method: "GET",
		URI: fmt.Sprintf("/?q=1+union+select+%d", i), Proto: "HTTP/1.1", Status: 200, UA: "Mozilla/5.0"}
}

type HitQ struct {
	IP    string
	Vhost string
	Rule  int
	Limit int
}

func (q *HitQ) filter() store.HitFilter {
	return store.HitFilter{IP: q.IP, Vhost: q.Vhost, Rule: q.Rule, Limit: q.Limit}
}

type HitView struct {
	IP, Vhost, Mode, URI string
	Score                int
	Rules                []int
}

func (h HitView) has(id int) bool {
	for _, r := range h.Rules {
		if r == id {
			return true
		}
	}
	return false
}
