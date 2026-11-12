package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var base = map[string]string{
	"LOGSTORE_DATABASE_URL": "postgres://u@h/db",
	"LOGSTORE_TLS_CERT":     "/c.pem",
	"LOGSTORE_TLS_KEY":      "/k.pem",
}

func with(extra map[string]string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.RetentionDays != 30 || c.IPMode != "clear" || c.DatabaseRead != c.DatabaseURL {
		t.Fatalf("%+v", c)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]map[string]string{
		"LOGSTORE_DATABASE_URL":  {"LOGSTORE_DATABASE_URL": ""},
		"TLS requis":             {"LOGSTORE_TLS_CERT": "", "LOGSTORE_TLS_KEY": ""},
		"vont ensemble":          {"LOGSTORE_TLS_KEY": ""},
		"entre 7 et 30":          {"LOGSTORE_RETENTION_DAYS": "90"},
		"pseudonymized exige":    {"LOGSTORE_IP_MODE": "pseudonymized"},
		"PSEUDO_KEY trop courte": {"LOGSTORE_PSEUDO_KEY": "court"},
		"ADMIN_TOKEN trop court": {"LOGSTORE_ADMIN_TOKEN": "court"},
		"mode IP inconnu":        {"LOGSTORE_IP_MODE": "x"},
	}
	for want, extra := range cases {
		m := with(extra)
		for k, v := range extra {
			if v == "" {
				delete(m, k)
			}
		}
		_, err := FromEnv(env(m))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: obtenu %v", want, err)
		}
	}
}

func TestInsecureHTTPExplicit(t *testing.T) {
	m := with(map[string]string{"LOGSTORE_INSECURE_HTTP": "true"})
	delete(m, "LOGSTORE_TLS_CERT")
	delete(m, "LOGSTORE_TLS_KEY")
	if _, err := FromEnv(env(m)); err != nil {
		t.Fatal(err)
	}
}
