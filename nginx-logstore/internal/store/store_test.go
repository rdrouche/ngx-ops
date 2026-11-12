package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/model"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := os.Getenv("LOGSTORE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LOGSTORE_TEST_DATABASE_URL non défini : test d'intégration ignoré")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)
	st, err := openWith(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st, dsn
}

func openWith(ctx context.Context, dsn string) (*Store, error) {
	return Open(ctx, Options{AdminURL: dsn, ReadURL: dsn, WriteURL: dsn, QueryTimeout: 5 * time.Second,
		SeedRetentionDays: 30, SeedIPMode: ipmode.Clear, PseudoKeyPresent: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func row(ts time.Time) model.Row {
	s := "access"
	_ = s
	return model.Row{TS: ts, Source: "access", Action: "allowed"}
}

func TestReadPoolIsReadOnly(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	var v string
	if err := st.read.QueryRow(ctx, `SHOW default_transaction_read_only`).Scan(&v); err != nil || v != "on" {
		t.Fatalf("lecture seule attendue: %q %v", v, err)
	}
	if _, err := st.read.Exec(ctx, `DELETE FROM events`); err == nil {
		t.Fatal("le pool de lecture ne doit pas pouvoir écrire")
	}
	if err := st.write.QueryRow(ctx, `SHOW timezone`).Scan(&v); err != nil || v != "UTC" {
		t.Fatalf("fuseau UTC attendu: %q %v", v, err)
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	st, dsn := open(t)
	if err := st.SaveSettings(context.Background(), Settings{}); err == nil {
		t.Fatal("des réglages vides doivent être refusés")
	}
	cur := st.Settings()
	cur.RetentionDays = 10
	if err := st.SaveSettings(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := openWith(context.Background(), dsn)
	if err != nil {
		t.Fatalf("réouverture: %v", err)
	}
	defer st2.Close()
	if got := st2.Settings().RetentionDays; got != 10 {
		t.Fatalf("les réglages doivent survivre au redémarrage (graine non réappliquée): %d", got)
	}
}

func TestIngestIsAtomic(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	good := row(time.Now())
	bad := row(time.Now())
	bad.IP = "pas-une-ip" // refusée par PostgreSQL pendant le COPY

	if _, err := st.Ingest(ctx, "web1", "", "batch-atom-1", []model.Row{good, bad}); err == nil {
		t.Fatal("le lot invalide doit échouer")
	}
	var n int
	_ = st.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM events) + (SELECT count(*) FROM ingest_batches)`).Scan(&n)
	if n != 0 {
		t.Fatalf("échec atomique attendu, %d lignes écrites", n)
	}
	// l'identifiant n'a pas été « consommé » : le producteur peut rejouer
	dup, err := st.Ingest(ctx, "web1", "", "batch-atom-1", []model.Row{good})
	if err != nil || dup {
		t.Fatalf("rejeu après échec: dup=%v err=%v", dup, err)
	}
}

func TestMaintainPurgesOldEventsInPlainMode(t *testing.T) {
	st, _ := open(t)
	if st.Timescale() {
		t.Skip("mode TimescaleDB : purge gérée par la politique de rétention")
	}
	ctx := context.Background()
	old := row(time.Now().Add(-40 * 24 * time.Hour))
	fresh := row(time.Now())
	if _, err := st.Ingest(ctx, "web1", "", "batch-mt-0001", []model.Row{old, fresh}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.admin.Exec(ctx, `UPDATE ingest_batches SET received_at = now() - interval '8 days'`); err != nil {
		t.Fatal(err)
	}
	if err := st.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	var ev, bt int
	_ = st.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM ingest_batches)`).Scan(&ev, &bt)
	if ev != 1 || bt != 0 {
		t.Fatalf("après maintenance: %d événements, %d lots (attendu 1 et 0)", ev, bt)
	}
}

func TestPseudoKeyRequiredAtStartup(t *testing.T) {
	st, dsn := open(t)
	cur := st.Settings()
	cur.IPMode = ipmode.Pseudonymized
	if err := st.SaveSettings(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	st.Close()
	_, err := Open(context.Background(), Options{AdminURL: dsn, ReadURL: dsn, WriteURL: dsn, QueryTimeout: time.Second,
		SeedRetentionDays: 30, SeedIPMode: ipmode.Clear, PseudoKeyPresent: false}, nil)
	if err == nil {
		t.Fatal("démarrage refusé : mode pseudonymisé sans clé")
	}
}

func TestBadURLDoesNotLeakPassword(t *testing.T) {
	_, err := Open(context.Background(), Options{AdminURL: "postgres://u:sup3rsecret@127.0.0.1:1/db?sslmode=disable&connect_timeout=1",
		ReadURL: "x", WriteURL: "x", QueryTimeout: time.Second, SeedRetentionDays: 30, SeedIPMode: ipmode.Clear}, nil)
	if err == nil {
		t.Fatal("erreur attendue")
	}
	if s := err.Error(); contains(s, "sup3rsecret") {
		t.Fatalf("mot de passe dans l'erreur : %s", s)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRunMaintenanceVacuumsAndReports(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	if _, err := st.Ingest(ctx, "web1", "", "batch-vac-0001", []model.Row{row(time.Now())}); err != nil {
		t.Fatal(err)
	}
	rep, err := st.RunMaintenance(ctx, "manual")
	if err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}
	if len(rep.Tables) != len(maintenanceTables) || rep.Error != "" || rep.Trigger != "manual" {
		t.Fatalf("rapport inattendu: %+v", rep)
	}
	status, err := st.MaintenanceStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Running || status.Last == nil || len(status.Tables) == 0 {
		t.Fatalf("état inattendu: %+v", status)
	}
	var ev *TableStat
	for i := range status.Tables {
		if status.Tables[i].Name == "events" {
			ev = &status.Tables[i]
		}
	}
	if ev == nil || ev.SizeBytes <= 0 {
		t.Fatalf("table events absente de l'état: %+v", status.Tables)
	}
	if st.MaintenanceDue(time.Hour) {
		t.Fatal("pas d'exécution due juste après une maintenance")
	}
}

func TestRunMaintenanceRejectsConcurrentRun(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	st.maint.mu.Lock()
	st.maint.running = true
	st.maint.mu.Unlock()
	if _, err := st.RunMaintenance(ctx, "manual"); err != ErrMaintenanceBusy {
		t.Fatalf("attendu ErrMaintenanceBusy, obtenu %v", err)
	}
	st.maint.mu.Lock()
	st.maint.running = false
	st.maint.mu.Unlock()
}

func TestChecksReportStorageHealth(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	if _, err := st.Ingest(ctx, "web1", "", "batch-chk-0001", []model.Row{row(time.Now())}); err != nil {
		t.Fatal(err)
	}
	got := map[string]Check{}
	for _, c := range st.Checks(ctx) {
		got[c.Name] = c
	}
	if c := got["retention_effective"]; c.Status != "ok" {
		t.Fatalf("rétention: %+v", c)
	}
	if !st.Timescale() {
		if c := got["timescaledb"]; c.Status != "na" {
			t.Fatalf("mode simple: %+v", c)
		}
		return
	}
	for _, name := range []string{"compression", "retention_events", "aggregate_events_1h", "aggregate_events_1d", "retention_events_1h", "retention_events_1d"} {
		c, ok := got[name]
		if !ok || c.Status == "fail" || c.Status == "unknown" {
			t.Fatalf("contrôle %s: %+v", name, c)
		}
	}
	// Une rétention modifiée dans les réglages mais pas dans la politique est signalée.
	if _, err := st.admin.Exec(ctx, `SELECT remove_retention_policy('events', if_exists => TRUE)`); err != nil {
		t.Fatal(err)
	}
	for _, c := range st.Checks(ctx) {
		if c.Name == "retention_events" && c.Status != "fail" {
			t.Fatalf("politique absente non détectée: %+v", c)
		}
	}
}
