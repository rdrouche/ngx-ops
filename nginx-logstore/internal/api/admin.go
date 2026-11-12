package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ngxops/logstore/internal/auth"
	"ngxops/logstore/internal/ipmode"
	"ngxops/logstore/internal/store"
)

var instanceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	writeJSON(w, 200, s.settingsView())
}

func (s *Server) settingsView() map[string]any {
	c := s.store.Settings()
	return map[string]any{
		"retention_days":        c.RetentionDays,
		"agg_retention_days":    c.AggRetentionDays,
		"ip_mode":               c.IPMode,
		"timescale":             s.store.Timescale(),
		"pseudo_key_configured": s.ip.HasKey(),
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, 400, "bad_json", "")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, 400, "bad_json", "")
		return false
	}
	return true
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var in struct {
		RetentionDays    *int    `json:"retention_days"`
		AggRetentionDays *int    `json:"agg_retention_days"`
		IPMode           *string `json:"ip_mode"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	cur := s.store.Settings()
	if in.RetentionDays != nil {
		cur.RetentionDays = *in.RetentionDays
	}
	if in.AggRetentionDays != nil {
		cur.AggRetentionDays = *in.AggRetentionDays
	}
	if in.IPMode != nil {
		m, err := ipmode.Parse(*in.IPMode)
		if err != nil {
			writeErr(w, 400, "bad_request", "ip_mode : clear, pseudonymized ou truncated")
			return
		}
		cur.IPMode = m
	}
	if cur.IPMode == ipmode.Pseudonymized && !s.ip.HasKey() {
		writeErr(w, 409, "pseudonymization_key_missing", "définir LOGSTORE_PSEUDO_KEY (≥ 32 caractères) puis redémarrer")
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	if err := s.store.SaveSettings(ctx, cur); err != nil {
		if errors.Is(err, store.ErrInvalidSettings) {
			writeErr(w, 400, "bad_request", err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, s.settingsView())
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	ctx, cancel := s.qctx(r)
	defer cancel()
	t, err := s.store.ListTokens(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": t})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var in struct {
		Label      string `json:"label"`
		Role       string `json:"role"`
		InstanceID string `json:"instance_id"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" || len(in.Label) > 64 {
		writeErr(w, 400, "bad_request", "label : 1 à 64 caractères")
		return
	}
	if !auth.ValidRole(in.Role) {
		writeErr(w, 400, "bad_request", "role : write, read ou admin")
		return
	}
	if in.Role == auth.RoleWrite {
		if !instanceRe.MatchString(in.InstanceID) {
			writeErr(w, 400, "bad_request", "instance_id requis pour write : [a-z0-9._-], 1 à 63 caractères")
			return
		}
	} else if in.InstanceID != "" {
		// read : instance_id OPTIONNEL = jeton limité aux données de cette instance (#89). admin : jamais limité.
		if in.Role != auth.RoleRead || !instanceRe.MatchString(in.InstanceID) {
			writeErr(w, 400, "bad_request", "instance_id : réservé à write (obligatoire) et read (optionnel, limite la lecture à cette instance)")
			return
		}
	}
	tok, err := auth.Generate()
	if err != nil {
		writeErr(w, 500, "internal", "")
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	id, err := s.store.CreateToken(ctx, in.Label, in.Role, in.InstanceID, auth.Hash(tok))
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.ReloadTokens(ctx); err != nil {
		s.log.Warn("rechargement des jetons", "err", sqlClass(err))
	}
	// Le jeton n'est montré qu'ici, une seule fois.
	out := map[string]any{"id": id, "token": tok, "role": in.Role}
	if in.InstanceID != "" {
		out["instance_id"] = in.InstanceID
	}
	writeJSON(w, 201, out)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, self auth.Identity) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad_request", "id invalide")
		return
	}
	ctx, cancel := s.qctx(r)
	defer cancel()
	ok, err := s.store.RevokeToken(ctx, id)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		writeErr(w, 409, "last_admin", err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	case !ok:
		writeErr(w, 404, "not_found", "")
		return
	}
	if err := s.ReloadTokens(ctx); err != nil {
		s.log.Warn("rechargement des jetons", "err", sqlClass(err))
	}
	_ = self
	w.WriteHeader(204)
}

// getMaintenance : état de la maintenance PostgreSQL (#96), admin.
func (s *Server) getMaintenance(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	st, err := s.store.MaintenanceStatus(r.Context())
	if err != nil {
		writeErr(w, 503, "unavailable", "")
		return
	}
	writeJSON(w, 200, map[string]any{
		"enabled":        s.cfg.MaintenanceEnabled,
		"interval_hours": int(s.cfg.MaintenanceInterval / time.Hour),
		"timescale":      s.store.Timescale(),
		"status":         st,
		"checks":         s.store.Checks(r.Context()),
	})
}

// runMaintenance lance la maintenance sans attendre la fin (VACUUM peut durer) :
// 202 ; l'avancement se lit via GET. 409 si déjà en cours.
func (s *Server) runMaintenance(w http.ResponseWriter, _ *http.Request, _ auth.Identity) {
	if s.store.MaintenanceRunning() {
		writeErr(w, 409, "busy", "")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		if _, err := s.store.RunMaintenance(ctx, "manual"); err != nil && !errors.Is(err, store.ErrMaintenanceBusy) {
			s.log.Warn("maintenance manuelle", "err", "échec (voir GET /v1/maintenance)")
		}
	}()
	writeJSON(w, 202, map[string]any{"started": true})
}
