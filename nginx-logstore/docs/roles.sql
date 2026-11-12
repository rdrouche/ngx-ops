-- Rôles PostgreSQL séparés (moindre privilège) — à appliquer APRÈS un premier
-- démarrage du log store avec le seul rôle propriétaire (les tables existent alors).
-- Remplacer les mots de passe ; relancer ensuite le service avec :
--   LOGSTORE_DATABASE_URL        = rôle propriétaire (DDL, réglages, jetons)
--   LOGSTORE_DATABASE_URL_READ   = ls_read
--   LOGSTORE_DATABASE_URL_WRITE  = ls_write
-- Idempotent : peut être rejoué (par exemple après une mise à jour).

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ls_read')  THEN CREATE ROLE ls_read  LOGIN PASSWORD 'CHANGER_MOI_LECTURE'; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ls_write') THEN CREATE ROLE ls_write LOGIN PASSWORD 'CHANGER_MOI_ECRITURE'; END IF;
END $$;

-- Lecture seule : événements, cumuls, instances. Rien sur api_tokens / settings.
GRANT USAGE ON SCHEMA public TO ls_read, ls_write;
GRANT SELECT ON events, events_1h, events_1d, instances TO ls_read;

-- Écriture : insertion d'événements et de lots, mise à jour des instances.
-- Aucun SELECT sur events, aucun accès aux jetons ni aux réglages.
GRANT INSERT ON events, ingest_batches TO ls_write;
GRANT INSERT, UPDATE ON instances TO ls_write;
GRANT SELECT (id, events_total, name) ON instances TO ls_write;  -- requis par ON CONFLICT DO UPDATE
GRANT USAGE ON SEQUENCE events_id_seq TO ls_write;
