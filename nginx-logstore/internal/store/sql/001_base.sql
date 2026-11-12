-- Schéma de base, compatible PostgreSQL simple. La partie TimescaleDB
-- (hypertable, compression, agrégats continus, rétention) est appliquée par
-- le service quand l'extension est disponible (voir timescale.go).

CREATE TABLE IF NOT EXISTS events (
    id           bigint GENERATED ALWAYS AS IDENTITY,
    ts           timestamptz NOT NULL,
    instance_id  text        NOT NULL,
    source       text        NOT NULL,  -- access | challenge | waf | blocklist | crowdsec | analysis
    action       text        NOT NULL,  -- allowed | blocked | challenged | logged
    site         text,
    ip           inet,                  -- selon ip_mode (adresse, préfixe /24 /48, ou NULL)
    ip_key       text,                  -- pseudonyme HMAC si ip_mode = pseudonymized
    method       text,
    path         text,
    query_hash   text,                  -- jamais la query string brute
    status       smallint,
    bytes        bigint,
    rt_ms        integer,
    ua           text,
    referer_host text,
    country      text,
    bot_class    text,
    rule         text,
    extra        jsonb
);

CREATE INDEX IF NOT EXISTS events_ts_id_idx     ON events (ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS events_site_ts_idx   ON events (site, ts DESC);
CREATE INDEX IF NOT EXISTS events_ip_ts_idx     ON events (ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_ipkey_ts_idx  ON events (ip_key, ts DESC) WHERE ip_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_src_act_idx   ON events (source, action, ts DESC);
CREATE INDEX IF NOT EXISTS events_err_idx       ON events (status, ts DESC) WHERE status >= 400;

CREATE TABLE IF NOT EXISTS instances (
    id           text PRIMARY KEY,
    name         text,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    events_total bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ingest_batches (
    instance_id text        NOT NULL,
    batch_id    text        NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    accepted    integer     NOT NULL,
    PRIMARY KEY (instance_id, batch_id)
);
CREATE INDEX IF NOT EXISTS ingest_batches_received_idx ON ingest_batches (received_at);

CREATE TABLE IF NOT EXISTS settings (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    label        text NOT NULL,
    role         text NOT NULL CHECK (role IN ('write','read','admin')),
    instance_id  text,
    hash         bytea NOT NULL UNIQUE,   -- SHA-256 ; le jeton en clair n'est jamais stocké
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    CHECK ((role = 'write') = (instance_id IS NOT NULL))
);
