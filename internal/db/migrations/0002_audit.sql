-- Tamper-evident audit log. Append-only, hash-chained: each row's hash commits
-- to the previous row's hash, so any tampering with history is detectable
-- (ISO 27001 A.8.15, SOC 2 CC7, BSSN forensic retention).

CREATE TABLE IF NOT EXISTS audit_log (
    seq        BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    status     INT NOT NULL DEFAULT 0,
    remote_ip  TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
