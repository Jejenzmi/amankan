-- Amankan PoC schema. PostgreSQL holds transactional data (assets, scan jobs,
-- findings). Graph/attack-path data (Neo4j) is out of scope for Phase 1.

CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK (type IN ('ip','domain','repo')),
    target      TEXT NOT NULL,
    criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low','medium','high','critical')),
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    profile     TEXT NOT NULL,
    scanners    TEXT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
    error       TEXT NOT NULL DEFAULT '',
    used_mock   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_asset ON scan_jobs(asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID PRIMARY KEY,
    scan_job_id   UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scanner       TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'info',
    cvss          DOUBLE PRECISION NOT NULL DEFAULT 0,
    cve           TEXT NOT NULL DEFAULT '',
    cwe           TEXT NOT NULL DEFAULT '',
    port          INT NOT NULL DEFAULT 0,
    service       TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','validated','false_positive','remediated')),
    risk_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
    known_exploit BOOLEAN NOT NULL DEFAULT false,
    compliance    JSONB NOT NULL DEFAULT '[]',
    remediation   JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe);
