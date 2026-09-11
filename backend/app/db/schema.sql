-- Reference DDL. The app also creates identical tables via
-- Base.metadata.create_all() on startup.

CREATE TABLE IF NOT EXISTS repositories (
    id              BIGSERIAL PRIMARY KEY,
    github_full_name TEXT NOT NULL UNIQUE,          -- "org/repo"
    default_branch  TEXT,
    primary_language TEXT,
    exposure_tier   TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (exposure_tier IN ('internet','internal','library','unknown')),
    is_archived     BOOLEAN NOT NULL DEFAULT FALSE,
    last_scan_id    BIGINT,                          -- no FK: avoids circular dependency with scans
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id            BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'running'
                  CHECK (status IN ('running','completed','failed')),
    error         TEXT,
    stats         JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_id, started_at DESC);

CREATE TABLE IF NOT EXISTS dependencies (
    id             BIGSERIAL PRIMARY KEY,
    repository_id  BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ecosystem      TEXT NOT NULL CHECK (ecosystem IN ('PyPI','npm')),
    name           TEXT NOT NULL,
    version        TEXT NOT NULL DEFAULT '',         -- '' = unresolved
    version_source TEXT NOT NULL DEFAULT 'none'
                   CHECK (version_source IN ('pin','lockfile','guess','none')),
    raw_specifier  TEXT,
    is_direct      BOOLEAN NOT NULL DEFAULT TRUE,
    is_dev         BOOLEAN NOT NULL DEFAULT FALSE,
    source_file    TEXT NOT NULL,
    UNIQUE (repository_id, ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS idx_deps_repo ON dependencies(repository_id);
CREATE INDEX IF NOT EXISTS idx_deps_pkg  ON dependencies(ecosystem, name);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          BIGSERIAL PRIMARY KEY,
    osv_id      TEXT NOT NULL UNIQUE,                -- GHSA-xxxx / CVE-xxxx / PYSEC-xxxx
    cve_id      TEXT,
    summary     TEXT,
    cvss_score  NUMERIC(3,1),
    cvss_vector TEXT,
    severity    TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE') OR severity IS NULL),
    fixed_versions TEXT[],
    raw         JSONB,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

-- One row per (scan, dependency, vulnerability): the dashboard unit.
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    repository_id   BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    dependency_id   BIGINT NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    reachable       BOOLEAN,                          -- NULL = unknown / not analyzed
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_score      NUMERIC(4,2) NOT NULL,
    risk_tier       TEXT NOT NULL CHECK (risk_tier IN ('P0','P1','P2','P3')),
    rationale       JSONB NOT NULL DEFAULT '[]'::jsonb,
    triage_status   TEXT NOT NULL DEFAULT 'open' CHECK (triage_status IN ('open','accepted_risk','false_positive','mitigated','snoozed')),
    triage_notes    TEXT,
    triaged_by      TEXT,
    triaged_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, dependency_id, vulnerability_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_latest ON findings(repository_id, scan_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tier   ON findings(risk_tier);
CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(triage_status);
