-- =============================================================================
-- The Midnight Protocol — Backend API (Service 3)
-- Database schema: alerts, cases, evidence_vault (+ chain_of_custody)
-- Target: PostgreSQL (spun up by root docker-compose.yml)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- CASES
-- Investigation cases opened by a Cyber Crime Branch officer/investigator.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cases (
    case_id        SERIAL PRIMARY KEY,
    case_number    VARCHAR(50) UNIQUE NOT NULL,      -- e.g. "CCB/APR/2026/0042"
    title          VARCHAR(255),
    investigator   VARCHAR(100) NOT NULL,
    threat_type    VARCHAR(100) NOT NULL,             -- e.g. "DNS Tunneling"
    status         VARCHAR(30) NOT NULL DEFAULT 'Under Investigation',
    summary        TEXT,
    opened_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_case_status CHECK (
        status IN ('Under Investigation', 'Escalated', 'Closed', 'Archived')
    )
);

-- ---------------------------------------------------------------------------
-- ALERTS
-- Every detection emitted by processing_engine (signature engine + AI engine
-- + threat correlation) lands here, consumed off Kafka by app.py.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            SERIAL PRIMARY KEY,
    case_id             INTEGER REFERENCES cases(case_id) ON DELETE SET NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip           VARCHAR(45) NOT NULL,
    destination_ip      VARCHAR(45),
    destination_port    INTEGER,
    protocol            VARCHAR(20),                  -- HTTP, DNS, SMTP, FTP, ICMP, ARP...
    alert_type          VARCHAR(150) NOT NULL,         -- e.g. "DNS Tunneling Detected"
    severity            VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    detection_engine    VARCHAR(20) NOT NULL DEFAULT 'SIGNATURE',
    anomaly_score       NUMERIC(6,3),                  -- AI engine confidence / deviation score
    baseline_deviation  NUMERIC(6,2),                  -- e.g. "3.7x baseline"
    description         TEXT,
    raw_payload         JSONB,                         -- full original Kafka message for replay
    is_reviewed         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_engine CHECK (detection_engine IN ('SIGNATURE', 'AI', 'CORRELATED'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_case_id      ON alerts(case_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at  ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_protocol     ON alerts(protocol);

-- ---------------------------------------------------------------------------
-- EVIDENCE VAULT
-- SHA-256 sealed evidence items (pcap slices, session replays, exports)
-- linked to a case and optionally the alert that triggered their capture.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_vault (
    evidence_id     SERIAL PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    alert_id        INTEGER REFERENCES alerts(alert_id) ON DELETE SET NULL,
    filename        VARCHAR(255) NOT NULL,
    evidence_type   VARCHAR(50) NOT NULL DEFAULT 'packet_capture',
    file_path       TEXT,
    sha256_hash     CHAR(64) NOT NULL,                 -- sealed by legal_hasher.py upstream, or here
    captured_at     TIMESTAMPTZ,
    added_by        VARCHAR(100) NOT NULL DEFAULT 'System',
    status          VARCHAR(20) NOT NULL DEFAULT 'SEALED',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_evidence_status CHECK (status IN ('SEALED', 'VERIFIED', 'FLAGGED'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence_vault(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash    ON evidence_vault(sha256_hash);

-- ---------------------------------------------------------------------------
-- CHAIN OF CUSTODY
-- Immutable, append-only log of every action taken on an evidence item —
-- what makes the exported report court-admissible.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id   SERIAL PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence_vault(evidence_id) ON DELETE CASCADE,
    action       VARCHAR(255) NOT NULL,     -- e.g. "Evidence captured & hashed"
    actor        VARCHAR(100) NOT NULL,     -- e.g. "Insp. R. Solanki"
    action_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_action_at   ON chain_of_custody(action_at);

-- ---------------------------------------------------------------------------
-- Keep cases.updated_at current whenever a case row changes
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_cases_updated_at ON cases;
CREATE TRIGGER trg_cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
