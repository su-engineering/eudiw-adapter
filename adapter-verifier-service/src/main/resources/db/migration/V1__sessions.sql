-- Verification sessions. Every row is owned by a tenant; every query filters by tenant_id.
CREATE TABLE verification_session (
    id                    TEXT        PRIMARY KEY,
    tenant_id             TEXT        NOT NULL,
    client_id             TEXT        NOT NULL,
    policy_id             TEXT        NOT NULL,
    config_revision       TEXT        NOT NULL,
    mode                  TEXT        NOT NULL CHECK (mode IN ('same_device', 'cross_device')),
    status                TEXT        NOT NULL CHECK (status IN ('pending', 'verified', 'rejected', 'denied', 'expired', 'cancelled', 'consumed')),
    request_handle        TEXT        NOT NULL UNIQUE,
    idempotency_key_hash  TEXT        NOT NULL,
    request_fingerprint   TEXT        NOT NULL,
    client_reference      TEXT,
    failure_code          TEXT,
    response_code_hash    TEXT,
    result_ciphertext     BYTEA,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    completed_at          TIMESTAMPTZ,
    result_expires_at     TIMESTAMPTZ,
    UNIQUE (tenant_id, client_id, idempotency_key_hash)
);

CREATE INDEX verification_session_expiry ON verification_session (status, expires_at);

-- One row per fetch of the request_uri: each fetch gets its own nonce, state and encryption key.
CREATE TABLE request_instance (
    kid                   TEXT        PRIMARY KEY,
    session_id            TEXT        NOT NULL REFERENCES verification_session (id) ON DELETE CASCADE,
    tenant_id             TEXT        NOT NULL,
    state                 TEXT        NOT NULL UNIQUE,
    nonce                 TEXT        NOT NULL,
    key_ciphertext        BYTEA       NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed_at           TIMESTAMPTZ
);

CREATE INDEX request_instance_session ON request_instance (session_id);

-- Audit trail: decisions and codes only, never claims or credentials.
CREATE TABLE audit_event (
    id                    BIGSERIAL   PRIMARY KEY,
    tenant_id             TEXT        NOT NULL,
    session_id            TEXT,
    client_id             TEXT,
    action                TEXT        NOT NULL,
    outcome               TEXT        NOT NULL,
    code                  TEXT,
    config_revision       TEXT,
    occurred_at           TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_event_tenant_time ON audit_event (tenant_id, occurred_at);
