-- Outbox of webhook notifications. Rows are written in the same statement that ends a session and hold
-- identifiers only; the payload is built at delivery time from the session and never contains claims.
CREATE TABLE webhook_delivery (
    id              TEXT        PRIMARY KEY,
    session_id      TEXT        NOT NULL,
    tenant_id       TEXT        NOT NULL,
    client_id       TEXT        NOT NULL,
    event_status    TEXT        NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    state           TEXT        NOT NULL DEFAULT 'pending',
    attempts        INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    claimed_until   TIMESTAMPTZ,
    last_result     TEXT,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX webhook_delivery_due ON webhook_delivery (next_attempt_at) WHERE state = 'pending';
