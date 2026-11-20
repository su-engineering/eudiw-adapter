-- One row per OpenID Connect authorization request to the wallet login provider (ADR-018). The row ties the
-- browser that started the login (binding_hash, from a cookie) to the verification session that runs the wallet
-- presentation, then carries the authorization code and the access token for userinfo. Codes, tokens and the
-- binding value are stored as hashes; the login's claims only encrypted, and only until the access token expires.
CREATE TABLE oidc_authorization (
    id                    TEXT        PRIMARY KEY,
    tenant_id             TEXT        NOT NULL,
    client_id             TEXT        NOT NULL,
    session_id            TEXT        NOT NULL UNIQUE REFERENCES verification_session (id) ON DELETE CASCADE,
    status                TEXT        NOT NULL CHECK (status IN ('pending', 'completing', 'code_issued', 'redeemed',
                                                                 'failed', 'revoked')),
    binding_hash          TEXT        NOT NULL,
    redirect_uri          TEXT        NOT NULL,
    state                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT,
    error                 TEXT,
    code_hash             TEXT        UNIQUE,
    code_ciphertext       BYTEA,
    code_expires_at       TIMESTAMPTZ,
    access_token_hash     TEXT        UNIQUE,
    access_expires_at     TIMESTAMPTZ,
    claims_ciphertext     BYTEA,
    auth_time             TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX oidc_authorization_expiry ON oidc_authorization (expires_at);
