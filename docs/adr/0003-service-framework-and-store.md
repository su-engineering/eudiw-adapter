# ADR-003: Service framework and persistent store

Status: proposed.

## Decision

- **Runtime:** Java 21, Quarkus 3.x (exact version pinned when WP-02 starts and recorded in [standards-matrix.md](../standards-matrix.md)), Jakarta REST resources, JVM mode first. Native image is out of scope until the crypto and BouncyCastle setup is proven in JVM mode.
- **Store:** PostgreSQL 16 or later, Flyway migrations, one schema per deployment, `tenant_id` on every tenant-owned row.
- **Single-use and completion:** wallet response acceptance is one `UPDATE ... WHERE id = ? AND tenant_id = ? AND state = 'PENDING' AND expires_at > now()` and succeeds for exactly one caller. No in-memory state is authoritative, so any node can serve any request.
- **Results:** minimized result stored encrypted with a per-tenant data key, deleted on retrieval or TTL. Raw `vp_token` is never persisted.
- **Auth for the management API:** OAuth2 client credentials with JWT access tokens (issuer, audience, expiry, scopes); the token's client identity selects the tenant. Keycloak is the authorization server in the demo; any OpenID Connect provider works. mTLS client authentication is a possible later addition.
- **Observability:** OpenTelemetry and Prometheus exporters, local only by default, with an allowlist of log fields.

## Why Quarkus

Java 21, mature Jakarta REST, PostgreSQL and OpenTelemetry support, and restricted-container deployments are well documented. `adapter-core` is plain Java with no framework dependency, so the service framework can change without touching verification code.

## Rejected

- Building the API on an identity provider's browser login flow: it depends on a browser session and cannot serve backend-to-backend callers safely.
- Redis or Infinispan as the authoritative store for M1: adds an operational dependency without removing the need for durable audit.
