# ADR-011: Metrics, audit log, tracing, rate limits and configuration reload

Status: accepted, implemented.

## Context

Operators need to see what the service does and to change it without downtime. The data that flows through it (claims, nonces, request handles, same-device response codes, tokens) must not leak into the tools they use for that.

## Decision

1. **Metrics on the management port only.** Micrometer with a Prometheus registry at `:9000/metrics`. Tags are configuration ids (tenant, policy, client), actions, outcomes and reason codes, all bounded by the configuration and the code. The HTTP server, HTTP client and Vert.x binders are off, because request paths carry request handles. A test asserts the public port serves no metrics or health, and that the metrics text contains no session id, handle, nonce, token or claim.
2. **One audit trail, three sinks.** Every audited event goes through one component that writes the existing `audit_event` row, one line in the `eudiw.audit` log category and the `eudiw_events_total` counter. There is no audit API: the table and the log are the interfaces.
3. **Tracing is off by default.** OpenTelemetry with OTLP export is built in and enabled by configuration. A span processor runs when a span starts and replaces the request handle in `/oid4vp/requests/{handle}` and every query string, since either would let a reader of the traces fetch a request or retrieve a same-device result. JDBC tracing stays off.
4. **Rate limits per client, shared by all nodes.** Session creation counts in a one-minute window keyed by client in PostgreSQL (one upsert per creation), and refuses with 429 and `Retry-After` above the client's `rate_limit` (default 300 per minute). The check runs after authentication, so the key is the authenticated client. Wallet endpoints are not limited by the service: they are unauthenticated, and per-source limits belong at the ingress.
5. **Configuration reload with revision-bound sessions.** Each node fingerprints the tenants file and the sizes and modification times of the files under its directory, and reloads when they change. A configuration that fails validation is refused and the running one stays. Sessions already carry the revision they started under; the replaced configuration, with its verifiers and keys, is kept for 15 minutes (the longest session lifetime), so a session finishes under its own rules. A session that reaches a node without its revision makes the node check the file first, then fails closed with `configuration_changed`. A changed configuration rebuilds trusted lists and status caches; lists are fetched before the new configuration becomes active.

## Consequences

- No admin API for clients and policies: the file stays the single source, reviewed and versioned like code.
- Changes inside an HSM token alone are not detected by the fingerprint; touch the configuration to reload.
- During a rolling Secret update, nodes can briefly run different revisions; sessions created on a newer node fail closed on an older one until it sees the file.
- Removing a client removes its access to open sessions at once, since client authentication always uses the active configuration.
- Traces and metrics add two Quarkus extensions to the service. `adapter-core` is unchanged.
