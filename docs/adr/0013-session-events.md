# ADR-013: Session status as Server-Sent Events

Status: accepted, implemented.

## Context

A backend learns that a session ended either by polling `GET /v1/verification-sessions/{id}` or from a webhook ([ADR-008](0008-webhooks.md)). Polling costs a request per interval and adds up to one interval of delay. Webhooks need an endpoint the adapter can reach, which a backend behind a firewall or in local development often does not have. A stream the backend opens itself, and that carries each change as it happens, fills the gap.

The stream must not become a second channel for claims, must work when the wallet's response lands on another node, and must not let one client exhaust a node.

## Decision

1. **Endpoint.** `GET /v1/verification-sessions/{id}/events`, `text/event-stream`, scope `verification:read`, authorized exactly like the status call: sessions of other clients or tenants return 404. The session creation response carries `events_url` next to `poll_url`.
2. **Same view as polling.** Each event is named `status`, has an increasing `id`, and its data is the JSON the status call returns. It never carries claims; the result is still fetched once with the result call, which keeps the same-device `response_code` binding.
3. **Lifetime.** The first event is the current status. Then one event per change, and the stream closes once the status is anything but `pending`. A session past `expires_at` is reported `expired` at that time, before the sweeper marks the row, so no stream outlives its session. A stream also ends when the access token it was opened with expires, and when its client is removed from the configuration. A comment line is sent every 15 seconds without a change, so proxies keep the connection. The last event is the outcome, not the close: a stream that ends on `pending` (token expired, node stopped) tells the client to reconnect with a fresh token or poll. Access tokens are often shorter-lived than a session (the demo realm issues five-minute tokens against a 15-minute session), so clients must expect it.
4. **State from PostgreSQL, one query per tick.** No stream holds a thread or a database connection. Each node keeps its open streams in memory and, every second (`EUDIW_EVENTS_INTERVAL`), reads all watched sessions in one query and sends what changed. A wallet response handled by another node therefore reaches every stream within one interval. PostgreSQL `LISTEN/NOTIFY` would cut that delay but needs a dedicated connection per node; it can replace the tick later without changing the API.
5. **Caps.** At most 1000 open streams per node (`EUDIW_EVENT_STREAMS_MAX`) and 100 per client on a node (`EUDIW_EVENT_STREAMS_PER_CLIENT`). Above either, the call returns `429 too_many_streams` with `Retry-After`, before the stream opens; the client polls instead. Streams close on shutdown, and clients reconnect to another node.
6. **Headers.** `Cache-Control: no-store`, like every other management response.
7. **Backend-facing.** Like the rest of the management API, the stream needs a bearer token, so a browser's `EventSource`, which cannot send one, is not the intended client. A browser follows the integrator's own backend, as the example application does with polling.

## Consequences

- A third way to learn the outcome. Polling and webhooks are unchanged, and a client can use any of them.
- Up to one tick of delay (one second by default), and one indexed query per node per tick while any stream is open.
- Long-lived HTTP connections through ingresses and load balancers: idle timeouts must exceed the heartbeat, and response buffering must be off for this path ([Kubernetes notes](../kubernetes.md)).
- The stream reports the session, not the delivery of the result: `verified` with `result_available: true` means the result can be fetched now.
- The gauge `eudiw_session_event_streams` shows open streams per node.
- A client that disconnects is dropped on the next tick, so it does not hold a slot under the caps.
- Removing a client from the configuration ends its streams on the next tick. This path is not covered by an automated test yet.
