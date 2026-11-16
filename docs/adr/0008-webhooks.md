# ADR-008: Webhooks

Status: accepted, implemented.

## Context

Clients either poll a session or are told when it ends. A notification must not become a second channel for claims, must not be lost or doubled when a node fails, and must be verifiable by the receiver. [Standard Webhooks](https://www.standardwebhooks.com) is a published convention for exactly this, with libraries in many languages. This implementation follows the specification at commit `ab6844147ce9` of `standard-webhooks/standard-webhooks`.

## Decision

1. **Thin payload.** The body names the session, its final status, the policy, the coarse reason and the caller's `client_reference`. Claims are fetched with the result call, which keeps the one-time retrieval and the same-device `response_code` binding.
2. **Outbox in the same statement.** The conditional update that ends a session (completion, or expiry in the sweep) also inserts the delivery row, in one SQL statement. A session cannot end without its notification being queued, and losing the completion race queues nothing. Cancellation is not notified: the client cancelled the session itself.
3. **One sender per delivery.** Each due row is claimed alone, just before it is sent, with `FOR UPDATE SKIP LOCKED` and a 60 second lease that covers the single request (connect and request timeouts add up to 25 seconds). Other nodes take the remaining rows meanwhile, so one slow receiver does not hold back other clients' deliveries on every node. A node that dies mid-delivery releases its rows when the lease ends. Receivers can still see a delivery twice (for example, a response lost after it was processed), so the `webhook-id` stays the same across retries and the receiver should process each id once.
4. **Standard Webhooks signatures.** HMAC-SHA256 over `id.timestamp.body` with a `whsec_` secret of 24 to 64 bytes, sent as `v1,<base64>`. An optional previous secret is signed with too, for rotation without downtime.
5. **Delivery rules.**
   - Any 2xx response is success.
   - `410 Gone` stops delivery.
   - Anything else is retried after 5 s, 5 min, 30 min, 2 h, 5 h and 10 h, with jitter, and then marked failed.
   - Requests time out after 15 s, and redirects are not followed.
   - Each final outcome is written to the audit log.
6. **Destination.**
   - The URL is operator configuration, not request input.
   - Production requires HTTPS.
   - Private addresses are allowed, because webhook receivers are usually internal services. The egress policy for list, status and CRL fetches does not apply here.
7. **Retention.** Delivered and failed rows are deleted after seven days.

## Consequences

- A receiver that misses all retries must fall back to polling. Sessions and results expire on their own schedule regardless of webhooks.
- Asymmetric signatures (`v1a`, ed25519) are not offered yet.
