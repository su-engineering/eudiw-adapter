# Threat model

Keep this in step with the code: a PR that changes a trust boundary or a control updates this file. The status column says what exists in this repository today.

## Assets

- Verified claims of a holder, before and after minimization.
- Request-signing and response-decryption keys, per tenant.
- Tenant trust profiles and verification policies.
- Session state: request handles, state, nonce, completion status.
- Management API credentials and webhook signing keys.

## Actors

- Honest holder with a wallet.
- Attacker controlling a wallet or replaying captured responses.
- Attacker controlling a malicious issuer, trust list host or status list host.
- Malicious or compromised tenant client trying to reach another tenant's data.
- Phishing relay that shows a victim the verifier's QR code.
- Network attacker (TLS assumed; DNS rebinding not excluded).

## Threats and controls

Status: `planned`, `implemented` (code and a regression test exist), `partial`.

| Threat | Control | Status | Regression test |
| --- | --- | --- | --- |
| Credential from an issuer outside the trust profile | Issuer chain to the policy's own anchors or to a service approved in a signed trusted list, `iss` bound to the certificate, optional issuer allow list | implemented (V-04 cross-tenant issuer test, trusted list flow test, demo rejection step) | Signature-valid credential from unlisted issuer rejected |
| Forged, replayed or stale trusted list | Pinned list signers (from configuration or the LOTL pointer), strict XML signature profile (one enveloped signature covering the root, same-document references only, secure validation, no DTDs), JAdES without detached payloads, pin checked before any signature computation, next update enforced, sequence number may not decrease (kept in PostgreSQL across restarts and nodes), last good list dropped at its next update, national lists dropped when the LOTL stops vouching for them (expires, drops the pointer, changes it to a form the source does not follow, or rotates the signer) | implemented ([ADR-006](adr/0006-trusted-lists.md)) | Tampered, wrongly signed, wrapped, rolled back (also after restart) and expired lists rejected; XXE refused; expired or changed LOTL evicts its lists, also before the next refresh; 3,000 mutated lists fail with coded errors only |
| Credential signed under a revoked issuer certificate | Opt-in per policy: every issuer chain certificate checked against a current CRL signed by its issuer; missing or stale CRL rejects; CRLs fetched only after the chain validates | implemented for CRLs ([ADR-007](adr/0007-certificate-revocation.md)); OCSP not implemented; status list token chains not yet checked | Revoked leaf and intermediate rejected; stale, forged and unreachable CRLs reject |
| Status list key used to sign credentials | Revocation service types anchor status list tokens only, never credentials | implemented | Revocation-service certificate absent from issuance anchors |
| SD-JWT replay or key-binding substitution | nonce per request instance, `aud` = client identifier, `sd_hash`, `iat` window, single-use request instance | implemented | Replay into a new session, the same session, another tenant |
| Modified or injected disclosure | Digest of every disclosure must appear exactly once in the signed payload | implemented | Changed, duplicated and unreferenced disclosures rejected |
| Forged or altered mdoc | Issuer signature over the MSO with the algorithm pinned to the signer key, value digest over each element as received, docType match, MSO validity, IACA country and usage rules for the mDL | implemented | Changed element, unknown digest id, repeated item, other docType, changed signature, untrusted issuer, expired and not-yet-valid MSO, signer outside validity, country and state mismatch, 3000 byte mutations that never verify with changed content |
| mdoc device authentication bypass | Session transcript, MSO validity and value digests, issuer and device signatures; device MAC rejected | implemented | Each transcript input changed, other doctype or namespaces, another device key, unauthorized device-signed elements and an ISO/IEC 18013-7 transcript from an independent wallet are rejected |
| Response delivered to the wrong session | Per-request state and decryption key, single-use completion | implemented (V-07) | Two concurrent responses, one accepted |
| Cross-tenant read, cancel or completion | Tenant from authenticated principal on every query, never from the path | implemented (V-04) | Tenant B token on tenant A session ID returns 404 |
| Caller requests more claims than approved | Server-held policy builds DCQL; callers cannot supply DCQL; only requested claims leave the evaluator | implemented: policies are configuration, result claims must be requested by the policy's DCQL | Request with extra claim rejected; result has only allowed claims |
| QR relay phishing and session fixation | Same-device mode returns `redirect_uri` with a one-time `response_code` that result retrieval requires (OpenID4VP 1.0 section 14.2); cross-device mode cannot detect relay | partial: same-device implemented; cross-device documented as not phishing resistant | Documented, not test-provable |
| SSRF via list or status URLs | Egress policy, no redirects, size and time limits | partial: implemented in `EgressPolicy` and `JdkHttpFetcher`, including IPv6 transition addresses (NAT64, 6to4, Teredo), with an optional host allow list (`EUDIW_EGRESS_ALLOWED_HOSTS`); DNS rebinding between check and connect remains in the application and is closed by the chart's egress policy (`networkPolicy.egress.enabled`) or another network-layer control | Loopback, cloud metadata and IPv6 transition addresses rejected; connect to the checked address only |
| Slow list, status or CRL server holds verification threads | One deadline over DNS lookup, connection, headers and body; body read stops at the size limit | implemented | A server that drips the body is cut off at the timeout |
| JWT algorithm or key confusion | Algorithm allowlist, algorithm derived from the trusted key, `kid` scoped to its source | implemented for JWS | `alg=none`, HMAC with a public key, wrong curve, header and key mismatch rejected |
| Forged or stale status list | Signature, issuer authority, TTL, bounded decompression; a cached list is used only while its anchor is still trusted and its chain is valid | implemented for JWT and CWT status lists | Modified, expired and oversized lists rejected; cached list dropped when a trusted list update removes its anchor |
| Trust decision leaks across tenants via cache | Per-policy trust anchors and status caches; cache key includes tenant, policy and configuration revision | implemented | Issuer trusted for tenant A not trusted for tenant B |
| Claims leak through notifications, or a forged notification is accepted | Webhook body holds the session id, status, policy, reason and the caller's reference only; HMAC-SHA256 signature over id, timestamp and body with a per-client secret; production requires HTTPS; redirects not followed | implemented ([ADR-008](adr/0008-webhooks.md)) | Webhook body checked for the canary claim; signature recomputed independently in the test |
| Late or duplicate wallet response revives a session | Monotonic state, conditional update | implemented | Response after cancel or expiry rejected |
| Sensitive data in logs, metrics and traces | No request body or token logging; result and request keys encrypted at rest per tenant; metric tags limited to configuration ids and reason codes; HTTP metrics off; span paths and queries scrubbed; metrics only on the management port | implemented: tests assert a canary claim, the bearer token and the nonce never reach the service log or database, metrics carry no session id, handle, nonce, token or claim, spans carry no request handle or `response_code`, and nothing operational is served on the public port | Canary claim value never appears in logs; metrics and span canaries |
| Configuration reload serves a session under other rules, or a bad file takes the service down | Sessions are bound to their configuration revision; the replaced configuration is kept for the longest session lifetime; an invalid file is refused and the running configuration stays | implemented | Session opened before a reload verifies under its own revision; invalid file ignored |
| Unauthenticated request fetches exhaust keys or storage | At most 5 request instances per session; request URIs are unguessable and expire with the session | implemented |
| Someone who sees the QR code ends the session | Anyone holding the request URI can fetch the request and post `access_denied`, or use up the five fetches, ending that session as `denied` or unservable. Denial of service only: no claims are released and the caller can start a new session. Prefer same-device flows and short TTLs | accepted, documented |
| Large or nested payloads exhaust CPU | Body limits, JSON and CBOR depth limits (CBOR also: 1 MB, 100000 items, definite lengths only, a 512 KB DeviceResponse), per-client rate limit on session creation | partial: size, depth and decompression limits in core, mutation tests over 5,000 malformed SD-JWT inputs; session creation limited per client across replicas (PostgreSQL window); wallet endpoints are not rate limited by the service, limit them per source address at the ingress | Oversized and deeply nested input rejected fast; third creation in a window of two returns 429 |
| Key theft | Keys outside images and the repository; per-request keys encrypted at rest; KMS or PKCS#11 signer | implemented: request-signing keys can stay in an HSM or KMS through PKCS#11 ([ADR-009](adr/0009-hsm-request-signing.md)); file keys are read from mounted files, never baked into images |

## Out of scope

Wallet compromise, issuer key compromise, and the legal validity of relying-party registration. The adapter checks what it is configured to check and reports it.
