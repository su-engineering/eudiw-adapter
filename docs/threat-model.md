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
| Credential from an issuer outside the trust profile | Issuer chain to the policy's own anchors, `iss` bound to the certificate, optional issuer allow list | implemented (V-04 cross-tenant issuer test, demo rejection step); ETSI trusted lists planned | Signature-valid credential from unlisted issuer rejected |
| SD-JWT replay or key-binding substitution | nonce per request instance, `aud` = client identifier, `sd_hash`, `iat` window, single-use request instance | implemented | Replay into a new session, the same session, another tenant |
| Modified or injected disclosure | Digest of every disclosure must appear exactly once in the signed payload | implemented | Changed, duplicated and unreferenced disclosures rejected |
| mdoc device authentication bypass | Session transcript, MSO validity and value digests, issuer and device signatures; device MAC rejected | planned | Swapped transcript and swapped device key rejected |
| Response delivered to the wrong session | Per-request state and decryption key, single-use completion | implemented (V-07) | Two concurrent responses, one accepted |
| Cross-tenant read, cancel or completion | Tenant from authenticated principal on every query, never from the path | implemented (V-04) | Tenant B token on tenant A session ID returns 404 |
| Caller requests more claims than approved | Server-held policy builds DCQL; callers cannot supply DCQL; only requested claims leave the evaluator | implemented: policies are configuration, result claims must be requested by the policy's DCQL | Request with extra claim rejected; result has only allowed claims |
| QR relay phishing and session fixation | Same-device mode returns `redirect_uri` with a one-time `response_code` that result retrieval requires (OpenID4VP 1.0 section 14.2); cross-device mode cannot detect relay | partial: same-device implemented; cross-device documented as not phishing resistant | Documented, not test-provable |
| SSRF via list or status URLs | Egress policy, no redirects, size and time limits | partial: implemented in `EgressPolicy` and `JdkHttpFetcher`; DNS rebinding between check and connect remains, restrict egress at the network layer | Loopback and cloud metadata addresses rejected; connect to the checked address only |
| JWT algorithm or key confusion | Algorithm allowlist, algorithm derived from the trusted key, `kid` scoped to its source | implemented for JWS | `alg=none`, HMAC with a public key, wrong curve, header and key mismatch rejected |
| Forged or stale status list | Signature, issuer authority, TTL, bounded decompression | implemented for JWT status lists | Modified, expired and oversized lists rejected |
| Trust decision leaks across tenants via cache | Per-policy trust anchors and status caches; cache key includes tenant, policy and configuration revision | implemented | Issuer trusted for tenant A not trusted for tenant B |
| Late or duplicate wallet response revives a session | Monotonic state, conditional update | implemented | Response after cancel or expiry rejected |
| Sensitive data in logs and traces | No request body or token logging; result and request keys encrypted at rest per tenant | partial: test asserts a canary claim, the bearer token and the nonce never reach the service log or database | Canary claim value never appears in logs |
| Unauthenticated request fetches exhaust keys or storage | At most 5 request instances per session; request URIs are unguessable and expire with the session | implemented |
| Large or nested payloads exhaust CPU | Body limits, JSON and CBOR depth limits, per-tenant rate limits | partial: size, depth and decompression limits in core, mutation tests over 5,000 malformed SD-JWT inputs; rate limits planned | Oversized and deeply nested input rejected fast |
| Key theft | Keys outside images and the repository; per-request keys encrypted at rest; KMS or PKCS#11 signer | partial: keys are read from mounted files, never baked into images; KMS signer planned |

## Out of scope

Wallet compromise, issuer key compromise, and the legal validity of relying-party registration. The adapter checks what it is configured to check and reports it.
