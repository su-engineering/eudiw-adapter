# ADR-017: OpenID4VP over the W3C Digital Credentials API

Status: accepted, implemented (server side). Tested with the adapter's own test wallet; a browser test against an independent wallet follows.

## Context

The W3C Digital Credentials API lets a web page ask the browser for a credential: `navigator.credentials.get({digital: {requests: [...]}})`. The browser shows the user's wallets, passes the request and the page's Origin to the chosen wallet, and returns the wallet's response to the page. There is no QR code, no deep link and no `response_uri`. OpenID4VP 1.0 appendix A defines the request and response, and HAIP 1.0 section 5.2 profiles them. The adapter has no browser of its own: the integrator's page calls the API, and the integrator's backend already talks to the adapter.

## Decision

1. **A third session mode, `dc_api`.** Creating a session with `mode: dc_api` and an `origin` returns `dc_api.request`, the exact argument for `navigator.credentials.get()`, instead of `wallet_launch`. The client's backend then posts the `data` of the returned DigitalCredential, unchanged, to `POST /v1/verification-sessions/{id}/dc-api-response` (scope `verification:create`), which answers with the session's status. Results are fetched as in the other modes.
2. **Signed requests only** (`openid4vp-v1-signed`, appendix A.3.2.1). The request carries `client_id` with `x509_hash`, as HAIP requires for signed requests, so the wallet shows the same relying-party identity and registration (`verifier_info`) as in the redirect flows, and `expected_origins` with the session's origin, which the wallet compares with the Origin the browser reports. Only the parameters of appendix A.2 are sent: no `response_uri`, `state`, `request_uri` or `aud`.
3. **Encrypted responses only** (`dc_api.jwt`, HAIP 1.0 section 5.2). Each request has its own ephemeral key, stored like a redirect request instance. A response with an unencrypted `vp_token` rejects the session (`response_not_encrypted`).
4. **Bound to the origin, chosen when the session is created.** The client must list its page origins in `dc_api_origins`; the session's origin must be one of them, compared exactly (scheme, host and port, lower case, as browsers report them), and is part of the idempotency fingerprint. The presentation must name it: the SD-JWT VC Key Binding JWT's `aud` is `origin:<origin>`, signed requests included (appendix A.4), and an mdoc is signed over the `OpenID4VPDCAPIHandover` session transcript (appendix B.2.6.2) with the bare origin, the nonce and the encryption key's thumbprint. The binding is taken from the stored session, never from the endpoint that received the response.
5. **No crossing between flows.** A `dc_api` session has no request URI (fetching by handle returns 404), the wallet response endpoint refuses its responses, and the relay endpoint refuses sessions of other modes and responses made for another session.
6. **Wallet errors** (`data.error`) end the session like redirect errors: `access_denied` is `denied`, anything else `rejected` with `wallet_error`.
7. **`transaction_data`** works as in the other modes ([ADR-016](0016-transaction-data.md)); appendix A.2 lists it.

## Consequences

- The integrator's page needs one call and one relay: `const c = await navigator.credentials.get(session.dc_api.request)`, then post `c.data` to its backend, which posts it to `response_url`. The adapter never sees the browser.
- The Origin check of `expected_origins` is the wallet's job (appendix A.2); the adapter's own check is that the presentation names the session's origin. A page on another origin cannot get a presentation the adapter accepts for this session.
- A retry of the creation with the same `Idempotency-Key` returns a fresh request for the same session, counted against the session's request limit.
- Tested so far with the spec's B.2.6.2 transcript example and the adapter's test wallet: SD-JWT VC and mdoc bound to the origin verify; a presentation for the Client Identifier, an mdoc signed over the redirect transcript, unencrypted responses, crossings between flows, wallet errors and unregistered origins are refused. Not yet tested against an independent wallet; the OIDF conformance suite (release v5.3.4) has no verifier test for the DC API.
- During a rolling upgrade, pods without this version do not know mode `dc_api`; replace all pods before clients use it. Migration `V7` widens the mode check and adds the origin column.
