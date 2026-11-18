# Changelog

All notable changes to eudiw-adapter. Versions follow [Semantic Versioning](https://semver.org/); before 1.0.0, a minor version can change the API or the configuration format, and the notes say how.

## [Unreleased]

### Added

- CI runs the OpenID Foundation OID4VP 1.0 Final + HAIP verifier test plan on every change (`oidf` job). The job fails when any of the 14 modules ends differently from `interop/oidf/expected.json` or the suite logs a failure or warning, and keeps the suite logs for 90 days. `interop/oidf/ci.sh` runs the same thing on a laptop. Every module still ends in REVIEW; this is not certification.

## [0.2.1] - 2026-11-17

Security fixes from a security assessment, and hardening. The defaults keep existing installations working. Stricter trust checks are opt-in policy settings. Some invalid input that 0.2.0 accepted is now refused; see **Upgrading** before rolling out.

### Upgrading

- **Rolling upgrades from 0.2.0.** While 0.2.0 and 0.2.1 pods run side by side, sessions can fail across versions, until they expire (at most the session lifetime, 15 minutes by default):
  - The configuration revision is now a full SHA-256 over the tenants file and every file it references, so the two versions compute different revisions for the same files. A session opened on one version gets 404 on the other.
  - 0.2.1 writes encrypted data with a key id that 0.2.0 cannot read. A wallet that reaches a 0.2.0 pod for a session opened on 0.2.1 gets an error.

  Upgrade outside busy hours, or replace all pods at once (for example with the `Recreate` strategy), or accept that a few sessions in flight fail.
- **Rolling back to 0.2.0.** Results and request keys written by 0.2.1 cannot be decrypted by 0.2.0, so open sessions and unretrieved results are lost. The `V5` migration stays applied; 0.2.0 does not use its columns.
- **Booleans must be JSON booleans.** `enforce_trusted_authorities` and `follow_pointers` given as strings or numbers now fail startup. Before, `"enforce_trusted_authorities": "true"` silently turned the check off.
- **Client ids are checked.** A `client_id` with a quote, space, backslash or control character, or longer than 255 characters, fails startup.
- **Unknown request fields are refused.** A management API request body with a property the OpenAPI schema does not define gets `400 invalid_request`.
- **Database migration.** Flyway adds the content digest columns to `trusted_list_sequence` (`V5`). It runs on startup.

### Security

- Trusted list, status list and CRL fetches run under one deadline that covers DNS lookup, connection, headers and the body. A server that sends the body slowly is cut off at the timeout instead of holding a verification thread.
- The egress policy accepts only global unicast IPv6. 6to4, Teredo, documentation and benchmarking addresses are refused. A NAT64 address in `64:ff9b::/96` is judged by the IPv4 address it embeds, so IPv6-only clusters with DNS64 still reach public IPv4 hosts.
- A cached status list is used only while the anchor that signed it is still trusted and its certificate chain is still valid.
- A national trusted list stops counting as soon as the list of lists that points to it expires, or stops pointing to it in a way the source follows.
- Concurrent status checks for the same list share one fetch, and a list that cannot be fetched or verified is not fetched again for 30 seconds. Concurrent CRL checks for the same distribution point also share one fetch.
- `enforce_trusted_authorities` and `follow_pointers` accept only JSON booleans.
- Token claims are compared exactly as issued. `azp` and `scope` were compared with quote characters removed.
- A session records the configuration revision the caller was authorized against, not the one current when it was written.
- The per-session cap of five request fetches holds under concurrent fetches.
- The trusted list sequence check is one atomic database statement, so two nodes cannot accept different lists under competing numbers.
- A trusted list that reuses its sequence number with different content is refused. A list that is only re-signed or re-dated still loads. The stored digest counts only for the number it was recorded with, so a number raised by a 0.2.0 node or before a rollback never locks a list out.
- XML trusted lists accept only RSA, RSA-PSS and ECDSA signatures over SHA-256, SHA-384 or SHA-512, and only those digests.
- A JAdES `sigT` on a JSON list must be a valid UTC time, not in the future by the trusted list clock, and inside the signer certificate's validity.
- An encrypted wallet response with a JWE `crit` header is refused.
- A wallet response to a finished or expired session, or for a request instance already used, is refused before it is decrypted or verified. Only the first refusal per request instance writes an audit row; repeats are counted in `eudiw.wallet.response.ignored`. A request key that cannot be decrypted gets 400, not 500.
- Audit lines replace line breaks and other control characters in every value.
- Contradicting mdoc age attestations (for example `age_over_18: false` with `age_over_21: true`) no longer answer an `age_over_NN` request.
- Jackson 2.22.4 and Guava 33.7.2 replace the versions with known denial of service advisories. The base image moves to Temurin 21.0.13.
- GHSA-ccrj-gw8r-854m (opentelemetry-api 1.62.0, which Quarkus 3.39 manages): a crafted `tracestate` header costs quadratic CPU. The W3C propagator stays configured with tracing off, so it was treated as reachable by default. With tracing off, the public HTTP server no longer passes trace headers to the tracer; the management port, which must stay private, is not covered. With tracing on, a `tracestate` over 512 characters is dropped before it is parsed. The fixed 1.67.0 cannot be forced under Quarkus 3.39, so it comes with the first Quarkus release that ships it.

### Added

- Policy settings, all off by default:
  - `require_status` refuses a credential without a status reference the adapter can check (`credential_status_missing`).
  - `status_signer: credential_issuer` requires the status list to be signed under the credential issuer's trust anchor.
  - `issuer_extended_key_usages` requires an SD-JWT VC issuer certificate to carry one of the listed extended key usages.
- An optional egress `NetworkPolicy` in the Helm chart (`networkPolicy.egress.enabled`). It allows DNS, listed cluster destinations and public addresses only, which also closes DNS rebinding between the egress check and the connection.
- `EUDIW_EGRESS_ALLOWED_HOSTS` limits list, status list and CRL fetches to named hosts. `EUDIW_EGRESS_PROXY` sends them through a forward proxy. The chart has `egress.allowedHosts` and `egress.proxy`.
- Data key rotation: ciphertext names its key, and `EUDIW_PREVIOUS_DATA_KEYS` holds keys that only decrypt. Data written by 0.2.0 still decrypts. The chart reads an optional `previous-data-keys` entry from the data key secret.
- `EUDIW_WALLET_REQUESTS_PER_MINUTE` (chart: `walletRateLimit.requestsPerMinute`) limits the wallet endpoints per source address across nodes. It is off by default because behind an ingress it needs proxy address forwarding, and only behind a proxy that replaces `X-Forwarded-For`. A source that is not an IP address counts against one shared bucket.
- `EUDIW_MANAGEMENT_HOST` sets the management port's bind address.
- A trusted list refresh follows at most 64 pointers and stops fetching after five minutes. Skipped lists keep their last verified version.
- CI: a dependency vulnerability gate (OSV over the runtime SBOM), CodeQL, and dependency review on pull requests. Dependabot also proposes weekly version updates.

### Changed

- Result retrieval decrypts the result and writes its audit row in the transaction that consumes it. A failed audit write leaves the result retrievable.
- Configuration reload watches exactly the files the configuration was read from, by content, including a referenced file that was missing at a failed load. Before, it walked the directory to depth 4 and at most 2000 files, and a rotated key or webhook secret alone did not reload.
- The base image is pinned by digest.
- The Node and Python example webhook receivers acknowledge a repeated `webhook-id` without processing it again.

### Documentation

- `trusted_authorities` with `aki` matches any certificate in the presented chain, as OpenID4VP 1.0 section 6.1.1.1 says.
- The adapter does not verify the registration certificate's signature; the wallet does.
- How to keep the management port private outside Kubernetes.

## [0.2.0] - 2026-11-17

ISO mdoc support. No breaking changes: existing configuration, the management API and SD-JWT VC behaviour are unchanged. New policy settings and audit events are additions.

### Added

- ISO mdoc (`mso_mdoc`) presentations over OpenID4VP 1.0 and HAIP 1.0 ([ADR-012](docs/adr/0012-mdoc.md), [configuration](docs/configuration.md#mdoc)):
  - issuer data authentication: the mobile security object, value digests, validity, and the IACA certificate rules for the mDL (country and state, extended and key usage, `issuing_country` and `issuing_jurisdiction`);
  - mdoc authentication by device signature over the OpenID4VP session transcript, with key authorizations for device-signed elements;
  - the DeviceResponse version and status rules;
  - DCQL `[namespace, element]` paths with `intent_to_retain`, and the `age_over_NN` rule (an `age_over_21: true` answers a request for `age_over_18`);
  - `mso_mdoc` in the request's `vp_formats_supported`;
  - revocation: the MSO's Token Status List reference is checked like an SD-JWT VC's status;
  - `allowed_issuers` names an mdoc issuer by its trust anchor's subject name or its trusted-list entity name, never by the document signer's name, which changes on rotation.
- Conformance warnings: departures from ISO/IEC 18013-5 that the adapter tolerates are accepted and written to the audit trail as `conformance_warning` events. These are a P-384 device key, a document signer valid for more than 457 days or without a CRL distribution point, and a root certificate in the x5chain, which is ignored and never trusted. The policy setting `mdoc_strict_conformance` refuses P-384 device keys.
- Token Status List in CWT form (draft-ietf-oauth-status-list-21), next to the JWT form. A token served by the eudi-dev wallet is a test fixture.
- `adapter-crypto-brainpool`, an opt-in module for mdoc signatures on brainpool curves, with BouncyCastle. The service image carries it, off unless `EUDIW_CRYPTO_BRAINPOOL=true`.
- A strict CBOR decoder and COSE_Sign1 verification in `adapter-core`, cross-checked in tests against Authlete `cbor`.
- The Compose demo has the eudi-dev wallet present an mdoc PID end to end, and checks that one signed over another session transcript is rejected. CI runs both.

### Not supported yet

- Device MAC, which needs a reader key that the OpenID4VP flow does not have.
- MSO status mechanisms other than a Token Status List reference. Under `require_valid` they are rejected.

## [0.1.1] - 2026-11-17

### Changed

- The README banner is in the su.engineering design and is generated by `tools/banner`.
- Releases stage the npm package through trusted publishing (OIDC) with provenance; a maintainer approves it with 2FA ([releasing](docs/releasing.md)).

### Fixed

- The release workflow attaches only the chart and the SBOM to the GitHub release; for 0.1.0 it also picked up CI's test reports and stopped before creating the release.

## [0.1.0] - 2026-11-17

The first release.

### Verification

- SD-JWT VC (RFC 9901) presentations over OpenID4VP 1.0 as profiled by HAIP 1.0: signed request objects by `request_uri`, the `x509_hash` client identifier, `direct_post.jwt` responses encrypted to a fresh key per request, and DCQL with claim sets, credential sets and `trusted_authorities`.
- Issuer signature, disclosure digests, key binding to the nonce and client identifier, X.509 chains, CRLs, and Token Status Lists (revocation and suspension). Anything unknown or late is rejected with a coarse reason code.
- Issuer trust from signed ETSI TS 119 602 and TS 119 612 trusted lists, including the EU list of trusted lists, with pinned signers, freshness checks and rollback protection.
- Relying-party registration: the registrar dataset and registration certificate are sent in `verifier_info` (ETSI TS 119 472-2), and a query that asks for more than was registered is refused at startup.

### Service

- Management API (OpenAPI 3.1) for sessions, with OAuth client credentials from your own authorization server, tenant scoping and idempotency keys.
- Per-policy claim minimization. Results are encrypted at rest, retrievable once and expire; the raw presentation is never stored.
- Standard Webhooks notifications, queued with the session's final state and retried with backoff. They carry no claims.
- Request-signing keys in an HSM or KMS through PKCS#11.
- Prometheus metrics, an audit trail, optional OpenTelemetry traces, per-client rate limits shared across replicas, and configuration reload without a restart.
- PostgreSQL is the only state. Any number of replicas.

### Deployment

- Multi-arch image (linux/amd64, linux/arm64) on GitHub Container Registry, signed with cosign, with an SBOM and build provenance.
- Helm chart that runs under the restricted Pod Security Standard, published as a signed OCI chart.
- Docker Compose demo with SoftHSM, Keycloak and the independent eudi-dev test wallet.

### Frontend

- `@su-engineering/eudiw-request`: a dependency-free web component that shows the wallet request as a QR code and wallet link, counts down to expiry and follows the session. Themeable with CSS custom properties.
- Node and Python example backends with webhook verification, tested end to end in CI.

### Not in this release

ISO mdoc, the Digital Credentials API, OCSP, wallet attestation and `transaction_data`. Interoperability is tested against the eudi-dev wallet and the OpenID Foundation HAIP verifier test plan run locally; there is no certification and no external security review yet. See the [roadmap](ROADMAP.md).

[Unreleased]: https://github.com/su-engineering/eudiw-adapter/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/su-engineering/eudiw-adapter/releases/tag/v0.2.1
[0.2.0]: https://github.com/su-engineering/eudiw-adapter/releases/tag/v0.2.0
[0.1.1]: https://github.com/su-engineering/eudiw-adapter/releases/tag/v0.1.1
[0.1.0]: https://github.com/su-engineering/eudiw-adapter/releases/tag/v0.1.0
