# Standards and feature status

Pinned versions. Changes go through a reviewed ADR and tests. "Supported" means a pinned version and passing automated tests; it is never a conformance or certification statement.

| Standard | Pinned version | Published | Used for |
| --- | --- | --- | --- |
| OpenID for Verifiable Presentations 1.0 | Final | 9 July 2025 | Requests, DCQL, `direct_post.jwt` |
| OpenID4VC High Assurance Interoperability Profile 1.0 | Final | 24 December 2025 | Signed requests via `request_uri`, `x509_hash` client identifier, ECDH-ES P-256 response encryption with `A128GCM` and `A256GCM`, `dc+sd-jwt` and `mso_mdoc` |
| RFC 9901, Selective Disclosure for JWTs | Standards Track | November 2025 | SD-JWT |
| SD-JWT VC | version referenced by HAIP 1.0 | | `dc+sd-jwt` credentials |
| Token Status List | version referenced by HAIP 1.0 | | Revocation and suspension |
| ISO/IEC 18013-5 | | | mdoc issuer and device authentication |
| ETSI TS 119 602 (lists of trusted entities) | V1.1.1 | | PID provider and other EU lists, JSON binding |
| ETSI TS 119 612 (trusted lists) | V2.4.1 | | XML trusted lists and the EU list of trusted lists |
| ETSI TS 119 182-1 (JAdES) | V1.2.1 | | Compact signatures on TS 119 602 lists |
| EUDI Wallet Architecture and Reference Framework | v3.0.0 | 21 July 2026 | Ecosystem reference |
| Standard Webhooks | as published at standardwebhooks.com | | Signed session notifications (`v1` HMAC-SHA256) |
| OpenID for Verifiable Credential Issuance 1.0 | Final | 16 September 2025 | Not used yet |

## Feature status

States: `not implemented`, `implemented` (code exists), `tested` (automated tests in this repository), `interop-tested` (tested against an independent wallet or the OIDF suite, with logs kept), `requires external onboarding`.

| Feature | Status |
| --- | --- |
| DCQL query construction and response checks | tested: OpenID4VP 1.0 section 7.3 and Appendix D examples, claim sets, credential sets, `trusted_authorities` (`aki`, `etsi_tl`) |
| SD-JWT VC: issuer signature, disclosures, key binding | interop-tested: RFC 9901 worked examples, rejection cases, differential test against Authlete `sd-jwt` 1.11, eudi-dev wallet v3.8.0 (2026-11-16) |
| ISO mdoc: issuer and device authentication | not implemented |
| `direct_post.jwt` with response encryption | interop-tested: OpenID4VP 1.0 section 8.3 example; eudi-dev wallet v3.8.0 with `--haip --arf --mode strict` (2026-11-16) |
| `x509_hash` client identifier, signed request objects | interop-tested: eudi-dev wallet v3.8.0 with `--haip --arf --mode strict` (2026-11-16): it accepts our access certificate chain under the configured relying-party CA and refuses it under a different CA. Over plain HTTP in tests |
| ETSI TS 119 602 / 119 612 trusted lists, LOTL | tested with synthetic signed lists: JSON with compact JAdES and XML with enveloped signatures, LOTL pointer following, tampering, wrong signer, XXE, partial-coverage signature wrapping, external references, rollback, expiry, six-month limit. Not yet run against a published list |
| Token Status List | JWT form tested: draft 14 section 4 and Appendix C vectors (1, 2, 4 and 8 bits), signed `x5c` status list tokens; CWT form not implemented |
| Issuer certificate revocation | CRL tested: revoked end-entity and intermediate, missing, stale, forged and unparsable CRLs, caching (CRLs from BouncyCastle, checked by the JDK). OCSP not implemented ([ADR-007](adr/0007-certificate-revocation.md)) |
| Relying-party access and registration certificates | requires external onboarding |
| Wallet and key attestation | not implemented |
| DC API | not implemented |
| did:web, did:webvh | not implemented |
| OID4VCI issuance | not implemented |

Update this table in the same PR that changes a status. Interop runs record the wallet, its version and the date.
