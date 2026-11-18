# Standards and feature status

Pinned versions. Changes go through a reviewed ADR and tests. "Supported" means a pinned version and passing automated tests; it is never a conformance or certification statement.

| Standard | Pinned version | Published | Used for |
| --- | --- | --- | --- |
| OpenID for Verifiable Presentations 1.0 | Final | 9 July 2025 | Requests, DCQL, `direct_post.jwt` |
| OpenID4VC High Assurance Interoperability Profile 1.0 | Final | 24 December 2025 | Signed requests via `request_uri`, `x509_hash` client identifier, ECDH-ES P-256 response encryption with `A128GCM` and `A256GCM`, `dc+sd-jwt` and `mso_mdoc` |
| RFC 9901, Selective Disclosure for JWTs | Standards Track | November 2025 | SD-JWT |
| SD-JWT VC | version referenced by HAIP 1.0 | | `dc+sd-jwt` credentials |
| Token Status List | version referenced by HAIP 1.0 | | Revocation and suspension |
| ISO/IEC 18013-5 | First edition | 2021 | mdoc issuer data authentication, mdoc authentication by device signature, DeviceResponse, age attestations, MSO revocation through a Token Status List reference ([ADR-012](adr/0012-mdoc.md)). The second edition is not yet published |
| ETSI TS 119 602 (lists of trusted entities) | V1.1.1 | | PID provider and other EU lists, JSON binding |
| ETSI TS 119 612 (trusted lists) | V2.4.1 | | XML trusted lists and the EU list of trusted lists |
| ETSI TS 119 182-1 (JAdES) | V1.2.1 | | Compact signatures on TS 119 602 lists |
| ETSI TS 119 472-2 (EAA presentation profiles) | V1.3.1 | July 2026 | `verifier_info` with `registrar_dataset` and `registration_cert` |
| ETSI TS 119 475 (relying party attributes) | V1.2.1 | March 2026 | Registration certificate and registrar dataset contents |
| EUDI Wallet Architecture and Reference Framework | v3.0.0 | 21 July 2026 | Ecosystem reference |
| Standard Webhooks | specification at commit `ab6844147ce9` | | Signed session notifications (`v1` HMAC-SHA256) |
| OpenID for Verifiable Credential Issuance 1.0 | Final | 16 September 2025 | Not used yet |

## Feature status

States: `not implemented`, `implemented` (code exists), `tested` (automated tests in this repository), `interop-tested` (tested against an independent wallet or the OIDF suite, with logs kept), `requires external onboarding`.

| Feature | Status |
| --- | --- |
| DCQL query construction and response checks | tested: OpenID4VP 1.0 section 7.3 and Appendix D examples, claim sets, credential sets, `trusted_authorities` (`aki`, `etsi_tl`) |
| SD-JWT VC: issuer signature, disclosures, key binding | interop-tested: RFC 9901 worked examples, rejection cases, differential test against Authlete `sd-jwt` 1.11, eudi-dev wallet v3.8.0 (2026-11-16), OpenID Foundation suite `oid4vp-1final-verifier-haip-test-plan` (suite release v5.3.4), run by CI's `oidf` job on every change: all 14 modules must end with the expected outcome and no failures or warnings in the suite log, and the job keeps the suite logs; not certified ([details](../interop/oidf/README.md), 2026-11-18) |
| ISO mdoc: issuer data authentication | tested: `mso_mdoc` fixtures issued by eudi-dev wallet v3.8.0 (PID and mDL), differential CBOR and COSE checks against Authlete `cbor` 1.21, one rejection case per inspection step (2026-11-17). Brainpool curves with the opt-in `adapter-crypto-brainpool` module: an mDL whose certificates and signatures were made by OpenSSL. `deviceMac` is not supported ([ADR-012](adr/0012-mdoc.md)) |
| ISO mdoc: session transcript, DCQL, request metadata, service | tested: OpenID4VP 1.0 Appendix B.2.6.1 examples (handover info, handover, session transcript, JWK thumbprint), `intent_to_retain`, `age_over_NN` substitution, `vp_formats_supported` for `mso_mdoc` |
| ISO mdoc: device authentication, DeviceResponse | interop-tested: eudi-dev wallet v3.8.0 presents an mdoc PID through the Compose demo and its device signature verifies; the same wallet signing the ISO/IEC 18013-7 transcript is rejected. Both run in CI's `demo` job on every push, so the job logs are the record (2026-11-17). Rejection cases for each transcript input, other doctype or namespaces, another key, attached payload, algorithm and key mismatch, `deviceMac`, missing `deviceSigned`, unauthorized device-signed elements, version and status. `deviceMac` is not supported ([ADR-012](adr/0012-mdoc.md)) |
| `direct_post.jwt` with response encryption | interop-tested: OpenID4VP 1.0 section 8.3 example; eudi-dev wallet v3.8.0 with `--haip --arf --mode strict` (2026-11-16) |
| `x509_hash` client identifier, signed request objects | interop-tested: eudi-dev wallet v3.8.0 with `--haip --arf --mode strict` (2026-11-16): it accepts our access certificate chain under the configured relying-party CA and refuses it under a different CA. Over plain HTTP in tests |
| ETSI TS 119 602 / 119 612 trusted lists, LOTL | tested with synthetic signed lists: JSON with compact JAdES and XML with enveloped signatures, LOTL pointer following, tampering, wrong signer, XXE, partial-coverage signature wrapping, external references, rollback, expiry, six-month limit. Not yet run against a published list |
| Token Status List | JWT form tested: draft 14 section 4 and Appendix C vectors (1, 2, 4 and 8 bits), signed `x5c` status list tokens. CWT form (draft-ietf-oauth-status-list-21 section 5.2) interop-tested: a token served by eudi-dev wallet v3.8.0 after a revocation is a fixture (2026-11-17); wrong type, other `sub`, expired, untrusted and tampered tokens are indeterminate. Used for SD-JWT VC and for the MSO `status` of an mdoc |
| Issuer certificate revocation | CRL tested: revoked end-entity and intermediate, missing, stale, forged and unparsable CRLs, caching (CRLs from BouncyCastle, checked by the JDK). OCSP not implemented ([ADR-007](adr/0007-certificate-revocation.md)) |
| Relying-party registration in `verifier_info` (ETSI TS 119 472-2 `registrar_dataset`, `registration_cert`) | tested with synthetic registration certificates only, no real registrar: request shape, over-asking check, expiry; eudi-dev wallet v3.8.0 with `--haip --arf --mode strict` accepts it, fetching the certificate's status list (2026-11-17) ([ADR-010](adr/0010-relying-party-registration.md)) |
| Relying-party access and registration certificates from a real registrar | requires external onboarding |
| Wallet and key attestation | not implemented |
| DC API | not implemented |
| did:web, did:webvh | not implemented |
| OID4VCI issuance | not implemented |

Update this table in the same PR that changes a status. Interop runs record the wallet, its version and the date.
