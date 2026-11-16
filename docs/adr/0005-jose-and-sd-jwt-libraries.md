# ADR-005: JOSE and SD-JWT libraries

Status: accepted (2026-11-16).

## JOSE: Nimbus JOSE+JWT

Requirements: JWS verification for ES256/384/512 and PS256/384/512, JWK parsing including `x5c`, JWE decryption with ECDH-ES on P-256 and `A128GCM`/`A256GCM` (HAIP 1.0 section 5), an explicit way to fix the algorithm instead of trusting the header, bounded JSON parsing, active maintenance.

Nimbus JOSE+JWT (Apache-2.0, Connect2id) meets these. It is widely deployed, releases regularly (last release September 2026) and fixes reported issues quickly; the most recent advisory, CVE-2025-53864 (unbounded recursion on deeply nested JSON claims), was fixed in 10.0.2. We pin 10.10 and track advisories through Dependabot security updates.

How we use it:
- Verifiers are built by our code from a trusted key and an algorithm chosen from the allowlist by key type and curve. The token header `alg` must equal that algorithm; it never selects the verifier on its own.
- No symmetric (`HS*`) or `none` algorithms are accepted for credentials, presentations or status lists.

## SD-JWT: implemented in core

RFC 9901 verification is a small, well-specified algorithm (sections 4, 7.1 and 7.3): split the presentation, verify the issuer JWT, hash and match disclosures, reject duplicates and unreferenced disclosures, verify the key binding JWT. Implementing it in core on top of Nimbus keeps every rejection rule visible and testable in one place and adds no dependency.

Independent check: Authlete's `com.authlete:sd-jwt` (Apache-2.0, maintained by a co-author of RFC 9901) is used **in test scope only** to issue and present SD-JWTs, so our verifier is tested against output it did not produce. The RFC 9901 worked examples (section 5 and Appendix A, with the key in Appendix A.5) are used as fixed vectors.

## Pinned profiles

HAIP 1.0 references SD-JWT VC draft-ietf-oauth-sd-jwt-vc-13 and Token Status List draft-ietf-oauth-status-list-14. Those are the versions implemented.
