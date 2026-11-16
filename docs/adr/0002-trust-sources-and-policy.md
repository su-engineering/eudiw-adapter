# ADR-002: Trust sources and trust policy

Status: accepted. Implemented for the first release: per-policy trust anchors (decision 1, as configured certificates), explicit status results (2), scoped caches (3), anchored issuer keys (5), production refusals (6). Trusted list ingestion (4) and DID methods (7) come later.

## Context

Issuer trust can come from ETSI TS 119 602 lists (JSON or JWT), ETSI TS 119 612 XML trusted lists and the EU list of trusted lists, VICAL for mdoc, and certificate chains carried in credentials. Revocation can use Token Status Lists (JWT and CWT) and OCSP or CRL. The service is multi-tenant: a trust decision made for one tenant's profile must never satisfy another tenant's check.

## Decision

1. **Trust profile is a named, versioned, immutable object** owned by a tenant: allowed sources (URLs plus pinned signer certificates), allowed issuers per credential type, status requirements, and the treatment of `INDETERMINATE`. A verification session records the profile revision it started with.
2. **Every trust and status result is explicit**: `VALID`, `INVALID` or `INDETERMINATE`. Profiles marked high assurance reject `INDETERMINATE`, including an unreachable status endpoint.
3. **Cache keys** contain tenant, trust profile revision and source URI. No global cache of decisions.
4. **Trust lists must be signed** by a configured signer. Accepting unsigned lists is a sandbox-only option.
5. **Issuer keys found through credential-supplied URLs** (for example `/.well-known/jwt-vc-issuer`) are accepted only when anchored by the profile: an allowed issuer list or a certificate that validates against a configured list.
6. **Sandbox and production profiles are separate namespaces.** A production tenant cannot reference a profile with unsigned lists, private-network fetch or DID trust without an explicit, audited override.
7. **DID methods** (did:web, did:webvh) are a later, opt-in extension and never a route to EUDI-authorized issuer status.

## Open

- Enforcing DCQL `trusted_authorities` on responses: planned, on by default for new tenants.
- Refresh and rollback rules for lists (sequence number or issue date must not go backwards).
