# Delivery plan

Each step is a separate commit or PR with tests and docs, and `main` builds and passes at every step. Tick items as they land.

## First public release: scope

- `adapter-core` verifies SD-JWT VC presentations, evaluates DCQL, checks issuer certificate chains against configured anchors and checks Token Status Lists.
- `adapter-verifier-service` exposes the management API and the wallet-facing OID4VP endpoints with PostgreSQL state.
- A Docker Compose demo runs end to end on synthetic data.
- README and [feature matrix](standards-matrix.md) match the code.

Not in the first release: ISO mdoc, ETSI trusted list ingestion, credential issuance, multi-node hardening, DC API, DID trust, webhooks, admin UI.

## How each area is built and tested

1. Read the governing sections of the specification.
2. Write fixtures: valid cases plus one targeted mutation per security check, each with an expected outcome and error code.
3. Anchor on material written by someone else: worked examples in the specification text, published test vectors, and output from an independent implementation where available. Self-generated fixtures alone are not enough.
4. Implement until all fixtures pass.

## Core (`adapter-core`)

- [x] Repository skeleton: reactor, Nimbus JOSE+JWT, Enforcer rule, formatting check, CI
- [x] [ADR-005](adr/0005-jose-and-sd-jwt-libraries.md): JOSE and SD-JWT library evaluation
- [x] JOSE layer: JWK parsing, JWS verification with an algorithm allowlist, X.509 chain validation
- [x] SD-JWT (RFC 9901): parsing, disclosure digests, key binding JWT
- [x] SD-JWT VC: type and issuer checks, `x5c` issuer binding
- [x] DCQL: query model, construction from a policy, response matching
- [x] Trusted lists: ETSI TS 119 602 (JSON, compact JAdES), TS 119 612 (XML) and LOTL, signature, freshness and rollback ([ADR-006](adr/0006-trusted-lists.md))
- [x] Token Status List, JWT form (CWT form with mdoc)
- [x] ISO mdoc: CBOR and COSE, MSO, value digests, issuer data authentication ([ADR-012](adr/0012-mdoc.md))
- [x] ISO mdoc: OpenID4VP session transcript, DCQL `mso_mdoc` with `intent_to_retain`, request metadata, service integration (fail-closed)
- [x] ISO mdoc: device authentication, DeviceResponse status rules, age attestations, eudi-dev wallet end to end
- [x] Presentation processor: `vp_token` to verified, minimized claims under a policy (SD-JWT VC)

## Service (`adapter-verifier-service`)

- [x] OpenAPI 3.1 contract ([management-v1.yaml](../openapi/management-v1.yaml))
- [x] Tenants, clients, policies (declarative configuration file); Flyway schema
- [x] Client-credentials authentication and tenant scoping
- [x] Session create, read, cancel; idempotency keys
- [x] Signed request objects (`x509_hash`), `request_uri` endpoint
- [x] `direct_post.jwt` endpoint: decryption, single-use completion
- [x] Result endpoint with minimized claims and short retention
- [x] Scenarios: happy path (V-01), cross-tenant access rejected (V-04), wallet decline reported as `denied` (V-06), concurrent responses produce one result (V-07), against PostgreSQL

## Release

- [x] Compose demo with a test wallet and synthetic issuer (`deploy/compose/demo.sh`, run in CI)
- [x] README, feature matrix, threat model and security policy reviewed against the code
- [x] Issuer certificate revocation with CRLs ([ADR-007](adr/0007-certificate-revocation.md)); OCSP not implemented
- [ ] Pending, recorded as such: OIDF conformance, a second independent wallet, real-device runs, external security review

## After the first release

ISO mdoc, SBOM, DC API, DID trust, and later an OID4VCI issuer service. Done since: per-client rate limits, metrics, audit log, tracing and configuration reload ([ADR-011](adr/0011-operations.md)), relying-party registration ([ADR-010](adr/0010-relying-party-registration.md)).
