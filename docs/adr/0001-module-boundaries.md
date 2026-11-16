# ADR-001: An independent verification core

Status: accepted (2026-11-16).

## Context

The adapter verifies the most security-sensitive inputs it receives: signed credentials, selective disclosures, holder binding proofs and encrypted wallet responses. It must be usable from any Java application and from the verifier service, and must not tie its release cadence or its correctness to an identity product's internal APIs.

## Decision

- `adapter-core` depends only on the JDK and a JOSE library (a CBOR library will join it with ISO mdoc). It has no dependency on any identity and access management product; a Maven Enforcer rule bans `org.keycloak` artifacts as a guard against accidental coupling.
- JOSE, JWK and JWE use Nimbus JOSE+JWT, subject to the evaluation in [ADR-005](0005-jose-and-sd-jwt-libraries.md).
- SD-JWT (RFC 9901) and SD-JWT VC verification are implemented in core on top of the JOSE library, with no custom cryptographic primitives.
- Each area is implemented from its specification and tested against fixtures with an expected outcome per case, anchored on published examples and test vectors where they exist (see [pr-plan.md](../pr-plan.md)).

## Consequences

- Failures use a core `VerificationFailure` type with a stable error code.
- Any Java application can verify presentations with `adapter-core` alone; the service adds sessions, tenants and HTTP endpoints.
