# eudiw-adapter

[![CI](https://github.com/su-engineering/eudiw-adapter/actions/workflows/ci.yaml/badge.svg)](https://github.com/su-engineering/eudiw-adapter/actions/workflows/ci.yaml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Java 21](https://img.shields.io/badge/java-21-informational.svg)

**Open-source EUDI Wallet verifier for relying parties.** A self-hostable service and Java library that lets an existing application accept credentials from the EU Digital Identity Wallet (EUDI Wallet, eIDAS 2.0) and other OpenID4VP wallets. It verifies SD-JWT VC presentations under OpenID4VP 1.0 and HAIP 1.0, and hands your backend only the claims it asked for.

Your backend asks for a verification, the user presents a credential from their wallet, and your backend gets back a small, already-checked result such as `{"age_over_18": true}`. Your application never handles OpenID4VP, DCQL, SD-JWT, JWE or certificate chains itself.

```text
your backend ──POST /v1/verification-sessions──▶ eudiw-adapter ◀──OpenID4VP──▶ wallet
             ◀──GET  …/result {"age_over_18": true}──┘
```

**Status:** early, unreleased. The [feature matrix](docs/standards-matrix.md) lists exactly what is implemented and tested. "Supported" here means automated tests pass for a pinned version of the standard. It is not a conformance or certification claim.

## Use cases

- **Age verification** without collecting a birth date or identity document.
- **Attribute checks** at onboarding or checkout: residency, nationality, a professional qualification, any claim an issuer puts in an SD-JWT VC.
- **Adding wallet presentation to an existing product** (web, mobile backend, kiosk) through one REST API instead of a protocol stack.

If you want wallet login inside Keycloak instead, see [keycloak-oid4vp](https://github.com/su-engineering/keycloak-oid4vp).

## Features

- **SD-JWT VC verification** (RFC 9901, SD-JWT VC): issuer signature, disclosure digests, key binding to your request's nonce and client identifier, issuer X.509 certificate chain to your trust anchors, Token Status List revocation and suspension.
- **OpenID4VP 1.0 as profiled by HAIP 1.0**: signed request objects fetched by `request_uri`, `x509_hash` client identifier, `direct_post.jwt` responses encrypted (ECDH-ES P-256) to a fresh key per request, DCQL queries with claim sets, credential sets and `trusted_authorities`.
- **Data minimization**: each policy decides which claims leave the service. Everything else the wallet disclosed is dropped. Results are encrypted at rest, retrievable once, and expire. The raw presentation is never stored.
- **ETSI trusted lists**: issuer trust from signed TS 119 602 lists (such as the EU PID providers list) and TS 119 612 trusted lists, including the EU list of trusted lists, with pinned signers, freshness checks and rollback protection. Tested with synthetic lists so far, not yet with a published list. Or configure anchor certificates directly.
- **HSM and KMS keys**: request-signing keys can stay in an HSM or KMS through PKCS#11. Tested with SoftHSM; the demo signs with a key inside it.
- **Multi-tenant**: tenants, client applications and policies come from configuration. The tenant is taken from the caller's OAuth 2.0 token, never from the request. Trust anchors and status caches are per policy.
- **Issuer certificate revocation** with CRLs, opt-in per policy, fetched only after the chain validates.
- **Fails closed**: unknown issuer, broken chain, revoked or unknown status, replayed or mismatched key binding, or a late response rejects the session with a coarse reason code.
- **Same-device and cross-device flows**: deep link or QR code, with a one-time `response_code` that stops a same-device request from being relayed to someone else's wallet.
- **Tested against an independent wallet**: the [eudi-dev](https://github.com/eudi-dev/eudi-dev) wallet in strict HAIP and ARF mode, plus RFC 9901 and OpenID4VP test vectors and a differential test against a second SD-JWT implementation.

Not yet: ISO mdoc (`mso_mdoc`), OCSP, Digital Credentials API, credential issuance (OID4VCI). Work in progress is tracked in the [delivery plan](docs/pr-plan.md).

## Standards

| Standard | Version |
| --- | --- |
| OpenID for Verifiable Presentations (OpenID4VP) | 1.0 Final |
| OpenID4VC High Assurance Interoperability Profile (HAIP) | 1.0 Final |
| Selective Disclosure for JWTs (SD-JWT) | RFC 9901 |
| SD-JWT-based Verifiable Credentials (SD-JWT VC) | version referenced by HAIP 1.0 |
| Token Status List | version referenced by HAIP 1.0 |
| EUDI Wallet Architecture and Reference Framework (ARF) | reference |

Details and test evidence per feature: [standards and feature status](docs/standards-matrix.md).

## Try it

Requirements: Docker, Java 21, `curl`, `jq`.

```bash
./deploy/compose/demo.sh
```

The demo starts PostgreSQL, Keycloak (as the OAuth server for your backend) and the adapter, generates synthetic keys (the adapter's request-signing key is created inside SoftHSM and never leaves it, and issuer trust comes from a signed trusted list), then plays both sides: a backend asks whether the user is over 18, and the eudi-dev test wallet issues itself a synthetic credential and presents it. The result is `{"age_over_18": true}` and nothing else, although the credential also holds a name. The demo then shows a credential from an untrusted issuer being rejected.

The demo runs over plain HTTP on localhost with `EUDIW_PRODUCTION=false`. Production requires HTTPS.

## Use it

1. Configure tenants, clients and policies: [configuration](docs/configuration.md).
2. Give your backend an OAuth 2.0 client in your authorization server with the `verification:*` scopes.
3. Call the API: [OpenAPI](openapi/management-v1.yaml).

```bash
curl -X POST https://adapter.example/v1/verification-sessions \
  -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' -d '{"policy_id":"age-over-18","mode":"same_device"}'
```

Show `wallet_launch.launch_uri` as a link (same device) or a QR code (cross device). Poll the session, or configure a [webhook](docs/configuration.md) to be told when it ends; when it is `verified`, fetch the result once. For `same_device`, the wallet returns the user to your completion URI with a `response_code`, and the result endpoint requires it. Plain cross-device QR flows cannot detect a relayed request; see the [threat model](docs/threat-model.md).

## Modules

| Module | What it is |
| --- | --- |
| [`adapter-core`](adapter-core) | Verification library: SD-JWT VC, DCQL, X.509 chains, status lists, request objects, response decryption. Plain Java 21 with Nimbus JOSE+JWT, no framework, usable without the service |
| [`adapter-verifier-service`](adapter-verifier-service) | Quarkus service: management API, wallet endpoints, PostgreSQL state, audit |

## Documentation

- [Architecture](docs/architecture.md) and [decisions](docs/adr/)
- [Threat model](docs/threat-model.md)
- [Standards and feature status](docs/standards-matrix.md)
- [Configuration](docs/configuration.md)
- [Kubernetes and Helm](docs/kubernetes.md)

## Build

```bash
./mvnw clean verify
```

Service tests start PostgreSQL and the eudi-dev wallet with Testcontainers, so Docker must be running.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE). Maintained by [su.engineering](https://su.engineering).
