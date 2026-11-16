# eudiw-adapter

A self-hostable service that lets an existing application accept credentials from EUDI wallets and compatible wallets. Your backend asks for a verification, the user presents a credential from their wallet, and your backend gets back only the claims it asked for, already checked. Your application never handles OpenID4VP, DCQL, SD-JWT or certificate chains itself.

```text
your backend ──POST /v1/verification-sessions──▶ eudiw-adapter ◀──OpenID4VP──▶ wallet
             ◀──GET  …/result {"age_over_18": true}──┘
```

**Status:** early, unreleased. Read the [feature matrix](docs/standards-matrix.md) for exactly what is implemented and tested. Supporting a protocol here means automated tests pass for the pinned version. It is not a conformance or certification claim.

## What it does

- **Verifies SD-JWT VC presentations** (RFC 9901, SD-JWT VC draft 13): issuer signature, disclosures, key binding to your request, issuer certificate chain to your trust anchors, Token Status List revocation.
- **Speaks OpenID4VP 1.0 as HAIP 1.0 profiles it**: signed request objects with `x509_hash`, `direct_post.jwt` responses encrypted with a fresh key per request, DCQL.
- **Returns minimized results**: the policy decides which claims leave the service; everything else the wallet disclosed is dropped. Results are retrievable once and expire.
- **Multi-tenant**: tenants, client applications and policies come from configuration; the tenant is taken from the caller's OAuth token, never from the request. Trust anchors and status caches are per policy.
- **Fails closed**: unknown issuer, broken chain, revoked or unknown status, replayed or mismatched key binding, unexpected response: the session is rejected with a coarse reason code.

Not yet: ISO mdoc, ETSI trusted list ingestion (trust anchors are configured as certificates), Digital Credentials API, webhooks, credential issuance. See the [delivery plan](docs/pr-plan.md).

## Try it

Requirements: Docker, Java 21, `curl`, `jq`.

```bash
./deploy/compose/demo.sh
```

The demo starts PostgreSQL, Keycloak (as the OAuth server for your backend) and the adapter, generates synthetic keys, then plays both sides: a backend asks whether the user is over 18, and the [eudi-dev](https://github.com/eudi-dev/eudi-dev) test wallet issues itself a synthetic credential and presents it. The result contains `{"age_over_18": true}` and nothing else, although the credential also holds a name.

The demo runs over plain HTTP on localhost with `EUDIW_PRODUCTION=false`. Production requires HTTPS.

## Use it

1. Configure tenants, clients and policies: [configuration](docs/configuration.md).
2. Give your backend an OAuth client in your authorization server with the `verification:*` scopes.
3. Call the API: [OpenAPI](openapi/management-v1.yaml).

```bash
curl -X POST https://adapter.example/v1/verification-sessions \
  -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' -d '{"policy_id":"age-over-18","mode":"same_device"}'
```

Show `wallet_launch.launch_uri` as a link (same device) or QR code (cross device). Poll the session; when it is `verified`, fetch the result once. For `same_device`, the wallet returns the user to your completion URI with a `response_code`, and the result endpoint requires it. That stops someone from relaying your request to another person's wallet. Plain cross-device QR flows cannot detect that relay; see the [threat model](docs/threat-model.md).

## Modules

- `adapter-core`: verification library (SD-JWT VC, DCQL, status lists, request objects, response decryption). Plain Java 21 with Nimbus JOSE+JWT; usable without the service.
- `adapter-verifier-service`: the Quarkus service with PostgreSQL state.

## Documentation

- [Architecture](docs/architecture.md) and [decisions](docs/adr/)
- [Threat model](docs/threat-model.md)
- [Standards and feature status](docs/standards-matrix.md)
- [Configuration](docs/configuration.md)

## Build

```bash
./mvnw clean verify
```

Service tests start PostgreSQL and the eudi-dev wallet with Testcontainers, so Docker must be running.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
