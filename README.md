<div align="center">

<img src="docs/assets/banner.svg" alt="eudiw-adapter: accept EU Digital Identity Wallet credentials, get back only the claims you asked for" width="100%">

<h3>The open-source EUDI Wallet verifier for relying parties</h3>

<p>Self-hosted service and Java library. Verifies SD-JWT VC presentations over OpenID4VP 1.0 and HAIP 1.0,<br>and hands your backend only the claims it asked for.</p>

[![CI](https://github.com/su-engineering/eudiw-adapter/actions/workflows/ci.yaml/badge.svg)](https://github.com/su-engineering/eudiw-adapter/actions/workflows/ci.yaml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-3b82f6)](LICENSE)
![Java 21](https://img.shields.io/badge/Java-21-f97316?logo=openjdk&logoColor=white)
![OpenID4VP 1.0](https://img.shields.io/badge/OpenID4VP-1.0_Final-0ea5e9)
![HAIP 1.0](https://img.shields.io/badge/HAIP-1.0_Final-6366f1)
![SD-JWT VC](https://img.shields.io/badge/SD--JWT_VC-RFC_9901-8b5cf6)
[![Helm](https://img.shields.io/badge/Helm-chart-0f1689?logo=helm&logoColor=white)](docs/kubernetes.md)

[**Quickstart**](#quickstart) · [**How it works**](#how-it-works) · [**Features**](#features) · [**Docs**](#documentation) · [**Security**](SECURITY.md)

</div>

> [!NOTE]
> **Early and unreleased.** The [feature matrix](docs/standards-matrix.md) lists exactly what is implemented and how it is tested. "Supported" means automated tests pass for a pinned version of a standard. It is not a conformance or certification claim.

## Why

The EU Digital Identity Wallet (EUDI Wallet, eIDAS 2.0) lets people prove facts about themselves from their phone. Accepting it means implementing a stack of new standards correctly. eudiw-adapter puts that stack behind one small REST API.

<table>
<tr>
<th width="50%">Without it, your application has to</th>
<th width="50%">With eudiw-adapter, your application</th>
</tr>
<tr>
<td>

- build and sign OpenID4VP request objects
- decrypt `direct_post.jwt` responses (ECDH-ES)
- verify SD-JWT disclosures and key binding
- validate issuer X.509 chains, trusted lists, CRLs
- check Token Status Lists
- decide what personal data to keep, and protect it

</td>
<td>

- calls `POST /v1/verification-sessions`
- shows a QR code or deep link
- reads `{"age_over_18": true}`

That's all. Nothing else the wallet disclosed ever reaches your systems.

</td>
</tr>
</table>

**Typical uses:** age verification without collecting a birth date, attribute checks at onboarding or checkout (residency, nationality, a qualification), adding wallet presentation to an existing web or mobile product. For wallet *login* inside Keycloak, see [keycloak-oid4vp](https://github.com/su-engineering/keycloak-oid4vp).

## Quickstart

Requirements: Docker, Java 21, `curl`, `jq`.

```bash
git clone https://github.com/su-engineering/eudiw-adapter.git && cd eudiw-adapter
./deploy/compose/demo.sh
```

<div align="center">
<img src="docs/assets/demo.svg" alt="Demo output: a session is created, the wallet presents, the result contains only age_over_18 true, and an untrusted issuer is rejected" width="88%">
</div>

The demo runs PostgreSQL, Keycloak (as your OAuth server) and the adapter, then plays both sides with the independent [eudi-dev](https://github.com/eudi-dev/eudi-dev) wallet in HAIP mode:
- The adapter's request-signing key is generated inside SoftHSM and never leaves it.
- Issuer trust comes from a signed ETSI trusted list.
- The credential also holds a name, but only `age_over_18` comes back.

The same demo runs in CI on every commit. It uses plain HTTP on localhost with `EUDIW_PRODUCTION=false`; production requires HTTPS.

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant App as Your backend
    participant A as eudiw-adapter
    participant W as Wallet
    App->>A: POST /v1/verification-sessions {policy_id}
    A-->>App: launch_uri (QR code or deep link)
    App-)W: user opens the link or scans the QR code
    W->>A: fetch request_uri
    A-->>W: signed request object (x509_hash, DCQL, fresh encryption key)
    W->>A: direct_post.jwt (encrypted SD-JWT VC presentation)
    Note over A: decrypt · verify issuer chain and trusted list<br/>key binding · status list · CRL · DCQL<br/>keep only the policy's output claims
    A-->>W: redirect_uri with one-time response_code (same device)
    A--)App: signed webhook (optional) or poll
    App->>A: GET /v1/verification-sessions/{id}/result
    A-->>App: {"age_over_18": true} (once, then deleted)
```

<details>
<summary><b>The API calls in full</b></summary>

```bash
# 1. Start a session (OAuth 2.0 client-credentials token with verification:create)
curl -X POST https://adapter.example/v1/verification-sessions \
  -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: $(uuidgen)" \
  -H 'Content-Type: application/json' \
  -d '{"policy_id":"age-over-18","mode":"same_device","client_reference":"order-42"}'
```

```json
{
  "id": "vrs_2SzKUQQugO51nHJtOptDBowHzwztWwdf8lyMvVvAN9E",
  "status": "pending",
  "policy_id": "age-over-18",
  "wallet_launch": { "launch_uri": "openid4vp://?client_id=x509_hash%3A...&request_uri=..." }
}
```

```bash
# 2. When the session is verified (poll, or wait for the webhook), fetch the result once
curl https://adapter.example/v1/verification-sessions/$ID/result -H "Authorization: Bearer $TOKEN"
```

```json
{
  "id": "vrs_2SzKUQQugO51nHJtOptDBowHzwztWwdf8lyMvVvAN9E",
  "status": "verified",
  "policy_id": "age-over-18",
  "verified_at": "2026-11-16T23:33:30Z",
  "claims": { "age_over_18": true },
  "credential_evidence": [
    { "format": "dc+sd-jwt", "credential_type": "https://credentials.example/age", "issuer": "https://issuer.example" }
  ]
}
```

Show `launch_uri` as a link on the same device or as a QR code across devices. In same-device flows the wallet sends the user back to your completion URI with a `response_code`, and the result call requires it, so a relayed request cannot be completed by someone else's wallet. Full contract: [OpenAPI](openapi/management-v1.yaml).

</details>

## Features

<table>
<tr>
<td width="50%" valign="top">

**Verification you don't have to write**<br>
SD-JWT VC (RFC 9901): issuer signature, disclosure digests, key binding to your nonce and client identifier, Token Status List revocation and suspension.

</td>
<td width="50%" valign="top">

**OpenID4VP 1.0 as HAIP 1.0 profiles it**<br>
Signed request objects by `request_uri`, `x509_hash` client identifier, `direct_post.jwt` encrypted to a fresh key per request, DCQL with claim sets, credential sets and `trusted_authorities`.

</td>
</tr>
<tr>
<td valign="top">

**Data minimization by design**<br>
Each policy names the claims that may leave the service. Results are encrypted at rest, retrievable once and expire. The raw presentation is never stored.

</td>
<td valign="top">

**ETSI trusted lists**<br>
Issuer trust from signed TS 119 602 lists (such as the EU PID providers list) and TS 119 612 lists including the EU list of trusted lists. Pinned signers, freshness checks, rollback protection. Tested with synthetic lists so far.

</td>
</tr>
<tr>
<td valign="top">

**HSM and KMS keys**<br>
Request-signing keys can stay in an HSM or KMS through PKCS#11. Tested with SoftHSM, which the demo signs with.

</td>
<td valign="top">

**Fails closed**<br>
Unknown issuer, broken chain, revoked certificate (CRL) or credential, unknown status, replayed key binding or late response: rejected, with a coarse reason code.

</td>
</tr>
<tr>
<td valign="top">

**Multi-tenant**<br>
Tenants, clients and policies from configuration. The tenant always comes from the caller's OAuth token, never from the request. Anchors and caches are per policy.

</td>
<td valign="top">

**Signed webhooks**<br>
Standard Webhooks HMAC signatures, queued in the same database statement that ends the session, retried with backoff. They carry the session id and status, never claims.

</td>
</tr>
<tr>
<td valign="top">

**Ready to run**<br>
Docker image, Compose demo, and a Helm chart that runs under the restricted Pod Security Standard. Any number of replicas share state through PostgreSQL.

</td>
<td valign="top">

**Tested against others' work**<br>
RFC 9901 and OpenID4VP worked examples, a differential test against a second SD-JWT implementation, 5,000 mutated inputs, the independent eudi-dev wallet in strict HAIP and ARF mode, and the OpenID Foundation HAIP verifier test plan run locally ([results](interop/oidf/README.md)).

</td>
</tr>
</table>

## Architecture

```mermaid
flowchart LR
    APP["Your backend"] -- "OAuth 2.0 bearer<br/>REST /v1" --> SVC
    WALLET["EUDI Wallet"] -- "OpenID4VP<br/>request_uri · direct_post.jwt" --> SVC
    subgraph ADAPTER ["eudiw-adapter"]
      SVC["verifier service<br/><sub>Quarkus</sub>"] --> CORE["adapter-core<br/><sub>plain Java library</sub>"]
    end
    SVC --> DB[("PostgreSQL")]
    SVC -. "signed webhooks" .-> APP
    CORE -. "egress-checked fetches" .-> NET["trusted lists · status lists · CRLs"]
    SVC -. "PKCS#11" .-> HSM["HSM / KMS"]
```

| Module | What it is |
| --- | --- |
| [`adapter-core`](adapter-core) | Verification library: SD-JWT VC, DCQL, X.509 chains, trusted lists, status lists, CRLs, request objects, response decryption. Java 21 with Nimbus JOSE+JWT, no framework, usable without the service |
| [`adapter-verifier-service`](adapter-verifier-service) | Quarkus service: management API, wallet endpoints, PostgreSQL state, webhooks, audit |

## Standards

| Standard | Version |
| --- | --- |
| OpenID for Verifiable Presentations (OpenID4VP) | 1.0 Final |
| OpenID4VC High Assurance Interoperability Profile (HAIP) | 1.0 Final |
| Selective Disclosure for JWTs (SD-JWT) | RFC 9901 |
| SD-JWT-based Verifiable Credentials (SD-JWT VC) | version referenced by HAIP 1.0 |
| Token Status List | version referenced by HAIP 1.0 |
| ETSI TS 119 602 / TS 119 612 trusted lists | V1.1.1 / V2.4.1 |
| EUDI Wallet Architecture and Reference Framework (ARF) | reference |

Test evidence per feature: [standards and feature status](docs/standards-matrix.md).

## Roadmap

- [x] SD-JWT VC verification, OpenID4VP 1.0 + HAIP 1.0, DCQL
- [x] ETSI trusted lists (TS 119 602, TS 119 612, EU LOTL)
- [x] Token Status List and CRL revocation checks
- [x] Signed webhooks, HSM/KMS request signing, Helm chart
- [ ] ISO mdoc (`mso_mdoc`)
- [ ] OCSP
- [x] OpenID Foundation HAIP verifier test plan, run locally (not certified)
- [ ] Certification, more wallets, real devices
- [ ] Digital Credentials API

## Documentation

| | |
| --- | --- |
| [Architecture](docs/architecture.md) and [decisions](docs/adr/) | How it is built and why |
| [Configuration](docs/configuration.md) | Tenants, policies, trusted lists, webhooks, HSM keys |
| [Kubernetes and Helm](docs/kubernetes.md) | Deploying the chart |
| [Threat model](docs/threat-model.md) | What it defends against, and what it doesn't |
| [Standards and feature status](docs/standards-matrix.md) | Pinned versions and test evidence |

## Build

```bash
./mvnw clean verify
```

Service tests start PostgreSQL and the eudi-dev wallet with Testcontainers, so Docker must be running.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

<div align="center">
<sub>Built by <a href="https://su.engineering">su.engineering</a></sub>
</div>
