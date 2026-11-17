# Configuration

The verifier service reads environment variables for deployment settings and one JSON file for tenants, clients and policies. Any error in the file stops startup.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `EUDIW_CONFIG_FILE` | yes | Path to the tenants file below |
| `EUDIW_PUBLIC_BASE_URL` | yes | Public HTTPS origin wallets reach, for example `https://adapter.example`. Request and response URIs are built from it |
| `EUDIW_DATA_KEY` | yes | 32 random bytes, base64. Results and per-request keys are encrypted at rest with keys derived from it per tenant. Generate with `openssl rand -base64 32` and keep it in a secret store |
| `EUDIW_DB_URL`, `EUDIW_DB_USER`, `EUDIW_DB_PASSWORD` | yes | PostgreSQL 16 or later. The schema is migrated at startup |
| `EUDIW_OIDC_ISSUER` | yes | Issuer URL of the authorization server that issues client-credentials tokens |
| `EUDIW_OIDC_AUDIENCE` | yes | Audience the access tokens must carry |
| `EUDIW_PRODUCTION` | no, default `true` | `true` refuses HTTP public URLs, development egress settings, `status_policy: ignore` and non-HTTPS completion URIs |
| `EUDIW_EGRESS_ALLOW_PRIVATE_ADDRESSES`, `EUDIW_EGRESS_ALLOW_HTTP` | no, default `false` | Development only: let status list and trusted list fetches reach private addresses or plain HTTP |
| `EUDIW_TRUSTED_LISTS_REFRESH_INTERVAL` | no, default `1h` | How often each node fetches and verifies the configured trusted lists |
| `EUDIW_WEBHOOK_INTERVAL` | no, default `5s` | How often each node sends due webhook notifications |

The public port (8080) serves the management API and the wallet endpoints. Health checks are on the management port (9000) at `/health/live` and `/health/ready`, not on the public port. Do not expose port 9000 publicly.

Access tokens must name the client in `azp` or `client_id` and list scopes in `scope`: `verification:create`, `verification:read`, `verification:result`, `verification:cancel`.

## Tenants file

```json
{
  "tenants": [
    {
      "id": "city-of-example",
      "verifier": {
        "private_key_file": "keys/verifier-key.pem",
        "certificate_chain_file": "keys/verifier-chain.pem"
      },
      "wallet_invocation": "openid4vp://",
      "clients": [
        {
          "client_id": "citizen-portal",
          "policies": ["age-over-18"],
          "completion_uri": "https://portal.example/verification-complete"
        }
      ],
      "policies": [
        {
          "id": "age-over-18",
          "dcql": { "credentials": [ { "id": "age", "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://credentials.example/age"] },
            "claims": [ { "path": ["age_over_18"] } ] } ] },
          "output": { "age_over_18": { "credential": "age", "path": ["age_over_18"] } },
          "trust_anchors_file": "trust/issuer-roots.pem",
          "allowed_issuers": ["https://issuer.example"],
          "status_policy": "require_valid",
          "enforce_trusted_authorities": true,
          "session_ttl_seconds": 300,
          "result_ttl_seconds": 900
        }
      ]
    }
  ]
}
```

Relative paths resolve against the directory of the tenants file.

**Tenant**
- `verifier`: the request-signing key and its certificate chain (`certificate_chain_file`), end-entity first, without the root. The key is either `private_key_file` (PKCS#8 PEM, EC P-256) or `pkcs11`, a key held in an HSM or KMS: `library` (path of the PKCS#11 library), `slot_list_index` (default 0), `key_label` and `pin_file`. The token must also hold the certificate under the same label and ID as the key (for example written with `pkcs11-tool --write-object cert.der --type cert`). At startup the service signs a probe with the key and checks it against the certificate ([ADR-009](adr/0009-hsm-request-signing.md)). The end-entity certificate must not be self-signed (HAIP 1.0). The client identifier wallets see is `x509_hash:` plus the SHA-256 of this certificate. In an EUDI ecosystem this is the relying-party access certificate issued under that ecosystem's rules.
- `wallet_invocation`: scheme of the launch URI, for example `openid4vp://` or `haip-vp://`.

**Client**
- `client_id`: the OAuth client id in the access token. Unique across all tenants.
- `policies`: the only policies this client may start.
- `completion_uri`: where same-device flows send the user back, with `#response_code=...`. Required for `same_device` sessions.
- `webhook`: optional. `url` (HTTPS in production) receives a signed notification when one of this client's sessions is verified, rejected, denied or expired; `secret_file` holds a `whsec_` secret of 24 to 64 random bytes (generate with `echo "whsec_$(openssl rand -base64 32)"`); `previous_secret_file` optionally holds the old secret during a rotation. The notification carries no claims. See the `webhooks` section of the [OpenAPI](../openapi/management-v1.yaml) and [ADR-008](adr/0008-webhooks.md).

**Policy**
- `dcql`: the DCQL query sent to wallets (OpenID4VP 1.0 section 6). Callers cannot change it.
- `output`: result claim names mapped to a credential query id and a claims path. Every path must be requested by the query, so a result can never contain more than the policy asks for.
- `trust_anchors_file`: PEM certificates that issuer and status list certificate chains must validate to. Scoped to this policy.
- `trusted_lists`: signed ETSI trusted lists whose approved services become trust anchors for this policy, in addition to `trust_anchors_file`. A policy needs at least one of the two. See [Trusted lists](#trusted-lists).
- `allowed_issuers`: optional allow list of issuer identifiers.
- `certificate_revocation`: `crl` checks every issuer chain certificate except the anchor against its CRL, and rejects when a CRL is missing, stale or unreachable; `off` (default) does not check. CRLs are fetched over HTTP or HTTPS from public addresses only ([ADR-007](adr/0007-certificate-revocation.md)).
- `status_policy`: `require_valid` (default; an unavailable status list rejects), `reject_known_invalid` (revoked or suspended rejects, unavailable is tolerated) or `ignore` (not allowed in production).
- `enforce_trusted_authorities`: reject credentials that match none of the query's `trusted_authorities` (default `true`).
- `session_ttl_seconds`: at most 900. `result_ttl_seconds`: at most 3600.
- `registration`: optional. What the relying party registered for this intended use, sent to wallets in `verifier_info` as ETSI TS 119 472-2 requires. See [Registration](#registration).

## Registration

In the EUDI Wallet ecosystem a relying party registers each intended use with its national registrar. The wallet shows that registration to the user and refuses requests that ask for more than was registered. Configure it per policy:

```json
"registration": {
  "registrar_dataset_file": "registration/age-over-18.json",
  "certificate_file": "registration/age-over-18.rc.jwt"
}
```

- `registrar_dataset` (an object) or `registrar_dataset_file` (a JSON file): the data the registrar holds about this intended use, sent as the `registrar_dataset` element. It needs `identifier`, `srvDescription` and `purpose` (arrays of `{"lang", "content"}`), `registryURI`, `intendedUseIdentifier` and `policyURI`, and may list the registered `credential` entries. Use what your registrar publishes; the service does not change it.
- `certificate_file`: optional. The registration certificate (a `rc-wrp+jwt` JWT) the registration certificate provider issued, sent base64url-encoded as the `registration_cert` element.

At startup:

- A dataset without a required member, a certificate that is not a `rc-wrp+jwt` JWS or has expired, and a DCQL query that asks for a credential or claim the dataset's `credential` list does not declare stop startup.
- A query that asks for more than the certificate's `credentials` declares, a certificate whose `sub` (or intermediary) does not match the access certificate's `organizationIdentifier` or `serialNumber`, and a certificate missing members ETSI TS 119 475 requires are logged as warnings. The certificate is the registrar's and the wallet decides; fix it with them.

After a certificate expires, requests carry only the dataset, and `/health/well` reports the policy. It reports a certificate 30 days before expiry too. Replace the file and restart. See [ADR-010](adr/0010-relying-party-registration.md).

## Trusted lists

Each entry of a policy's `trusted_lists`:

| Field | Required | Meaning |
| --- | --- | --- |
| `location` | yes | `https://` URL, or a path relative to the tenants file for a list you mirror locally |
| `identifier` | no | What DCQL `trusted_authorities` of type `etsi_tl` must name to match credentials anchored by this list. Defaults to `location`; set it to the public URL when `location` is a local mirror |
| `format` | yes | `tsl_xml` (ETSI TS 119 612, including the EU list of trusted lists) or `lote_json` (ETSI TS 119 602 JSON with a compact JAdES signature) |
| `signer_certificates_file` | yes | PEM certificates allowed to sign the list. For the EU list of trusted lists, the certificates published in the Official Journal of the EU |
| `issuance_service_types` | yes | Service type URIs whose certificates may anchor credential issuers, for example `http://uri.etsi.org/19602/SvcType/PID/Issuance` or `http://uri.etsi.org/TrstSvc/Svctype/EAA/Q` |
| `status_service_types` | no | Further service types whose certificates may anchor status list tokens, for example `http://uri.etsi.org/19602/SvcType/PID/Revocation`. Issuance types always may |
| `accepted_statuses` | no | Service status URIs that count as approved. Default: `granted`, `recognisedatnationallevel` (TS 119 612) and the public sector EAA `notified` (TS 119 602). A service without a status counts as approved |
| `follow_pointers` | no | For a list of trusted lists (`tsl_xml` only): also load the XML lists it points to, each checked against the signer certificates its pointer publishes |
| `territories` | no | With `follow_pointers`, only these territories, for example `["DE", "AT"]` |

```json
"trusted_lists": [
  { "location": "https://lists.example/pid-providers.jwt",
    "format": "lote_json",
    "signer_certificates_file": "trust/pid-list-signers.pem",
    "issuance_service_types": ["http://uri.etsi.org/19602/SvcType/PID/Issuance"],
    "status_service_types": ["http://uri.etsi.org/19602/SvcType/PID/Revocation"] }
]
```

Each node fetches the lists at startup and then every refresh interval. A list must be signed by one of its configured certificates and be within its issue and next update times, and its sequence number may not go backwards. If a refresh fails, the last verified version stays in use until its next update and is then dropped, so trust fails closed. The highest accepted sequence number of each list is kept in the database. A node reports not ready on `/health/ready` until its first refresh has run. After that, a policy with no current list rejects every presentation and is named in the `trusted-lists` health check data and in the log, but the node stays ready for other policies.

No list, list location or signer certificate is bundled with the service. Take them from the publishing body.

Changing the file changes its revision. Sessions started under a previous revision are not served under different rules: their wallet requests return 404.
