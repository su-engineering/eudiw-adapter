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
| `EUDIW_CONFIG_RELOAD_INTERVAL` | no, default `30s` | How often each node checks the tenants file and the files under its directory for changes and reloads them. `off` disables. See [Reloading](#reloading) |
| `QUARKUS_OTEL_SDK_DISABLED` | no, default `true` | `false` turns on OpenTelemetry tracing over OTLP. Set the collector with `QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT` |

The public port (8080) serves the management API and the wallet endpoints. The management port (9000) serves health checks at `/health/live`, `/health/ready` and `/health/well` (registration certificates near expiry) and Prometheus metrics at `/metrics`; none of these are on the public port. Do not expose port 9000 publicly. See [Operations](#operations).

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
- `rate_limit`: optional. `{"sessions_per_minute": N}`, 1 to 100000, default 300. Counted per client in one-minute windows in PostgreSQL, so the limit holds across replicas. Over the limit, session creation returns 429 with `Retry-After`. The default applies to every client that does not set its own, so size it to each client's expected peak: 300 per minute is 5 new sessions per second. Watch `eudiw_rate_limited_total` after changing it.
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

- A dataset without a required member, a certificate that is not a `rc-wrp+jwt` JWS, and a DCQL query that asks for a credential or claim the dataset's `credential` list does not declare stop startup (or are refused on reload).
- An expired certificate is logged as an error and not sent.
- A query that asks for more than the certificate's `credentials` declares, a certificate whose `sub` (or intermediary) does not match the access certificate's `organizationIdentifier` or `serialNumber`, and a certificate missing members ETSI TS 119 475 requires are logged as warnings. The certificate is the registrar's and the wallet decides; fix it with them.

After a certificate expires, requests carry only the dataset, and `/health/well` reports the policy. It reports a certificate 30 days before expiry too. Replace the file and restart. See [ADR-010](adr/0010-relying-party-registration.md).

## Reloading

Each node checks the tenants file every `EUDIW_CONFIG_RELOAD_INTERVAL` (and when a session arrives under a revision it does not know). When the file or anything under its directory changed, it loads and validates the new configuration:

- If it is valid, it becomes active for new sessions. The previous configuration is kept for 15 minutes, the longest session lifetime, so sessions started under it finish under the rules they started with.
- If it is not valid, the error is logged and counted (`eudiw_config_reloads_total{outcome="failed"}`) and the running configuration stays.

Clients removed from the file lose access at once, also to their open sessions. Keys held in an HSM are reloaded with the configuration that references them; a change inside the token alone is not detected. In Kubernetes a mounted Secret is updated in place, so editing it is enough (not with `subPath` mounts).

## Operations

**Metrics** (Prometheus, `:9000/metrics`). Tags are configuration ids and reason codes, never session ids or request data.

| Metric | Meaning |
| --- | --- |
| `eudiw_events_total{tenant,policy,client,action,outcome,code}` | Every audited event: `session_created`, `request_fetched`, `response_received` (outcome `verified`, `rejected`, `denied`, with the reason code), `result_retrieved`, `session_cancelled`, `webhook` |
| `eudiw_presentation_verification_seconds{tenant,policy,outcome}` | Time to verify a presentation |
| `eudiw_sessions_expired_total` | Sessions that expired without a response |
| `eudiw_rate_limited_total{tenant,client}` | Session creations refused by the rate limit |
| `eudiw_webhook_retries_total{tenant,client}` | Webhook deliveries scheduled for another attempt |
| `eudiw_trusted_list_refreshes_total{outcome,code}`, `eudiw_trusted_lists_current{tenant,policy}` | Trusted list refreshes, and whether each policy that uses lists has a current one (0 means its verifications fail closed) |
| `eudiw_registration_certificate_expiry_seconds{tenant,policy}` | Seconds until a registration certificate expires |
| `eudiw_config_reloads_total{outcome}`, `eudiw_config_info{revision}` | Configuration reloads and the active revision |

JVM, process and connection pool metrics are included. HTTP server metrics are not, because request paths carry request handles.

**Audit log.** Every event above is also written to the `audit_event` table and as one line to the `eudiw.audit` log category: action, outcome, reason code, tenant, client, policy, session id, configuration revision and time. No claims, tokens, nonces or request handles. Route the category to your log pipeline; for JSON output add the Quarkus JSON logging extension in your build.

**Tracing.** With `QUARKUS_OTEL_SDK_DISABLED=false`, the service exports OpenTelemetry spans over OTLP. Before a span is recorded the request handle in `/oid4vp/requests/{handle}` is replaced and every query string is removed, since they would let a reader fetch a request or retrieve a same-device result.

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
