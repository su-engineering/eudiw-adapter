# Configuration

The verifier service reads environment variables for deployment settings and one JSON file for tenants, clients and policies. Any error in the file stops startup.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `EUDIW_CONFIG_FILE` | yes | Path to the tenants file below |
| `EUDIW_PUBLIC_BASE_URL` | yes | Public HTTPS origin wallets reach, for example `https://adapter.example`. Request and response URIs are built from it |
| `EUDIW_DATA_KEY` | yes | 32 random bytes, base64. Results and per-request keys are encrypted at rest with keys derived from it per tenant. Generate with `openssl rand -base64 32` and keep it in a secret store. See [Rotating the data key](#rotating-the-data-key) |
| `EUDIW_PREVIOUS_DATA_KEYS` | no | Comma-separated data keys from before a rotation. They decrypt what they wrote; nothing new is encrypted with them |
| `EUDIW_DB_URL`, `EUDIW_DB_USER`, `EUDIW_DB_PASSWORD` | yes | PostgreSQL 16 or later. The schema is migrated at startup |
| `EUDIW_OIDC_ISSUER` | yes | Issuer URL of the authorization server that issues client-credentials tokens |
| `EUDIW_OIDC_AUDIENCE` | yes | Audience the access tokens must carry |
| `EUDIW_PRODUCTION` | no, default `true` | `true` refuses HTTP public URLs, development egress settings, `status_policy: ignore` and non-HTTPS completion URIs |
| `EUDIW_EGRESS_ALLOW_PRIVATE_ADDRESSES`, `EUDIW_EGRESS_ALLOW_HTTP` | no, default `false` | Development only: let status list and trusted list fetches reach private addresses or plain HTTP |
| `EUDIW_EGRESS_PROXY` | no | Forward proxy for every trusted list, status list and CRL fetch, as `host:port` or `http://host:port`. HTTPS goes through it with `CONNECT`. The service still applies its own address and host checks, so it must be able to resolve the host names itself; the proxy resolves the name again, so give it its own allow list and deny private ranges there. Without it, the JVM proxy system properties (`https.proxyHost` and so on) apply as before |
| `EUDIW_EGRESS_ALLOWED_HOSTS` | no | Comma-separated host names. If set, trusted list, status list and CRL fetches may reach only these hosts, on top of the address checks. Every host the configured lists, their pointers, the credentials' status lists and the CRL distribution points name must be listed |
| `EUDIW_MANAGEMENT_HOST` | no, default `0.0.0.0` | Address the management port (9000) listens on. Set `127.0.0.1` outside Kubernetes when only local monitoring needs it |
| `EUDIW_TRUSTED_LISTS_REFRESH_INTERVAL` | no, default `1h` | How often each node fetches and verifies the configured trusted lists |
| `EUDIW_WEBHOOK_INTERVAL` | no, default `5s` | How often each node sends due webhook notifications |
| `EUDIW_EVENTS_INTERVAL` | no, default `1s` | How often each node reads the sessions behind open event streams (`/v1/verification-sessions/{id}/events`) and sends what changed. One query per node per interval while any stream is open ([ADR-013](adr/0013-session-events.md)) |
| `EUDIW_EVENT_STREAMS_MAX`, `EUDIW_EVENT_STREAMS_PER_CLIENT` | no, default `1000` and `100` | Open event streams allowed per node, and per client on one node. Above either, opening a stream returns `429 too_many_streams` and the client polls instead |
| `EUDIW_WALLET_REQUESTS_PER_MINUTE` | no, default `0` (off) | Requests per minute one source address may make to the wallet endpoints (`/oid4vp/requests/*` and `/oid4vp/responses`), counted across nodes in PostgreSQL. IPv6 addresses count by their /64. Over the limit the endpoints return 429 with `Retry-After`. The address is the one the service sees: behind a load balancer or ingress, turn on proxy address forwarding (`QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING=true` with `QUARKUS_HTTP_PROXY_ALLOW_X_FORWARDED=true` or `..._ALLOW_FORWARDED=true`, and `QUARKUS_HTTP_PROXY_TRUSTED_PROXIES`), or every wallet shares the proxy's address and one limit. Quarkus takes the leftmost `X-Forwarded-For` entry, so turn forwarding on only behind a proxy that replaces the header with the address it saw; behind one that appends to it, a client can choose its own key, so limit at the ingress instead. A forwarded value that is not an IP address, such as `unknown`, counts against one shared bucket. A wallet makes two or three requests per session, so leave room for many users behind one carrier NAT address; 600 is a reasonable start. Limiting at the ingress works too |
| `EUDIW_CONFIG_RELOAD_INTERVAL` | no, default `30s` | How often each node checks the tenants file and the files it references for changes and reloads them. `off` disables. See [Reloading](#reloading) |
| `QUARKUS_OTEL_SDK_DISABLED` | no, default `true` | `false` turns on OpenTelemetry tracing over OTLP. Set the collector with `QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT` |

The public port (8080) serves the management API and the wallet endpoints. The management port (9000) serves health checks at `/health/live`, `/health/ready` and `/health/well` (registration certificates near expiry) and Prometheus metrics at `/metrics`; none of these are on the public port. Do not expose port 9000 publicly. It listens on every interface, because Kubernetes probes and Prometheus reach it on the pod address; the chart's network policy limits who can connect, and the Compose file publishes it on `127.0.0.1` only. On a plain host or VM, set `EUDIW_MANAGEMENT_HOST=127.0.0.1` (or the address your monitoring uses) or block port 9000 in the host firewall. See [Operations](#operations).

Access tokens must name the client in `azp` or `client_id` (a string, compared exactly) and list scopes in `scope`: `verification:create`, `verification:read`, `verification:result`, `verification:cancel`.

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
- `client_id`: the OAuth client id in the access token. Unique across all tenants. 1 to 255 printable ASCII characters without spaces, double quotes or backslashes.
- `policies`: the only policies this client may start.
- `completion_uri`: where same-device flows send the user back, with `#response_code=...`. Required for `same_device` sessions.
- `rate_limit`: optional. `{"sessions_per_minute": N}`, 1 to 100000, default 300. Counted per client in one-minute windows in PostgreSQL, so the limit holds across replicas. Over the limit, session creation returns 429 with `Retry-After`. The default applies to every client that does not set its own, so size it to each client's expected peak: 300 per minute is 5 new sessions per second. Watch `eudiw_rate_limited_total` after changing it.
- `webhook`: optional. `url` (HTTPS in production) receives a signed notification when one of this client's sessions is verified, rejected, denied or expired; `secret_file` holds a `whsec_` secret of 24 to 64 random bytes (generate with `echo "whsec_$(openssl rand -base64 32)"`); `previous_secret_file` optionally holds the old secret during a rotation. The notification carries no claims. See the `webhooks` section of the [OpenAPI](../openapi/management-v1.yaml) and [ADR-008](adr/0008-webhooks.md).

**Policy**
- `dcql`: the DCQL query sent to wallets (OpenID4VP 1.0 section 6). Callers cannot change it. Formats: `dc+sd-jwt`, and `mso_mdoc` (see [mdoc](#mdoc)).
- `output`: result claim names mapped to a credential query id and a claims path. Every path must be requested by the query, so a result can never contain more than the policy asks for.
- `trust_anchors_file`: PEM certificates that issuer and status list certificate chains must validate to. Scoped to this policy. Prefer the issuer's own CA over a broad CA that also certifies other purposes: any certificate under an anchor that can bind the credential's `iss` can sign credentials. `issuer_extended_key_usages` narrows this.
- `trusted_lists`: signed ETSI trusted lists whose approved services become trust anchors for this policy, in addition to `trust_anchors_file`. A policy needs at least one of the two. See [Trusted lists](#trusted-lists).
- `allowed_issuers`: optional allow list of issuer identifiers.
- `certificate_revocation`: `crl` checks every issuer chain certificate except the anchor against its CRL, and rejects when a CRL is missing, stale or unreachable; `off` (default) does not check. CRLs are fetched over HTTP or HTTPS from public addresses only ([ADR-007](adr/0007-certificate-revocation.md)).
- `status_policy`: `require_valid` (default; an unavailable status list rejects), `reject_known_invalid` (revoked or suspended rejects, unavailable is tolerated) or `ignore` (not allowed in production).
- `require_status`: refuse a credential that carries no status reference the adapter can check, with `credential_status_missing` (default `false`: under every `status_policy`, a credential without status is accepted). An mdoc whose MSO status uses a mechanism other than a Token Status List is refused with `credential_status_unknown`. Set it when revocation must be possible for every accepted credential. Not allowed with `status_policy: ignore`. Must be a JSON boolean.
- `status_signer`: which trust anchors may sign a credential's status list. `any_anchor` (default) accepts a list whose signer chains to any status anchor of the policy. `credential_issuer` accepts only a list signed under the same trust anchor as the credential's issuer, so a status provider trusted for one issuer cannot report on another issuer's credentials. A list signed under another anchor counts as an unavailable status (`status_signer_not_issuer`): `require_valid` rejects the credential with `credential_status_unknown`, `reject_known_invalid` accepts it.
- `issuer_extended_key_usages`: optional list of dotted extended key usage OIDs. When set, an SD-JWT VC is accepted only if its issuer (end-entity) certificate carries at least one of them; otherwise it is rejected with `issuer_untrusted`. Use the OID your issuer certificate profile defines. Default: no requirement.
- `enforce_trusted_authorities`: reject credentials that match none of the query's `trusted_authorities` (default `true`). Must be a JSON boolean; `"true"` is a configuration error. An `aki` value matches the AuthorityKeyIdentifier of any certificate in the chain the credential presents (OpenID4VP 1.0 section 6.1.1.1). Use the key identifier of the CA that issued a certificate in that chain; a root's key identifier matches through the certificate it issued, even when the chain omits the root.
- `mdoc_strict_conformance`: refuse mdoc departures from ISO/IEC 18013-5 that are otherwise accepted with a conformance warning; today, a P-384 device key (default `false`, see [mdoc](#mdoc)).
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
- `certificate_file`: optional. The registration certificate (a `rc-wrp+jwt` JWT) the registration certificate provider issued, sent base64url-encoded as the `registration_cert` element. The adapter checks its form (`typ`, `x5c`, `sub`, `iat`) and expiry but does not verify its signature or its provider's trust; the wallet does that, so make sure the file comes from your registration certificate provider.

At startup:

- A dataset without a required member, a certificate that is not a `rc-wrp+jwt` JWS, and a DCQL query that asks for a credential or claim the dataset's `credential` list does not declare stop startup (or are refused on reload).
- An expired certificate is logged as an error and not sent.
- A query that asks for more than the certificate's `credentials` declares, a certificate whose `sub` (or intermediary) does not match the access certificate's `organizationIdentifier` or `serialNumber`, and a certificate missing members ETSI TS 119 475 requires are logged as warnings. The certificate is the registrar's and the wallet decides; fix it with them.

After a certificate expires, requests carry only the dataset, and `/health/well` reports the policy. It reports a certificate 30 days before expiry too. Replace the file and restart. See [ADR-010](adr/0010-relying-party-registration.md).

## Reloading

Each node checks the tenants file every `EUDIW_CONFIG_RELOAD_INTERVAL` (and when a session arrives under a revision it does not know). It compares the content of the tenants file and of every file it references (keys, certificate chains, trust anchors, webhook secrets, registration files, the HSM PIN file) with what it last loaded. Other files in the directory are not watched. When one changed, it loads and validates the new configuration:

- If it is valid, it becomes active for new sessions. The previous configuration is kept for 15 minutes, the longest session lifetime, so sessions started under it finish under the rules they started with.
- If it is not valid, the error is logged and counted (`eudiw_config_reloads_total{outcome="failed"}`) and the running configuration stays.

Clients removed from the file lose access at once, also to their open sessions. Keys held in an HSM are reloaded with the configuration that references them; a change inside the token alone is not detected. In Kubernetes a mounted Secret is updated in place, so editing it is enough (not with `subPath` mounts).

The revision is the SHA-256 of the tenants file and the content of every file it references, 64 hex characters. Rotating a webhook secret or a signing key therefore makes a new revision, like any other change. Before 0.2.1 the revision was 16 characters and did not cover keys and secrets. During a rolling upgrade from 0.2.0, old and new pods compute different revisions for the same files, so a session created on one version gets 404 for its wallet requests on the other. Upgrade outside busy hours, or let open sessions (at most 15 minutes) finish first.

### Rotating the data key

Results and per-request keys are encrypted with the current `EUDIW_DATA_KEY`. Each ciphertext names the key that wrote it.

1. Generate a new key. Set it as `EUDIW_DATA_KEY` and move the old one to `EUDIW_PREVIOUS_DATA_KEYS` on every node.
2. Wait until everything the old key wrote has expired: the longest `result_ttl` of any policy (results are deleted when retrieved or when they expire), and the longest session lifetime for per-request keys.
3. Remove the old key from `EUDIW_PREVIOUS_DATA_KEYS`.

With the Helm chart, put the old keys under `previous-data-keys` in the data key secret. Data written by 0.2.0, before key ids, is tried against every configured key.

## Operations

**Metrics** (Prometheus, `:9000/metrics`). Tags are configuration ids and reason codes, never session ids or request data.

| Metric | Meaning |
| --- | --- |
| `eudiw_events_total{tenant,policy,client,action,outcome,code}` | Every audited event: `session_created`, `request_fetched`, `response_received` (outcome `verified`, `rejected`, `denied`, with the reason code), `conformance_warning` (outcome `accepted`, with the warning code; see [mdoc](#mdoc)), `result_retrieved`, `session_cancelled`, `webhook` |
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


## mdoc

A policy can request an ISO mdoc (ISO/IEC 18013-5) with `"format": "mso_mdoc"`, a `meta.doctype_value`, and claim paths of the form `[namespace, element]`, optionally with `intent_to_retain` (OpenID4VP 1.0 Appendix B.2). An mDL:

```json
"dcql": { "credentials": [ { "id": "mdl", "format": "mso_mdoc",
  "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
  "claims": [ { "path": ["org.iso.18013.5.1", "age_over_18"], "intent_to_retain": false } ] } ] },
"output": { "age_over_18": { "credential": "mdl", "path": ["org.iso.18013.5.1", "age_over_18"] } }
```

An EU PID in mdoc form uses the doctype and namespace `eu.europa.ec.eudi.pid.1`. The Compose demo has this policy (`age-over-18-mdoc` in [tenants.json](../deploy/compose/config/tenants.json)):

```json
"dcql": { "credentials": [ { "id": "pid", "format": "mso_mdoc",
  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
  "claims": [ { "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"], "intent_to_retain": false } ] } ] },
"output": { "age_over_18": { "credential": "pid", "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"] } },
"allowed_issuers": ["Demo Issuer"]
```

A policy that asks for `mso_mdoc` adds `mso_mdoc` to `vp_formats_supported` in its requests, with the COSE algorithms the adapter accepts.

**What is checked**
- **Issuer.** The MSO's signature, with the algorithm pinned to the signer key's curve (P-256, P-384, P-521, Ed25519, Ed448, and brainpool curves when [enabled](#brainpool-curves)). The digest of every returned element. The docType, and the MSO's validity period. Document signer certificates validate to the policy's `trust_anchors_file` and `trusted_lists`, as for SD-JWT VC, with CRLs when `certificate_revocation` is `crl`. A root certificate sent in the x5chain is ignored, never trusted.
- **The mDL certificate rules.** For the `org.iso.18013.5.1.mDL` doctype, the IACA rules apply too. The document signer carries:
  - the mDL document signer extended key usage and the digitalSignature key usage;
  - the IACA's country, and its state when the IACA has one.

  A returned `issuing_country` or `issuing_jurisdiction` must match the document signer.
- **The holder.** The wallet proves possession of the device key bound in the MSO by signing this request's session transcript (client identifier, nonce, response URI and encryption key). A response made for another request does not verify. A device MAC is not accepted, because the OpenID4VP flow has no reader key to derive it from.
- **The response.** One document per DeviceResponse (HAIP 1.0), of the requested doctype, with status 0.
- **Revocation.** An MSO `status` holding a Token Status List reference (`status_list` with `idx` and `uri`) is checked like an SD-JWT VC's status. The list is fetched in CWT or JWT form, its signer must chain to the policy's status anchors, and `status_policy` decides what an unavailable list means. An MSO `status` with any other mechanism counts as unknown: `require_valid` rejects it, while `reject_known_invalid` accepts it.

**What comes back**
- Only issuer-signed elements. Device-signed elements are checked against the MSO's key authorizations but never returned.
- Values as JSON: dates as their text, byte strings (such as a portrait) as base64url.
- A request for `age_over_NN` is also answered by a nearby attestation, as ISO/IEC 18013-5 intends. `age_over_21: true` satisfies `age_over_18`, and `age_over_16: false` answers it with false. The value is reported under the requested name. If the disclosed attestations contradict each other, for example `age_over_18: false` with `age_over_21: true`, the request gets no answer.

**Naming the issuer.** An mdoc has no issuer identifier of its own. `allowed_issuers` matches either:
- the subject name of the trust anchor the chain validated to (the IACA), in RFC 4514 form such as `CN=Test IACA,C=EU`;
- the name of a trusted-list entity that publishes that anchor, such as `Demo Issuer`.

The document signer's own name is not matched: it changes on every signer rotation, and any trusted anchor could issue a certificate carrying another issuer's name. The result's `credential_evidence` names the anchor.

**Tolerated departures and `mdoc_strict_conformance`.** Some departures from ISO/IEC 18013-5 do not reject the credential. Each one is written to the audit trail as a `conformance_warning` event (outcome `accepted`) with one of these codes:

| Code | When |
| --- | --- |
| `mdoc_device_key_curve_not_in_table_22` | The device key is on P-384. The standard allows P-384 for issuer signatures but does not list it for device keys |
| `mdoc_signer_validity_over_457_days` | For the mDL: the document signer certificate is valid for longer than the certificate profile allows |
| `mdoc_signer_without_crl_distribution_point` | For the mDL: the document signer certificate has no CRL distribution point |
| `mdoc_x5chain_includes_root` | The x5chain carries a root certificate, which was ignored |

Set `"mdoc_strict_conformance": true` on a policy to refuse P-384 device keys (`unsupported_key`) instead of warning. The certificate profile duties stay warnings in either mode: they are the issuer's to meet.

**Rejection reasons specific to mdoc**
- `holder_binding_invalid`: the device signature does not verify for this request, a device MAC was sent, or a device-signed element is not authorized.
- `unprocessable_presentation`: the DeviceResponse reports a non-zero status.
- `credential_mismatch`: the MSO's docType differs from the document, or `issuing_country` or `issuing_jurisdiction` differs from the certificate.
- `malformed_credential`: the presentation is not valid CBOR or lacks a mandatory part.
- `credential_revoked`, `credential_suspended` and `credential_status_unknown`: as for SD-JWT VC, from the MSO's status.

All other reasons are the same as for SD-JWT VC.

### Brainpool curves

ISO/IEC 18013-5 lets mdoc signatures use the brainpool curves (brainpoolP256r1, P320r1, P384r1, P512r1). The JDK cannot verify them, so they need BouncyCastle, which ships in the opt-in `adapter-crypto-brainpool` module. The service image carries it, turned off. Set `EUDIW_CRYPTO_BRAINPOOL=true` (`eudiw.crypto.brainpool`) to turn it on, with the chart through `extraEnv`; the startup log says so. BouncyCastle is then used only where a brainpool key is involved, and everything else keeps the JDK's providers ([ADR-012](adr/0012-mdoc.md)). In a Java application using `adapter-core` directly, add `io.github.su-engineering:adapter-crypto-brainpool` and call `BrainpoolSupport.enable()` once at startup.

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

Each node fetches the lists at startup and then every refresh interval. A list must be signed by one of its configured certificates and be within its issue and next update times, and its sequence number may not go backwards. The same sequence number is accepted again only if the list's services and pointers are unchanged. One refresh follows at most 64 pointers from a list of lists and stops fetching after five minutes; a list skipped this way keeps its last verified version until its next update. If a refresh fails, the last verified version stays in use until its next update and is then dropped, so trust fails closed. The highest accepted sequence number of each list is kept in the database. A node reports not ready on `/health/ready` until its first refresh has run. After that, a policy with no current list rejects every presentation and is named in the `trusted-lists` health check data and in the log, but the node stays ready for other policies.

No list, list location or signer certificate is bundled with the service. Take them from the publishing body.

Changing the file changes its revision. Sessions started under a previous revision are not served under different rules: their wallet requests return 404.
