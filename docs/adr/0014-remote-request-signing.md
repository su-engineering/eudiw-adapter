# ADR-014: Request signing with a key service (Vault Transit)

Status: accepted, implemented for HashiCorp Vault Transit. Amends [ADR-009](0009-hsm-request-signing.md).

## Context

ADR-009 keeps the request-signing key in an HSM or KMS through PKCS#11. Many operators run HashiCorp Vault and would rather sign with its Transit engine than install a PKCS#11 library. A key service is reached over the network, signs one request object per wallet fetch, and can rotate its keys on its own schedule.

## Decision

1. **One signing interface.** The service asks a `RequestSigner` for an ES256 signature (`R || S`) and nothing else. In-memory keys, PKCS#11 and Vault Transit implement it. `verifier.vault_transit` is a third, mutually exclusive key source next to `private_key_file` and `pkcs11`.
2. **Vault Transit over its HTTP API, without an SDK.** The digest is computed in the service and sent with `prehashed=true` to `POST /v1/<mount>/sign/<key>/sha2-256`. With `marshaling_algorithm=jws`, Vault returns the signature already in JOSE form. The key type must be `ecdsa-p256`. Requests have a 5 second connect and a 10 second overall timeout and do not follow redirects.
3. **The token is read from a file on every signature.** Vault Agent or a CSI driver renews or replaces it without a reload. The file is checked when the configuration loads but is not part of the configuration revision: each replica has its own token, and a renewal would otherwise give every replica a different revision and break sessions across them. The token never appears in logs or error messages; Vault's own error text (such as `permission denied`) does.
4. **Every signature is checked against the certificate.** The startup probe of ADR-009 still runs. In addition, each signature is verified with the end-entity certificate before it is used, because a Transit key can be rotated after startup: requests signed with the new version would fail at every wallet. Rotation therefore fails closed until the certificate is replaced. `key_version` pins a version so that rotation in Vault does not affect the adapter.
5. **A signing failure is a 503 to the wallet**, with `Retry-After: 5`, and the cause is logged with the tenant. The fetch still counts towards the session's request fetch limit.
6. **HTTPS in production.** An `http://` Vault address is refused when `EUDIW_PRODUCTION=true`. The Vault client is configured by the operator, so it does not go through the egress guard for wallet-supplied URLs, which would refuse the private address Vault usually has; it trusts the JVM's CA certificates.

## Consequences

- Tested against a real Vault server (`hashicorp/vault:1.21.1`, dev mode) in CI: signing, the startup probe with a mismatched certificate, a token replaced between signatures, rotation with and without a pinned version, a non-EC key, an unreachable server, and a token renewal that leaves the revision unchanged. Not run against Vault Enterprise namespaces or HCP Vault.
- Every request object fetch is a network round trip to Vault. Its latency adds to the wallet's fetch.
- Token authentication only. Kubernetes or AppRole login is left to Vault Agent, which writes the token file.
- AWS KMS and other key services can implement the same interface; each needs its own decision on dependencies, since ADR-009 avoided vendor SDKs.
