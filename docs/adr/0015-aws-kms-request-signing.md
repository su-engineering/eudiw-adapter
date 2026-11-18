# ADR-015: Request signing with AWS KMS, through the AWS SDK

Status: accepted, implemented. Amends [ADR-009](0009-hsm-request-signing.md), which avoided vendor SDKs, and builds on [ADR-014](0014-remote-request-signing.md).

## Context

Operators on AWS keep keys in KMS. KMS has no PKCS#11 library of its own (CloudHSM does, at a much higher cost), so ADR-009's route does not reach it. ADR-014 introduced the `RequestSigner` interface, the per-signature certificate check and the 503 on failure; this decision adds a KMS implementation.

## Decision

1. **The AWS SDK for Java v2, in its own module (`adapter-kms-aws`).** AWS request signing (SigV4) and the credential chain, in particular web identity for EKS (IRSA), container and instance credentials, are what operators rely on, and re-implementing them is a larger risk than the dependency. The module keeps the SDK out of `adapter-core`. The service image ships it, like the brainpool module, and it is inert unless a tenant sets `verifier.aws_kms`.
2. **A small client.** Only `kms`, `sts` (for web identity) and the JDK `HttpURLConnection` client: the Netty, Apache 4 and Apache 5 clients are excluded. That is 32 jars, about 6.3 MB, under Apache-2.0, MIT and MIT-0, with no known advisories when added (osv-scanner, 2026-11-18). The Apache 5 client was excluded partly because its `httpcore5` carried advisories at the time.
3. **`MessageType=DIGEST`.** The SHA-256 digest is computed in the service, so any request object can be signed (KMS takes at most 4096 bytes of raw message, and a request object with a certificate chain and registration data can exceed that). KMS returns DER, converted to `R || S`. The key must be `ECC_NIST_P256` with usage `SIGN_VERIFY`.
4. **Credentials are never configured in the adapter.** The SDK's default chain provides them; the tenant names only `key_id` (key id, key ARN, alias or alias ARN), optionally `region` and `endpoint` (a VPC endpoint; `https` in production). Errors carry the KMS error code and HTTP status, not credentials.
5. **Timeouts:** 5 seconds to connect, 10 seconds per call.

## Consequences

- Tested against [local-kms](https://github.com/nsmithuk/local-kms) (an open-source KMS emulator, pinned by digest) in CI: signing a request object over 4096 bytes, signing through an alias, startup refusal when the key does not match the certificate, unknown and non-EC keys, an unreachable endpoint. Not run against AWS itself. LocalStack was not used: its image now requires an account token. moto was not used: its `DIGEST` signatures did not verify in our check, while its `RAW` ones did.
- About 6 MB more in the image for every deployment, and the SDK's release cadence to follow with Dependabot.
- Each configuration load creates a KMS client; a reload replaces it.
