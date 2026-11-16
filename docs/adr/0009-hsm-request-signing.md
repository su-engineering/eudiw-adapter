# ADR-009: Request signing keys in an HSM or KMS

Status: accepted, implemented for PKCS#11.

## Context

Each tenant's request-signing key is its relying-party identity towards wallets. Until now it was a PKCS#8 file. Operators with an HSM, a cloud HSM or a cloud KMS want the key never to leave it.

## Decision

1. **PKCS#11 through the JDK.** The service loads the key through the SunPKCS11 provider from a configured library, slot and key label, with the PIN read from a file. Any HSM, cloud HSM or KMS that provides a PKCS#11 library can be used this way without adding a vendor SDK to the build. Only SoftHSM has been tested.
   - The token must hold the certificate as a certificate object with the same label and ID as the key. The JDK's PKCS#11 key store does not list a private key without one, and startup then fails with `no private key with label ...`.
2. **Plain ECDSA in the token.** The SHA-256 digest of the JWS signing input is computed in the service, and the token performs plain ECDSA (`CKM_ECDSA`). Every HSM offers that mechanism, while hashed mechanisms vary: SoftHSM fails the one the JDK selects for `SHA256withECDSA`. The DER result is converted to the JOSE `R || S` form.
3. **Prove the key at startup.** A probe is signed with the key and verified with the configured certificate. A wrong label or a key that does not match the certificate stops startup instead of producing requests wallets reject.
4. **One provider per library and slot**, created once per JVM, since a PKCS#11 library is initialized once per process.

## Consequences

- The PKCS#11 library must be present in the container image or mounted into it. The Dockerfile does not include one, and it uses a glibc base (`eclipse-temurin` on Ubuntu), because vendor libraries are generally built for glibc and cannot load on musl.
- Only EC P-256 keys (ES256, as HAIP 1.0 requires) are supported.
- Tests generate a non-extractable key inside SoftHSM, sign a request object and verify it with the certificate. CI installs SoftHSM and fails if the test would skip.
- The Compose demo, which also runs in CI, keeps the verifier key in SoftHSM inside the service image. The independent eudi-dev wallet accepts the request objects signed with it.
