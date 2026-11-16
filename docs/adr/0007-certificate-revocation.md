# ADR-007: Issuer certificate revocation

Status: accepted. CRL checking is implemented; OCSP is not.

## Context

An issuer's signing certificate, or a CA above it, can be revoked before it expires. Token Status Lists cover individual credentials, not the certificates that sign them. RFC 5280 offers CRLs and OCSP (RFC 6960).

The JDK can evaluate both, but its own fetching would bypass the service's egress policy: it fetches from distribution points or OCSP responders found in the certificates themselves. Building and parsing OCSP requests and responses needs either JDK internal classes or a library such as BouncyCastle at runtime. `adapter-core` depends only on Nimbus JOSE+JWT and the JDK.

## Decision

1. **CRLs, per policy, opt-in.** `certificate_revocation: "crl"` checks every certificate of the issuer chain except the trust anchor. The default is `off` so existing configurations do not change behavior. Turn it on wherever the issuer PKI publishes CRLs.
2. **Fetching goes through `HttpFetcher`, and only after the chain validates**, so the distribution point URLs come from certificates a trusted CA issued. Plain HTTP is allowed for CRLs because they are signed; private, loopback and link-local addresses stay blocked.
3. **The JDK evaluates the CRLs.** `PKIXRevocationChecker` runs with `PREFER_CRLS` and `NO_FALLBACK` over the fetched CRLs only. It checks the CRL signature against the issuer, issuer name matching, reason coverage and the revocation entry. It does not fetch anything itself and does not try OCSP.
4. **Fail closed.** Each of these is `certificate_status_unknown`, and the presentation is rejected:
   - a certificate without an HTTP distribution point;
   - an unreachable or unparsable CRL;
   - a CRL without a next update, or past it;
   - a CRL that does not verify.
   A listed certificate is `certificate_revoked`.
5. **Caching.** CRLs are cached per policy until their next update, at most 256 per policy.
6. **A directly trusted certificate** (a trusted list naming the issuer's own certificate) has no issuer in the path, so nothing is checked. The list itself is the revocation mechanism: removing the certificate from the list revokes it.
7. **OCSP is not implemented.** Adding it means either an OCSP client written against RFC 6960 with a DER encoder and decoder, or a separate optional module that brings BouncyCastle at runtime. Either needs its own review. Neither is started.

## Consequences

- Revocation is checked for the issuer chain of credentials, not yet for the chain of status list tokens.
- Indirect CRLs (a distribution point with a `cRLIssuer`) and delta CRLs are not fetched. A PKI that relies on them shows as `certificate_status_unknown`.
- The tests issue certificates and CRLs with BouncyCastle (test scope only) and verify them with the JDK, two independent implementations.
