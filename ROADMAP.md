# Roadmap

What is planned for eudiw-adapter after the first release, in order. Nothing here has a date. Items move up or down as specifications settle and as people using the adapter tell us what they need: open an issue or a discussion if something here matters to you, or if something is missing.

Each item is built the way the rest of the adapter is (see the [delivery plan](docs/pr-plan.md)): read the governing specification, write fixtures that include material from someone else (worked examples, published test vectors, an independent implementation), then implement until they pass. The [feature matrix](docs/standards-matrix.md) changes only when the tests do.

## Released

The first release covers SD-JWT VC over OpenID4VP 1.0 and HAIP 1.0, DCQL, ETSI trusted lists, Token Status Lists and CRLs, signed webhooks, HSM and KMS request signing, relying-party registration in `verifier_info`, metrics, audit, tracing, rate limits, configuration reload, the Helm chart, and the `<eudiw-request>` web component with Node and Python examples. See the [changelog](CHANGELOG.md).

## Next

1. **ISO mdoc, second edition.** 0.2.0 verifies mdocs end to end, including revocation through a Token Status List reference. Once the second edition of ISO/IEC 18013-5 is published, check it against what was built and add any status mechanism it defines beyond that.
2. **Digital Credentials API with a phone wallet.** The server side, `<eudiw-request>` and the examples support the API, tested in Chromium against eudi-dev's extension in CI ([ADR-017](docs/adr/0017-digital-credentials-api.md)). Next: a phone wallet through a platform's API (Android Credential Manager, iOS), and its results in the [wallet table](docs/wallets.md).
3. **The EU reference wallet on real devices.** Run the adapter against the EU reference wallet apps on Android and iOS, first on emulators and simulators, then on phones, and publish what was run.
4. **More independent wallets.** walt.id Wallet API 2 now runs next to eudi-dev in CI with SD-JWT VC and mdoc. Next: other wallets that can run without a person. The [wallet table](docs/wallets.md) lists what has been tested so far.
5. **OCSP**, alongside the existing CRL checks.

## Later

6. **Wallet and key attestation.** Check the attestations a presentation carries where HAIP and the ARF let a verifier rely on them.
7. **Transaction data for ISO mdoc.** SD-JWT VC transaction data is done ([ADR-016](docs/adr/0016-transaction-data.md)). For mdoc, OpenID4VP binds it through data elements each transaction data type defines; implement the first type that wallets support.
8. **OpenID Foundation certification.** The HAIP verifier test plan runs in CI on every change; certification needs the hosted suite.
9. **External security review** of the verifier and the service.
10. **Registration in the demo.** The registration certificate is tested against a strict wallet in CI; the Compose demo does not send one yet.
11. **ETSI TS 119 472-2 RO-17** (the `etsi_tl` Authority Key Identifier), once its meaning in that clause is clear.
12. **An admin API** for reading the active configuration and triggering a reload. Today configuration is reloaded from files.

## Exploring

These depend on how the specifications and the EU framework settle. They are not commitments.

- **Zero-knowledge proofs for age**, following the work in the ARF.
- **DID-based trust** for issuers outside ETSI trusted lists.
- **OpenID4VCI.** Issuance is a different product; it stays out of the adapter unless there is clear demand.
