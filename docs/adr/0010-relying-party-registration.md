# ADR-010: Relying-party registration in requests

Status: accepted, implemented.

## Context

Under Implementing Regulation (EU) 2025/848 every relying party registers its intended uses with a national registrar. The wallet shows the user who is asking and why, and refuses requests that ask for more than was registered ("over-asking").

- OpenID4VP 1.0 section 5.11 defines `verifier_info`, an array of attestations about the verifier in the Request Object, and leaves the formats to ecosystems.
- ETSI TS 119 472-2 V1.3.1 clause 6.3.2.2 profiles it for the EUDI Wallet. The Request Object must carry a `registrar_dataset` element with the registrar's data about the intended use (RO-01 to RO-12). If the relying party has a registration certificate, a `registration_cert` element with its base64url encoding is added (RO-13 to RO-16). Neither element has `credential_ids`.
- ETSI TS 119 475 V1.2.1 clause 5.2 defines the registration certificate: a JWT with `typ` `rc-wrp+jwt` and an `x5c` chain, signed by a registration certificate provider, whose payload names the relying party (`sub`), its intended use and the credentials and claims it may request.

## Decision

1. **Per policy.** A registration covers one intended use, and a policy is one intended use here, so `registration` is configured on the policy.
2. **The dataset is the operator's input; the certificate is a third party's artefact.**
   - The dataset is sent as configured, after checking the members TS 119 472-2 requires.
   - The certificate is parsed, not validated against a trust framework: its signature and its provider's place on a trusted list are for the wallet to check. Startup stops only when it is not a compact JWS with `typ` `rc-wrp+jwt`, `x5c`, `sub` and `iat`, or when it has expired.
   - TS 119 475 is not consistent about some members (the intermediary as `intermediary.sub` or `act.sub`, `status` as a URI or an object). The parser accepts both intermediary forms and does not interpret the others.
3. **Over-asking is caught before a wallet sees it.** The policy's DCQL query is compared with the declared credentials: same `format`, every requested type in the declared `meta`, every requested claim path equal to a declared one. A declared credential without claims declares none.
   - Against the dataset's `credential` list, a mismatch stops startup: the operator controls both.
   - Against the certificate's `credentials`, a mismatch is logged: the certificate cannot be edited, and the wallet makes the decision.
4. **Intermediaries are allowed.** A hosted adapter can act as an intermediary, presenting its own access certificate with the final relying party's registration certificate. The certificate's `sub` or its intermediary identifier is compared with the access certificate's `organizationIdentifier` or `serialNumber` (TS 119 475 clause 5.1), and a mismatch is logged, not refused.
5. **An expired certificate is never sent.** From its `exp` on, requests carry only the dataset, from which the wallet can query the registrar (TS 119 472-2 clause 6.3.2.2, note 2). `/health/well` reports certificates within 30 days of expiry and expired ones, without affecting readiness.
6. **Encoding follows RO-16**: base64url of the serialized JWT.

## Consequences

- Tested with synthetic certificates only. No real registrar has issued one for this project.
- The independent eudi-dev wallet v3.8.0, in `--haip --arf --mode strict`, accepts a request carrying both elements, fetches the certificate's status list and checks it for over-asking. It refuses the request when the certificate chains to an untrusted provider, and when the certificate lacks members TS 119 475 requires. The second finding led to the startup warning for missing members.
- RO-17 (the Authority Key Identifier using the `etsi_tl` mechanism) is not addressed: its meaning in this clause is unclear and it is left until clarified.
- The registration certificate's own status is not checked by the service.
- Rotation needs a restart until configuration can be reloaded.
