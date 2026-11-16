# ADR-006: Trusted lists

Status: accepted, implemented.

## Context

[ADR-002](0002-trust-sources-and-policy.md) decision 4 requires signed trusted lists. Two ETSI formats matter for EUDI relying parties:

- ETSI TS 119 602 V1.1.1 lists of trusted entities. Its Annexes D to I profile the EU lists of PID providers, wallet providers, access and registration certificate providers, public sector EAA providers and registrars. Annex D requires the JSON binding signed with a compact JAdES baseline B signature (ETSI TS 119 182-1 V1.2.1).
- ETSI TS 119 612 V2.4.1 XML trusted lists with an enveloped XAdES baseline B signature, and the EU list of trusted lists (LOTL) that points to the national lists. Qualified EAA providers appear here with service type `http://uri.etsi.org/TrstSvc/Svctype/EAA/Q`.

## Decision

1. **Both bindings, one model.** `TslXmlParser` and `LoteJsonParser` produce the same `TrustedList`: issue time, next update, sequence number, services (type, status, certificates) and pointers. TS 119 602 Annex A.2.2 maps the fields.
2. **The signer is pinned.** The signing certificate must equal one configured for that list. For a national list reached through the LOTL, it must equal one the LOTL pointer publishes. The pin is checked before any signature computation with the certificate's key. No PKIX path is built to a list signer. The TS 119 612 rule that the signer's subject `C` and `O` match the scheme territory and operator name is not enforced: pinning already authenticates the signer, and enforcing the name rule would only reject lists the operator chose to trust.
3. **XML signature handling is strict.**
   - The parser refuses DTDs and external entities.
   - There must be exactly one `ds:Signature`, and it must be a direct child of the root.
   - Canonicalization must be exclusive c14n.
   - One reference must cover the whole list (`URI=""` or the root `Id`) with exactly the enveloped and exclusive c14n transforms (TS 119 612 Annex B).
   - Only same-document references are accepted, and this is checked before validation, so nothing is fetched.
   - Validation runs in the JDK's secure validation mode.
   - Values are read only from the element the signature covers.
4. **JAdES handling is strict.**
   - The signer comes from `x5c`, or is matched by `x5t#S256`. When both are present they must agree.
   - `sigD` (detached signatures) and `b64: false` are rejected.
   - `crit` may list only `sigT`.
   - RSASSA-PKCS1-v1_5 is accepted for list signatures only, because ETSI TS 119 312 still allows it. Credentials never accept it.
5. **Freshness fails closed.**
   - A list must be within its issue and next update times, and next update may be at most six months after issue.
   - A closed list (no next update) contributes nothing.
   - A list that fails to refresh keeps its last verified version only until that version's next update.
   - A national list is trusted only while a current LOTL still points to it and still publishes its signing certificate. When the LOTL drops the pointer or rotates the signer, or no current LOTL is left, the national list is dropped at once.
   - A lower sequence number than the highest accepted one is refused as a rollback. The service keeps the highest sequence number per list identifier in PostgreSQL, so a restart or another node does not accept an older list. The record is shared by every policy that names the same identifier, which is intended: the same identifier means the same list.
   - A list that fails in any way, including an unexpected exception, is reported as failed without stopping the other lists or policies.
6. **Services become anchors by type and status.**
   - Each list source names the service types whose certificates may anchor credential issuers, and optionally further types that may anchor status list tokens (for example `PID/Revocation`).
   - Issuance types may always anchor status lists. Revocation types never anchor credentials.
   - A service without a status counts as approved (TS 119 602 clause 6.6.0). A service with a status counts only if its status is accepted: by default `granted`, `recognisedatnationallevel` and the public sector EAA `notified`.
7. **Direct trust of a listed end-entity certificate.** When a list names the issuer's own certificate, an `x5c` of exactly that one certificate is accepted after validity and key usage checks. A longer chain that contains a trusted certificate is still refused (HAIP 1.0).
8. **Provenance for `etsi_tl`.**
   - Every trusted certificate remembers the identifier of the list that named it.
   - For lists reached through the LOTL, it also remembers the LOTL's identifier.
   - DCQL `trusted_authorities` of type `etsi_tl` match on these identifiers.
   - The identifier defaults to the list location and can be set separately when the operator serves a local mirror.
9. **Refresh is per node** on a schedule (default hourly), through the same egress policy as status lists, with a 30 second timeout because national lists run to several megabytes. A node is not ready until its first refresh has run. After that it stays ready even when one policy has no current list: that policy's verifications fail closed and the health check and log name it, while other tenants keep working.

## Consequences

- The tests use synthetic lists only. Real EU lists and the Official Journal signer certificates are not bundled; operators configure them. No real list has been run through the parser in this repository yet.
- The JDK XML signature implementation creates and verifies the test lists, so those tests are not independent of the verifier. An external vector (a published list) is still needed.
- The tests include the XAdES shape published lists use (a second reference to `SignedProperties` in a `ds:Object`), a forged root that wraps a genuine signed list, and 3,000 mutated lists that must fail only with coded errors.
- Historical validation (service history, status at a past time) is not implemented: trust is evaluated at the current time only.
- XAdES qualifying properties (signing time, signing certificate digest) are not evaluated beyond the core XML signature; the pinned `ds:KeyInfo` certificate is what authenticates the list.
