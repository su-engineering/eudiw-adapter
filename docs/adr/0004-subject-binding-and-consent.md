# ADR-004: Subject binding and consent

Status: proposed.

## Context

A verified presentation proves that a wallet holder controls a credential from a trusted issuer. It does not prove that the holder is the owner of a pre-existing account in the calling application, and two credentials in one presentation do not prove they describe the same person.

Linking a credential to an account on display names, email or an identifier that is unique only per issuer, without the issuer in the key, is a known account-takeover path.

## Decision

1. The standalone API returns **claims and evidence, never an account decision**. Linking a result to a local account is the calling application's responsibility, documented with the anti-takeover checks it needs (issuer-scoped identifiers, no linking on display names or email alone).
2. Where a policy requests several credentials, the policy must name a correlation rule (for example the same issuer-scoped subject identifier). Without one, the result lists credentials separately and the API never states that they share a subject.
3. **Consent to disclose** is collected by the wallet. The adapter's job is to request only what the approved policy allows; callers cannot add claims at request time.
4. The `client_reference` field is correlation data for the caller. It is not stored in audit events in clear text and never becomes a subject identifier.

## Consequences

- No "find or create user" feature in the standalone service.
- Issuer service (later) uses an external authorization server for user authentication and consent; it does not infer a subject from a presentation.
