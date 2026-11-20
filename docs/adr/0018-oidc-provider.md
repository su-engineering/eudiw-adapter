# ADR-018: The adapter as an OpenID Connect provider for wallet login

Status: accepted. Provider implemented and tested inside the service; Keycloak (as a broker) and Nextcloud (`user_oidc`) log in through it end to end in CI. Other identity providers and applications are documented but not tested ([integration guide](../oidc-provider.md)).

## Context

The verification API answers "is this person over 18" for a backend at a given moment. Many services want something else: "log in with the EU Digital Identity Wallet" in an application that already has a login, such as Nextcloud. Those applications and the identity providers in front of them (Keycloak, Ory, Authentik, Zitadel, Auth0, Okta, Microsoft Entra ID) all have one integration point in common: they can add an external OpenID Connect provider from their settings, with an issuer URL, a client id and a secret. None of the SaaS providers can load a plugin.

We considered a Keycloak authenticator extension that calls the verification API. It works only for Keycloak, needs a Keycloak-specific account-linking design, and adds a second deployable. [keycloak-oid4vp](https://github.com/su-engineering/keycloak-oid4vp) already covers wallet login inside Keycloak for teams that want verification there.

## Decision

1. **A minimal OIDC provider inside the service.** Each tenant can be an issuer at `{public base url}/oidc/{tenant}`, with discovery, JWKS, authorization, token and userinfo endpoints. It supports the authorization code flow with confidential clients (`client_secret_basic`, `client_secret_post`) and nothing else: no implicit or hybrid flows, no refresh tokens, no dynamic registration, no request objects, no logout. It holds no login session, so every authorization is a fresh wallet presentation, `prompt=none` returns `login_required`, and there is nothing to log out of.
2. **A client is a client application with an `oidc` block.** It names the login policy, the redirect URIs (compared exactly), the claims that make up the subject and the claims that go into the ID token. The verifier, trust lists, status checks, registration (`verifier_info`), request signing, rate limits and audit trail are the same as for the verification API. Off unless configured.
3. **The login runs a cross-device verification session.** `/authorize` validates the request, creates the session and answers with a login page served by the adapter: the `<eudiw-request>` component with the QR code and "open the wallet on this device". The same launch link works on the phone itself: the wallet posts its response and the user returns to the browser tab. The page polls a status endpoint that only the browser holding the login's cookie can read (`__Host-` prefixed, `HttpOnly`, `SameSite=Lax`). Once the session is verified, the first poll consumes the result, derives the subject and issues the code; the status then carries the redirect to the client.
4. **The subject is pairwise and derived from configured claims.** `sub` is HMAC-SHA256 under a per-tenant subject key over the client id and the values of `subject_claims`. Two clients see different subjects for the same person; the same person gets the same subject on every login, also after their wallet's credential is reissued, as long as those claims do not change. A presentation that lacks a subject claim does not log in. Account linking stays in the customer's identity provider, which already does it.
5. **No subject from personal attributes by accident.** The ARF makes `personal_administrative_number` optional for each member state, and wallets present batch-issued credentials with a different holder key each time, so there is no guaranteed persistent identifier. `subject_claims` without a persistent identifier (today: `personal_administrative_number`) fail at startup unless `subject_from_personal_attributes` is `true`: names and birth date can join two people into one account, and change.
6. **No claims that identity providers link on.** `email`, `email_verified`, `preferred_username`, `phone_number` and `phone_number_verified` cannot be mapped into the ID token, because brokers link or create accounts on them.
7. **A separate ID token key.** ID tokens are signed with RS256, the algorithm OpenID Connect Core requires providers to support and many identity providers accept exclusively, with an RSA key of its own (`kid` = JWK thumbprint). The wallet request key is never used for it.
8. **Codes and tokens.** Codes are 256-bit random values, stored as hashes, valid for 60 seconds, single use. A code presented again revokes the access token it produced. PKCE `S256` is required unless a client sets `pkce: optional`; a verifier without a challenge is refused. Access tokens serve userinfo only and live 5 minutes. The authorization response carries `iss` (RFC 9207).
9. **Bearer tokens are checked when an endpoint needs the caller.** Quarkus no longer authenticates every request proactively, so userinfo can receive its own access tokens; management endpoints still require a valid management token through the same check as before.

## Consequences

- An application or identity provider adds wallet login by pasting three values. The [integration guide](../oidc-provider.md) lists, per product, what is tested.
- The adapter now serves pages to browsers: the login page, with a strict Content Security Policy, `frame-ancestors 'none'` and only the adapter's own scripts. The [threat model](../threat-model.md) covers it.
- Cross-device relay: someone who starts a login can show its QR code to another person and receive their identity if that person presents. The wallet shows the relying party's registered name; the Digital Credentials API's cross-device flow, which checks proximity, is the mitigation we will add to the login page once it is tested with a phone wallet.
- Nextcloud's `user_oidc` hashes provider and user id by default, so a wallet login cannot collide with an existing Nextcloud account; it creates a new one. Linking existing accounts needs an identity provider in front.
- Tenants without `oidc_provider` are unchanged. Migration `V8` adds one table.

## Not done

- The OpenID Foundation's OP conformance tests have not been run against the provider.
- The Digital Credentials API on the login page.
- Signing ID tokens with a key in an HSM, Vault or KMS (the wallet request key supports all three).
- More than one ID token key at a time for rotation; replace the key between logins and expect brokers to refetch the JWKS.
