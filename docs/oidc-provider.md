# Wallet login for applications and identity providers

eudiw-adapter can act as an OpenID Connect provider: an application, or the identity provider in front of it, adds "EU Digital Identity Wallet" the way it adds any other OpenID Connect login. The user scans a QR code (or opens the wallet on the same phone), presents a credential such as a PID, and comes back logged in. The design and its limits are in [ADR-018](adr/0018-oidc-provider.md).

## What the provider does

- Authorization code flow with PKCE, for confidential clients. Discovery at `{EUDIW_PUBLIC_BASE_URL}/oidc/{tenant}/.well-known/openid-configuration`.
- Every login is a fresh wallet presentation: no provider session, no refresh tokens, no logout.
- The ID token (RS256) carries a pairwise `sub` derived from the claims you choose (for example issuing country and personal administrative number) and the claims you map, such as `given_name` and `family_name`. It never carries `email` or `preferred_username`.
- The same trust lists, status checks, registration (`verifier_info`), request signing keys (file, HSM, Vault or AWS KMS), audit trail and metrics as the verification API.

## Set up the provider

1. In the tenants file, give the tenant an `oidc_provider` with an ID token key and a subject key ([configuration](configuration.md)).
2. Add a login policy whose query asks for the identifying claims, for example from the PID: `issuing_country`, `personal_administrative_number`, `given_name`, `family_name`.
3. Add a client with an `oidc` block: a client secret file, the redirect URI your application or identity provider gives you, the login policy, `subject_claims` and `id_token_claims`.

```json
"oidc_provider": {
  "signing_key_file": "/keys/oidc-id-token-key.pem",
  "subject_key_file": "/keys/oidc-subject-key"
},
"clients": [{
  "client_id": "keycloak-broker",
  "policies": ["pid-login"],
  "oidc": {
    "client_secret_file": "/keys/oidc-broker-secret",
    "redirect_uris": ["https://login.example/realms/shop/broker/eudi-wallet/endpoint"],
    "policy_id": "pid-login",
    "subject_claims": ["issuing_country", "personal_administrative_number"],
    "id_token_claims": { "given_name": "given_name", "family_name": "family_name" }
  }
}]
```

Then, in the application or identity provider, add an OpenID Connect provider with:

| Setting | Value |
| --- | --- |
| Issuer / discovery URL | `https://adapter.example/oidc/{tenant}` (append `/.well-known/openid-configuration` where a discovery URL is asked for) |
| Client id | the `client_id` |
| Client secret | the content of `client_secret_file` |
| Scopes | `openid` |
| PKCE | on, `S256` |
| Client authentication | client secret (basic or post) |

Users must be able to reach the adapter's public URL from their browser, and the identity provider must reach it for the token, userinfo and JWKS endpoints.

## Accounts and linking

The adapter does not keep accounts. It gives the same `sub` to the same person on every login, as long as the subject claims do not change, and a different `sub` to each client. Linking that identity to an account is the job of the identity provider or application, which already does it for every other external login:

- **New users:** the identity provider creates an account on the first wallet login. It may ask the user for attributes the wallet does not provide, such as an email address.
- **Existing users:** the identity provider's account-linking flow attaches the wallet to an account after the user signs in once the usual way. Do not let it link automatically on email or username: the adapter never sends them, and a provider that links on a claim the user controls hands over accounts.

The subject is not tied to the credential's issuer: any issuer the login policy trusts can assert any country and number. Let a login policy trust only PID providers, for example through a trusted list limited to the PID issuance service type.

Which claims make a good subject depends on the credential. `personal_administrative_number` is optional in the PID and each member state decides whether to include it. Without a persistent identifier you can set `subject_from_personal_attributes` and use, for example, issuing country, family name, given name and birth date, but then two people with the same values share one account and a name change creates a new one.

## Products

"Tested" means a run in this repository's CI. Everything else is documentation from the product's own settings and has not been run here; open an issue with what you find.

| Product | How to add the adapter | Status |
| --- | --- | --- |
| Keycloak 26.8 | Identity providers, OpenID Connect v1.0: discovery URL, client id and secret, PKCE `S256`, client authentication "Client secret sent as basic auth". The redirect URI is `https://{keycloak}/realms/{realm}/broker/{alias}/endpoint`. The default first-login flow asks for the email address. | Tested: [`deploy/compose/oidc/run.sh`](../deploy/compose/oidc/run.sh) in the `demo` job logs in twice through Keycloak's account console with the eudi-dev wallet and checks that both logins reach one account linked to the provider |
| Nextcloud 35 (`user_oidc` app) | Administration settings, OpenID Connect, or `occ user_oidc:provider <name> --clientid=... --clientsecret=... --discoveryuri=https://adapter.example/oidc/{tenant}/.well-known/openid-configuration`. Register `https://{nextcloud}/index.php/apps/user_oidc/code` (or without `index.php/` when Nextcloud uses pretty URLs). `user_oidc` hashes provider and user id into the Nextcloud user id by default, so a wallet login creates a new Nextcloud account on first use (with auto-provisioning on) and never collides with an existing one; to link existing Nextcloud users, put an identity provider such as Keycloak in front. The display name defaults to the user id; map it to `given_name` or `family_name` in the provider settings if you send them. If the adapter has a private address, Nextcloud needs `allow_local_remote_servers`. | Tested: the same run logs in to Nextcloud twice through `user_oidc` and checks that both logins reach one Nextcloud user. The demo has no TLS, so it sets `user_oidc`'s `allow_insecure_http`; never set that in production |
| Ory (Kratos, Ory Network) | A `generic` OIDC provider with `issuer_url`, `client_id`, `client_secret` and `scope: [openid]`, and a Jsonnet mapper from the ID token claims to identity traits. Hydra on its own delegates login to an application you write, so it needs Kratos or your own login app for this. | Not tested |
| Authentik | Federation and social login, OpenID OAuth source, with the discovery URL. | Not tested |
| Zitadel | Identity providers, generic OIDC, with the issuer. | Not tested |
| Auth0 | Authentication, Enterprise, OpenID Connect connection, with the issuer URL, client id and secret. | Not tested |
| Okta | Identity providers, OpenID Connect IdP, with the endpoints from the discovery document. | Not tested |
| Microsoft Entra External ID | Custom OpenID Connect identity provider, with the well-known endpoint. | Not tested |

SaaS identity providers need the adapter reachable on the internet, and several expect an email claim from every upstream provider. Check whether yours can create an account without one, or asks the user for it, before planning a rollout.

## Try it locally

```bash
./deploy/compose/demo.sh        # starts PostgreSQL, Keycloak and the adapter, and runs the verification demo
./deploy/compose/oidc/run.sh    # wallet login through Keycloak's "shop" realm and through Nextcloud, twice each
```

The run writes screenshots of the adapter's login page, Keycloak's first-login form, the account console and the Nextcloud dashboard to `deploy/compose/oidc/out/`. To click through it yourself, open `http://localhost:8081/realms/shop/account/` and choose "EU Digital Identity Wallet"; the login page shows a QR code for a wallet that trusts the demo relying-party certificate. The demo's keys, trust list and credentials are synthetic.

## Security notes

- **QR relay.** Anyone who starts a login can show its QR code to another person; if that person presents, the login completes for whoever started it. The wallet shows the relying party's registered name, so register a name users recognize. The Digital Credentials API's cross-device flow checks that the phone is near the computer and will be offered on the login page once it is tested with a phone wallet.
- The login page runs only the adapter's own scripts under a strict Content Security Policy and cannot be framed.
- Codes are single use and short-lived; PKCE is required by default; redirect URIs are compared exactly.
- An `oidc` client cannot call the management API, so it cannot read the login policy's claims around the pairwise subject.
- A user who presents on the same phone and comes back to the tab late (up to 10 minutes after the request expired) is sent back to the application with an error rather than left on a dead page.
- See the [threat model](threat-model.md) for the full list.
