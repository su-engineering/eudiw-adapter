# Examples

Two small relying-party backends with the same behaviour, one in Node (22 or later) and one in Python (3.10 or later). Both use only the standard library and serve one page with the [`<eudiw-request>`](../clients/web) component.

| Route | What it does |
| --- | --- |
| `POST /verifications` | Gets an access token (client credentials), creates a session at the adapter with an `Idempotency-Key`, and returns the launch URI plus status and result URLs keyed by a random local id |
| `GET /verifications/{id}/status` | Returns only `{"status": ...}` from the adapter |
| `POST /verifications/{id}/result` | Retrieves the result once. A real application acts on the claims on the server |
| `POST /webhooks/eudiw` | Verifies a [Standard Webhooks](https://www.standardwebhooks.com/) signature over the raw body with a constant-time comparison and a five-minute timestamp tolerance, accepting the previous secret during a rotation |

## Run against the demo

```sh
./deploy/compose/demo.sh                # starts PostgreSQL, Keycloak and the adapter
node examples/node/server.mjs           # http://localhost:3000
python3 examples/python/server.py       # http://localhost:3001
```

Open the page and select "Verify with my wallet". Answer the QR code with a wallet that trusts the demo's relying-party certificate, or with the test wallet:

```sh
cd deploy/compose && docker compose run --rm wallet '<launch URI>'
```

`examples/e2e.sh` does this for both backends and checks that only `age_over_18` comes back. CI runs it after the demo.

## Settings

Environment variables, with the demo's values as defaults: `ADAPTER_URL`, `TOKEN_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `POLICY_ID`, `PORT`, and `WEBHOOK_SECRET` (plus `WEBHOOK_PREVIOUS_SECRET` during a rotation) in the `whsec_` form configured for the client in the adapter.

## Webhook vector

`shared/webhook-vector.json` is a signed notification during a secret rotation. The service test `WebhookVectorTest` checks that the adapter's signer produces exactly this signature, and both examples' tests verify it, so the example verifiers are tested against the real sender.

These are examples, not production code: sessions live in memory and there is no user login.
