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

Open the page and select "start a check". Answer the QR code with a wallet that trusts the demo's relying-party certificate, or with the test wallet:

```sh
cd deploy/compose && docker compose run --rm wallet '<launch URI>'
```

### Webhooks in the demo

The demo client sends webhooks to `http://host.docker.internal:3000/webhooks/eudiw`, signed with a secret the demo generates. To receive them, start a backend on port 3000 with that secret:

```sh
export WEBHOOK_SECRET=$(cd deploy/compose && docker compose run --rm --no-deps -T --entrypoint cat keygen /keys/webhook-secret)
node examples/node/server.mjs                 # or: PORT=3000 python3 examples/python/server.py
```

The backend checks the signature and adds the notification to the session's trace. The page shows it when it arrives before the result is fetched; the adapter sends webhooks every `EUDIW_WEBHOOK_INTERVAL` (5 seconds by default). Without the secret it answers 401 and the adapter retries with backoff, which is harmless. On Linux, also set `HOST=0.0.0.0`: a container reaches the host only on a non-loopback address, so the backend has to listen on one (keep it behind a firewall).

`examples/e2e.sh` does all of this for both backends and checks that the webhook arrives with a valid signature and that only `age_over_18` comes back. CI runs it after the demo.

`examples/render/check.sh` opens the page in Chromium (in the Playwright container), decodes the QR code as drawn on screen with `zbarimg`, checks the vendored font is in use, and answers with the test wallet until the page shows the verified state. CI runs it and keeps the screenshots.

### The Digital Credentials API

In a browser with the W3C Digital Credentials API, the page also offers "use a wallet on this device". The backend then creates a `dc_api` session for the page's origin (the `Origin` header of the page's request), the `<eudiw-request>` component calls `navigator.credentials.get()`, and the backend relays what the browser returned to the adapter (`POST /verifications/{id}/dc-api`). The demo client allows `http://localhost:3005` and `http://localhost:3006` in `dc_api_origins`; add your page's origin, such as `http://localhost:3000`, to `deploy/compose/config/tenants.json` to try it from the example's default port. Without a wallet on the device, eudi-dev's browser extension can answer (`eudi wallet browser`). `deploy/compose/dc-api/run.sh` runs this page that way in CI.

## Settings

Environment variables, with the demo's values as defaults: `HOST` (default `127.0.0.1`), `ADAPTER_URL`, `TOKEN_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `POLICY_ID`, `PORT`, and `WEBHOOK_SECRET` (plus `WEBHOOK_PREVIOUS_SECRET` during a rotation) in the `whsec_` form configured for the client in the adapter.

## Webhook vector

`shared/webhook-vector.json` is a signed notification during a secret rotation. The service test `WebhookVectorTest` checks that the adapter's signer produces exactly this signature, and both examples' tests verify it, so the example verifiers are tested against the real sender.

These are examples, not production code: sessions live in memory and there is no user login.
