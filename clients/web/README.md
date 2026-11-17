# `<eudiw-request>` web component

Shows an EUDI Wallet request as a QR code with an "open wallet" link, says what is asked and that nothing else leaves the wallet, counts down to expiry, and follows the session until it ends. One ES module, no build step, no dependencies besides a vendored QR encoder and the JetBrains Mono font. It ships in the su.engineering look (charcoal, ivory, signal orange) with a light variant, and every color is a custom property.

```html
<script type="module" src="/eudiw/eudiw-request.js"></script>

<eudiw-request
  launch-uri="openid4vp://?client_id=...&request_uri=...&request_uri_method=post"
  status-url="/verifications/7Qx.../status"
  request-label="over 18"
  expires-at="2026-11-17T10:05:00Z"></eudiw-request>

<script type="module">
  document.querySelector('eudiw-request').addEventListener('eudiw-done', (event) => {
    if (event.detail.status === 'verified') {
      // Ask your backend for the outcome. The claims never pass through the browser unless you choose so.
    }
  });
</script>
```

Serve `eudiw-request.js`, `vendor/qrcode.mjs` and `fonts/*.woff2` from your own origin, keeping the relative paths. The font is registered once per page as `eudiw-jetbrains-mono`, so it does not clash with your own fonts.

## How it fits

The browser never talks to the adapter. Your backend holds the client credentials:

1. The browser asks your backend to start a check. Your backend creates a session at the adapter (`POST /v1/verification-sessions`) and returns `wallet_launch.launch_uri` and a status URL of its own.
2. The component renders the launch URI and polls your status URL, which answers `{"status": "..."}` from the adapter's `GET /v1/verification-sessions/{id}`.
3. When the status is `verified`, your backend retrieves the result once (`GET /v1/verification-sessions/{id}/result`) and acts on it.

Give the browser a random id of your own rather than the adapter's session id. See [examples](../../examples) for complete backends in Node and Python.

## Attributes

| Attribute | Meaning |
| --- | --- |
| `launch-uri` | `wallet_launch.launch_uri` of the session. `javascript:`, `data:`, `blob:`, `file:` and `vbscript:` URIs are refused |
| `status-url` | Your backend's status URL for this session. Fetched with same-origin credentials |
| `request-label` | What is asked, in the user's words, for example `over 18`. Shown as "this service asks for over 18" and repeated in the confirmation |
| `expires-at` | The session's `expires_at`. Shows a countdown and ends the request locally at zero. Also read from `expires_at` in the status response |
| `mode` | `cross_device` (default): QR code and link. `same_device`: link only |
| `theme` | `dark` (default), `light` (warm ivory), or `auto` (follows `prefers-color-scheme`) |
| `credit` | `off` hides the "eudiw-adapter · su.engineering" line |
| `poll-interval` | Milliseconds between status checks, default 2000, at least 500. Errors back off up to 30 seconds; polling pauses while the page is hidden |

## Events

Both bubble and cross shadow DOM boundaries.

- `eudiw-status`: `detail.status` and `detail.response` (your status URL's JSON) whenever the status changes.
- `eudiw-done`: once, when the session reaches `verified`, `rejected`, `denied`, `expired` or `cancelled`.
- `eudiw-restart`: the user asked for a new request after one ended without a verification. Start a new session and replace the element.

## Styling

The component uses a shadow root and adopted style sheets, so it works under a strict `style-src` Content Security Policy. Restyle it with custom properties on the element: `--eudiw-bg`, `--eudiw-fg`, `--eudiw-muted`, `--eudiw-line`, `--eudiw-signal` (dots, marks), `--eudiw-signal-text` (signal-colored text), `--eudiw-qr-bg`, `--eudiw-qr-fg` and `--eudiw-font`, or with `::part(panel)`, `::part(qr)`, `::part(open)`, `::part(privacy)` and `::part(credit)`. Keep the QR colors dark on light so phones can read the code.

## Tests

`node --test clients/web/test/*.test.mjs` encodes launch URIs as the component does and decodes the images back with `zbarimg` (skipped when zbar is not installed; CI requires it).

Not published to npm yet.
