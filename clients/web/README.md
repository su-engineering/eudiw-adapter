# `<eudiw-request>` web component

Shows an EUDI Wallet request as a QR code with an "open wallet" link, and follows the session until it ends. One ES module, no build step, no dependencies besides a vendored QR encoder.

```html
<script type="module" src="/eudiw/eudiw-request.js"></script>

<eudiw-request
  launch-uri="openid4vp://?client_id=...&request_uri=...&request_uri_method=post"
  status-url="/verifications/7Qx.../status"></eudiw-request>

<script type="module">
  document.querySelector('eudiw-request').addEventListener('eudiw-done', (event) => {
    if (event.detail.status === 'verified') {
      // Ask your backend for the outcome. The claims never pass through the browser unless you choose so.
    }
  });
</script>
```

Serve `eudiw-request.js` and `vendor/qrcode.mjs` from your own origin, keeping the relative path between them.

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
| `mode` | `cross_device` (default): QR code and link. `same_device`: link only |
| `poll-interval` | Milliseconds between status checks, default 2000, at least 500. Errors back off up to 30 seconds; polling pauses while the page is hidden |

## Events

Both bubble and cross shadow DOM boundaries.

- `eudiw-status`: `detail.status` whenever the status changes.
- `eudiw-done`: once, when the session reaches `verified`, `rejected`, `denied`, `expired` or `cancelled`.

## Styling

The component uses a shadow root and adopted style sheets, so it works under a strict `style-src` Content Security Policy. Restyle it with custom properties on the element (`--eudiw-fg`, `--eudiw-bg`, `--eudiw-muted`, `--eudiw-accent`, `--eudiw-accent-fg`, `--eudiw-ok`, `--eudiw-bad`, `--eudiw-radius`) or with `::part(card)`, `::part(qr)`, `::part(open)` and `::part(status)`. It follows `prefers-color-scheme`. The QR code always keeps a white quiet zone so phones can read it.

## Tests

`node --test clients/web/test/*.test.mjs` encodes launch URIs as the component does and decodes the images back with `zbarimg` (skipped when zbar is not installed; CI requires it).

Not published to npm yet.
