// A relying-party page that uses the W3C Digital Credentials API, and Chromium with eudi-dev's DC API extension
// clicking its button. Runs inside the Playwright image on the Compose network, so the page's Origin is
// http://localhost:3005, the origin the demo client registers in dc_api_origins.
//
// The page's backend (this file) creates a dc_api session at the adapter, hands dc_api.request to the page, and
// relays what navigator.credentials.get() returned to the adapter. Prints the outcome as JSON and exits 1 unless it
// is the expected status (EXPECT, default verified) and, if set, reason (EXPECT_REASON).
import { createServer } from 'node:http'
import { chromium } from 'playwright'

const adapter = process.env.ADAPTER_URL ?? 'http://adapter:8080'
const keycloak = process.env.KEYCLOAK_URL ?? 'http://keycloak:8080'
const policy = process.env.POLICY ?? 'age-over-18'
const origin = process.env.ORIGIN ?? 'http://localhost:3005'
const expect = process.env.EXPECT ?? 'verified'
const expectReason = process.env.EXPECT_REASON

async function token() {
  const r = await fetch(`${keycloak}/realms/demo/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials&client_id=demo-portal&client_secret=demo-only-secret',
  })
  return (await r.json()).access_token
}

async function adapterCall(method, path, body) {
  const r = await fetch(adapter + path, {
    method,
    headers: {
      authorization: `Bearer ${await token()}`,
      'content-type': 'application/json',
      'idempotency-key': `dc-api-${Date.now()}-${Math.random()}`,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return { status: r.status, body: await r.json() }
}

const page = `<!doctype html><meta charset="utf-8"><title>DC API check</title>
<button id="go">Verify with your wallet</button><pre id="out"></pre>
<script>
document.getElementById('go').onclick = async () => {
  const out = document.getElementById('out');
  const session = await (await fetch('/start', { method: 'POST' })).json();
  try {
    const credential = await navigator.credentials.get(session.request);
    const finished = await fetch('/finish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: session.id, data: credential.data }),
    });
    out.textContent = JSON.stringify(await finished.json());
  } catch (e) {
    out.textContent = JSON.stringify({ browser_error: e.name + ': ' + e.message });
  }
};
</script>`

const server = createServer(async (req, res) => {
  const send = (status, body, type = 'application/json') => {
    res.writeHead(status, { 'content-type': type })
    res.end(type === 'application/json' ? JSON.stringify(body) : body)
  }
  try {
    if (req.method === 'GET' && req.url === '/') return send(200, page, 'text/html')
    let raw = ''
    for await (const chunk of req) raw += chunk
    if (req.url === '/start') {
      const created = await adapterCall('POST', '/v1/verification-sessions', { policy_id: policy, mode: 'dc_api', origin })
      if (created.status !== 201) return send(500, created.body)
      return send(200, { id: created.body.id, request: created.body.dc_api.request })
    }
    if (req.url === '/finish') {
      const { id, data } = JSON.parse(raw)
      const relayed = await adapterCall('POST', `/v1/verification-sessions/${id}/dc-api-response`, { data })
      const outcome = { http: relayed.status, status: relayed.body.status, reason: relayed.body.reason ?? relayed.body.code }
      if (relayed.body.status === 'verified') {
        outcome.claims = (await adapterCall('GET', `/v1/verification-sessions/${id}/result`)).body.claims
      }
      return send(200, outcome)
    }
    send(404, {})
  } catch (e) {
    send(500, { error: String(e) })
  }
})
await new Promise((resolve) => server.listen(3005, '127.0.0.1', resolve))

const context = await chromium.launchPersistentContext('', {
  channel: 'chromium',
  headless: true,
  args: ['--disable-extensions-except=/ext', '--load-extension=/ext'],
})
let outcome
try {
  const tab = await context.newPage()
  // The extension registers its page script once its service worker has started. Until then the page sees
  // Chromium's own navigator.credentials.get, which has no wallet behind it; reload until the extension's is there.
  let ready = false
  for (let attempt = 0; attempt < 30 && !ready; attempt++) {
    await tab.goto('http://localhost:3005/')
    ready = await tab.evaluate(() => !navigator.credentials.get.toString().includes('[native code]'))
    if (!ready) await tab.waitForTimeout(1000)
  }
  if (!ready) throw new Error('the eudi-dev extension did not take over navigator.credentials.get')
  await tab.click('#go') // a click: the API needs user activation
  await tab.waitForFunction(() => document.getElementById('out').textContent.length > 0, null, { timeout: 90_000 })
  outcome = JSON.parse(await tab.textContent('#out'))
} finally {
  await context.close()
  server.close()
}
console.log(JSON.stringify(outcome))
process.exit(outcome.status === expect && (!expectReason || outcome.reason === expectReason) ? 0 : 1)
