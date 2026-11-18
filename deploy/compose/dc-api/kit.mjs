// The integration kit over the W3C Digital Credentials API: the Node (or Python) example backend and its page with the
// <eudiw-request> component, in Chromium with eudi-dev's DC API extension. The page offers "use a wallet on this
// device" because the browser has DigitalCredential; the component calls navigator.credentials.get() and hands the
// response to the example backend, which relays it to the adapter. Prints the component's final status and the
// claims the page shows; exits 1 unless the status is verified with {"age_over_18": true}.
import { spawn } from 'node:child_process'
import { chromium } from 'playwright'

// BACKEND=python runs the Python example instead of the Node one; both serve the same page.
const python = process.env.BACKEND === 'python'
const backend = spawn(python ? 'python3' : 'node', [python ? '/repo/examples/python/server.py' : '/repo/examples/node/server.mjs'], {
  env: {
    ...process.env,
    PORT: '3005',
    HOST: '127.0.0.1',
    ADAPTER_URL: process.env.ADAPTER_URL ?? 'http://adapter:8080',
    TOKEN_URL: process.env.TOKEN_URL ?? 'http://keycloak:8080/realms/demo/protocol/openid-connect/token',
  },
  stdio: 'inherit',
})
for (let i = 0; i < 30; i++) {
  try {
    if ((await fetch('http://127.0.0.1:3005/')).ok) break
  } catch {}
  await new Promise((r) => setTimeout(r, 500))
}

const context = await chromium.launchPersistentContext('', {
  channel: 'chromium',
  headless: true,
  args: ['--disable-extensions-except=/ext', '--load-extension=/ext'],
})
let outcome
try {
  const tab = await context.newPage()
  let ready = false
  for (let attempt = 0; attempt < 30 && !ready; attempt++) {
    await tab.goto('http://localhost:3005/')
    ready = await tab.evaluate(() => !navigator.credentials.get.toString().includes('[native code]'))
    if (!ready) await tab.waitForTimeout(1000)
  }
  if (!ready) throw new Error('the eudi-dev extension did not take over navigator.credentials.get')
  await tab.click('#start-dc-api')
  const shots = process.env.OUT_DIR
  await tab.waitForSelector('eudiw-request button.open')
  if (shots) await tab.locator('eudiw-request').screenshot({ path: `${shots}/dc-api-pending.png` })
  // Playwright's CSS selectors pierce the component's open shadow root.
  await tab.click('eudiw-request button.open')
  await tab.waitForFunction(
    () => ['verified', 'rejected', 'denied', 'expired'].includes(document.querySelector('eudiw-request')?.status),
    null,
    { timeout: 90_000 },
  )
  const status = await tab.evaluate(() => document.querySelector('eudiw-request').status)
  let claims = null
  if (status === 'verified') {
    await tab.waitForFunction(() => document.getElementById('claims').textContent.includes('age_over_18'), null, {
      timeout: 30_000,
    })
    claims = JSON.parse(await tab.textContent('#claims'))
  }
  if (shots) await tab.screenshot({ path: `${shots}/dc-api-done.png`, fullPage: true })
  outcome = { status, claims }
} finally {
  await context.close()
  backend.kill()
}
console.log(JSON.stringify(outcome))
process.exit(outcome.status === 'verified' && outcome.claims?.age_over_18 === true ? 0 : 1)
