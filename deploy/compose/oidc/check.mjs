// Wallet login through Keycloak (ADR-018). Chromium opens the shop realm's account console; Keycloak's login page
// offers "EU Digital Identity Wallet", the adapter's OpenID Connect provider. The adapter's login page shows a
// wallet launch URI, which this script writes to /out/launch-<n> for run.sh to hand to the eudi-dev wallet; once
// the wallet has presented, the page returns to Keycloak, which completes its first-login flow and opens the account
// console. Two logins, in separate browser contexts: the second must not ask for anything and land on the same
// account. Prints {logins: [{url}]}; run.sh checks the accounts through Keycloak's admin API.
import { createServer, connect } from 'node:net'
import { writeFileSync } from 'node:fs'
import { chromium } from 'playwright'

// Keycloak's hostname is http://localhost:8081, as a browser on the host sees it. Inside this container,
// localhost:8081 is forwarded to the Keycloak service.
const forwarder = createServer((socket) => {
  const upstream = connect(8080, 'keycloak')
  socket.pipe(upstream).pipe(socket)
  socket.on('error', () => upstream.destroy())
  upstream.on('error', () => socket.destroy())
})
await new Promise((resolve) => forwarder.listen(8081, '127.0.0.1', resolve))

const browser = await chromium.launch({ headless: true })
const shots = process.env.OUT_DIR ?? '/out'

async function login(n) {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await page.goto('http://localhost:8081/realms/shop/account/')
    await page.getByRole('link', { name: 'EU Digital Identity Wallet' }).click()
    await page.waitForURL(/^http:\/\/adapter:8080\/oidc\/demo-city\/authorize/)
    const launch = await page.locator('eudiw-request').getAttribute('launch-uri')
    if (!launch?.startsWith('openid4vp://')) throw new Error(`no launch URI on the login page: ${launch}`)
    await page.screenshot({ path: `${shots}/login-${n}-wallet-page.png`, fullPage: true })
    writeFileSync(`/out/launch-${n}`, launch)
    // The wallet presents; the page follows the login's status and returns to Keycloak.
    await page.waitForURL(/^http:\/\/localhost:8081\//, { timeout: 120_000 })
    // First login: Keycloak's first-login flow asks for the profile attributes the wallet did not provide.
    const email = page.locator('input[name="email"]')
    if (await email.isVisible({ timeout: 5_000 }).catch(() => false)) {
      if (n > 1) throw new Error('the second login asked for the profile again, so it did not find the same account')
      await email.fill('erika@shop.example')
      await page.screenshot({ path: `${shots}/login-${n}-first-broker-login.png`, fullPage: true })
      await page.locator('input[type="submit"], button[type="submit"]').first().click()
    }
    await page.waitForURL(/\/realms\/shop\/account/, { timeout: 60_000 })
    await page.screenshot({ path: `${shots}/login-${n}-account.png`, fullPage: true })
    return { url: page.url() }
  } finally {
    await context.close()
  }
}

let logins
try {
  logins = [await login(1), await login(2)]
} finally {
  await browser.close()
  forwarder.close()
}
console.log(JSON.stringify({ logins }))
