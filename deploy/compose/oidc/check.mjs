// Wallet login through the adapter's OpenID Connect provider (ADR-018), in Chromium, twice through each of:
//   - Keycloak: the shop realm's account console, with the adapter as an identity provider;
//   - Nextcloud: the stock user_oidc app, with the adapter as its OpenID Connect provider.
// Each login reaches the adapter's login page, whose wallet launch URI this script writes to /out/launch-<n> for
// run.sh to hand to the eudi-dev wallet; the page then follows the login and returns to the application. The second
// login of each must land on the same account without asking for anything. Prints {logins: [...]}; run.sh checks
// the accounts.
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
const shots = '/out'

/** On the adapter's login page: hand the launch URI to run.sh and wait until the page returns to `back`. */
async function wallet(page, n, back) {
  await page.waitForURL(/^http:\/\/adapter:8080\/oidc\/demo-city\/authorize/)
  const launch = await page.locator('eudiw-request').getAttribute('launch-uri')
  if (!launch?.startsWith('openid4vp://')) throw new Error(`no launch URI on the login page: ${launch}`)
  await page.screenshot({ path: `${shots}/login-${n}-wallet-page.png`, fullPage: true })
  writeFileSync(`/out/launch-${n}`, launch)
  await page.waitForURL(back, { timeout: 120_000 })
}

async function keycloak(n, first) {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await page.goto('http://localhost:8081/realms/shop/account/')
    await page.getByRole('link', { name: 'EU Digital Identity Wallet' }).click()
    await wallet(page, n, /^http:\/\/localhost:8081\//)
    // First login: Keycloak's first-login flow asks for the profile attributes the wallet did not provide.
    const email = page.locator('input[name="email"]')
    if (await email.isVisible({ timeout: 5_000 }).catch(() => false)) {
      if (!first) throw new Error('the second login asked for the profile again, so it did not find the same account')
      await email.fill('erika@shop.example')
      await page.screenshot({ path: `${shots}/login-${n}-first-broker-login.png`, fullPage: true })
      await page.locator('input[type="submit"], button[type="submit"]').first().click()
    }
    await page.waitForURL(/\/realms\/shop\/account/, { timeout: 60_000 })
    await page.screenshot({ path: `${shots}/login-${n}-keycloak-account.png`, fullPage: true })
    return { app: 'keycloak', url: page.url() }
  } finally {
    await context.close()
  }
}

async function nextcloud(n) {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await page.goto('http://nextcloud/login')
    await page.locator('a[href*="/apps/user_oidc/login/"]').first().click()
    await wallet(page, n, /^http:\/\/nextcloud\//)
    await page.waitForURL((url) => !url.pathname.includes('/apps/user_oidc/') && !url.pathname.endsWith('/login'), {
      timeout: 60_000,
    })
    await page.screenshot({ path: `${shots}/login-${n}-nextcloud.png`, fullPage: true })
    const user = await page.evaluate(async () => {
      const r = await fetch('/ocs/v2.php/cloud/user?format=json', { headers: { 'OCS-APIRequest': 'true' } })
      return r.ok ? (await r.json()).ocs.data : null
    })
    return { app: 'nextcloud', user: user?.id ?? null, displayName: user?.['display-name'] ?? user?.displayname ?? null }
  } finally {
    await context.close()
  }
}

const logins = []
try {
  logins.push(await keycloak(1, true))
  logins.push(await keycloak(2, false))
  logins.push(await nextcloud(3))
  logins.push(await nextcloud(4))
} catch (e) {
  console.log(JSON.stringify({ logins, error: String(e) }))
  process.exit(1)
} finally {
  await browser.close()
  forwarder.close()
}
console.log(JSON.stringify({ logins }))
