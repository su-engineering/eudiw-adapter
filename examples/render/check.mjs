// Renders the example page in Chromium and records what a person would see: the QR code as drawn on screen, the
// font actually used, and the final state. Run by check.sh, which decodes the QR code and plays the wallet.
import { chromium } from 'playwright';
import { writeFileSync } from 'node:fs';

const base = process.env.BASE_URL;
const out = process.env.OUT_DIR ?? '/out';
const fail = (message) => { console.error(message); process.exit(1); };
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 975 } });
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('requestfailed', (r) => errors.push(`request failed: ${r.url()}`));

await page.goto(base, { waitUntil: 'networkidle' });
await page.click('#start');
await page.waitForFunction(() => document.querySelector('eudiw-request')?.shadowRoot?.querySelector('.code svg'));
await page.evaluate(() => document.fonts.ready);
const font = await page.evaluate(() => ({
  loaded: [...document.fonts].some((f) => f.family.replaceAll('"', '') === 'eudiw-jetbrains-mono' && f.status === 'loaded'),
  used: getComputedStyle(document.querySelector('eudiw-request').shadowRoot.querySelector('.code').parentElement).fontFamily,
}));
if (!font.loaded || !font.used.includes('eudiw-jetbrains-mono')) fail(`font not in use: ${JSON.stringify(font)}`);

// The QR code exactly as rendered, at a scale zbarimg reads reliably.
const code = await page.evaluateHandle(() => document.querySelector('eudiw-request').shadowRoot.querySelector('.code svg'));
await code.screenshot({ path: `${out}/qr.png`, scale: 'device' });
await page.screenshot({ path: `${out}/pending.png` });
writeFileSync(`${out}/launch.txt`, await page.$eval('eudiw-request', (e) => e.getAttribute('launch-uri')));

// check.sh answers with the test wallet; the component must reach its final state and the page show the result.
await page.waitForFunction(() => document.querySelector('eudiw-request')?.status === 'verified', null, { timeout: 120000 });
await page.waitForSelector('#returned:not([hidden])', { timeout: 20000 });
const done = await page.evaluate(() => document.querySelector('eudiw-request').shadowRoot.textContent);
if (!/done\./.test(done)) fail('component did not show its done state');
await page.screenshot({ path: `${out}/verified.png` });
if (errors.length) fail(`page errors: ${JSON.stringify(errors)}`);
await browser.close();
console.log('rendered: font loaded, QR drawn, done state shown');
