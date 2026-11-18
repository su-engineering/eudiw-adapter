// Plays the holder with walt.id Wallet API 2 (service waltid-wallet): create a wallet, import a P-256 key, issue
// a synthetic SD-JWT VC bound to that key with the demo issuer key, import it, then hand the wallet the launch URI.
// The wallet fetches and checks the signed request, builds the presentation and posts the response; this script
// only drives its HTTP API. Node built-ins only, so it runs in a plain node image.
//
// Usage: node holder.mjs <launch URI> [trusted|untrusted]
// With "untrusted" the credential is signed under a certificate chain the adapter's trusted list does not name.
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'

const [launchUri, mode = 'trusted'] = process.argv.slice(2)
if (!launchUri || !['trusted', 'untrusted'].includes(mode)) {
  console.error('usage: node holder.mjs <launch URI> [trusted|untrusted]')
  process.exit(2)
}
const wallet = process.env.WALTID_URL ?? 'http://waltid-wallet:7006'
const keys = process.env.KEYS_DIR ?? '/keys'

async function call(method, path, body) {
  const response = await fetch(wallet + path, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status} ${text}`)
  return text ? JSON.parse(text) : null
}

const b64url = (data) => Buffer.from(data).toString('base64url')

function sdJwtVc(holderJwk) {
  // "untrusted": a valid key and certificate chain, but under the demo relying-party root, which the trusted list
  // does not name as an issuer.
  const signer = mode === 'untrusted' ? 'verifier' : 'issuer'
  const issuerKey = createPrivateKey(readFileSync(`${keys}/${signer}-key.pem`))
  const x5c = [new X509Certificate(readFileSync(`${keys}/${signer}.pem`)).raw.toString('base64')]
  const claims = { age_over_18: true, given_name: 'Erika', family_name: 'Mustermann' }
  const disclosures = Object.entries(claims).map(([name, value]) => b64url(JSON.stringify([b64url(randomBytes(16)), name, value])))
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: 'https://issuer.demo.example',
    iat: now,
    exp: now + 86_400,
    vct: 'https://credentials.demo.example/age',
    cnf: { jwk: holderJwk },
    _sd_alg: 'sha-256',
    _sd: disclosures.map((d) => createHash('sha256').update(d).digest('base64url')),
  }
  const header = { alg: 'ES256', typ: 'dc+sd-jwt', x5c }
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  const signature = sign('sha256', Buffer.from(input), { key: issuerKey, dsaEncoding: 'ieee-p1363' })
  return `${input}.${b64url(signature)}~${disclosures.join('~')}~`
}

const { walletId } = await call('POST', '/wallet', {})
// The wallet API does not return a generated key's public part, so the holder key is made here and imported.
const holderKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' })
const { keyId } = await call('POST', `/wallet/${walletId}/keys/import`, { key: { type: 'jwk', jwk: holderKey } })
const { kty, crv, x, y } = holderKey
await call('POST', `/wallet/${walletId}/credentials/import`, { rawCredential: sdJwtVc({ kty, crv, x, y }) })

const result = await call('POST', `/wallet/${walletId}/credentials/present`, { requestUrl: launchUri, keyId })
console.log(JSON.stringify({ transmission_success: result.transmission_success, verifier_response: result.verifier_response }))
if (result.transmission_success !== true) process.exitCode = 1
