// Plays the holder with walt.id Wallet API 2 (service waltid-wallet): create a wallet and a P-256 key in it, issue
// a synthetic credential bound to that key with the demo issuer key, import it, then hand the wallet the launch URI.
// The wallet fetches and checks the signed request, builds the presentation and posts the response; this script
// only drives its HTTP API. Node built-ins only, so it runs in a plain node image.
//
// Usage: node holder.mjs <launch URI> [trusted|untrusted|mdoc]
//   trusted    an SD-JWT VC from the demo issuer (default)
//   untrusted  an SD-JWT VC signed under a certificate chain the adapter's trusted list does not name
//   mdoc       an ISO mdoc PID (eu.europa.ec.eudi.pid.1) from the demo issuer; the wallet signs the session transcript
import { createHash, createPrivateKey, randomBytes, sign, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'

const [launchUri, mode = 'trusted'] = process.argv.slice(2)
if (!launchUri || !['trusted', 'untrusted', 'mdoc'].includes(mode)) {
  console.error('usage: node holder.mjs <launch URI> [trusted|untrusted|mdoc]')
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
const sha256 = (data) => createHash('sha256').update(data).digest()
const claims = { age_over_18: true, given_name: 'Erika', family_name: 'Mustermann' }

// "untrusted": a valid key and certificate chain, but under the demo relying-party root, which the trusted list
// does not name as an issuer.
function signer() {
  const name = mode === 'untrusted' ? 'verifier' : 'issuer'
  return {
    key: createPrivateKey(readFileSync(`${keys}/${name}-key.pem`)),
    certificate: new X509Certificate(readFileSync(`${keys}/${name}.pem`)).raw,
  }
}

function sdJwtVc(holderJwk) {
  const { key, certificate } = signer()
  const disclosures = Object.entries(claims).map(([name, value]) => b64url(JSON.stringify([b64url(randomBytes(16)), name, value])))
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: 'https://issuer.demo.example',
    iat: now,
    exp: now + 86_400,
    vct: 'https://credentials.demo.example/age',
    cnf: { jwk: holderJwk },
    _sd_alg: 'sha-256',
    _sd: disclosures.map((d) => sha256(d).toString('base64url')),
  }
  const header = { alg: 'ES256', typ: 'dc+sd-jwt', x5c: [certificate.toString('base64')] }
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  const signature = sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' })
  return `${input}.${b64url(signature)}~${disclosures.join('~')}~`
}

// Minimal CBOR encoder (RFC 8949) for the mdoc: unsigned and negative integers, byte and text strings, arrays,
// maps (keys in insertion order), booleans, and tags.
class Tag {
  constructor(tag, value) {
    this.tag = tag
    this.value = value
  }
}
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n])
  if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff])
  const b = Buffer.alloc(5)
  b[0] = (major << 5) | 26
  b.writeUInt32BE(n, 1)
  return b
}
function cbor(value) {
  if (value === true) return Buffer.from([0xf5])
  if (value === false) return Buffer.from([0xf4])
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)])
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (value instanceof Tag) return Buffer.concat([head(6, value.tag), cbor(value.value)])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  if (value instanceof Map) {
    return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
  }
  return cbor(new Map(Object.entries(value)))
}
const embedded = (value) => new Tag(24, cbor(value))
const tdate = (date) => new Tag(0, date.toISOString().replace(/\.\d{3}Z$/, 'Z'))

// IssuerSigned for one namespace: the items as embedded CBOR, and the issuer's COSE_Sign1 (RFC 9052) over the
// mobile security object, which holds a digest of each item and the device (holder) key.
function mdoc(holderJwk) {
  const { key, certificate } = signer()
  const docType = 'eu.europa.ec.eudi.pid.1'
  const items = Object.entries(claims).map(([elementIdentifier, elementValue], digestID) =>
    embedded(new Map([['digestID', digestID], ['random', randomBytes(16)], ['elementIdentifier', elementIdentifier], ['elementValue', elementValue]])),
  )
  const deviceKey = new Map([[1, 2], [-1, 1], [-2, Buffer.from(holderJwk.x, 'base64url')], [-3, Buffer.from(holderJwk.y, 'base64url')]])
  const now = new Date()
  const mso = new Map([
    ['version', '1.0'],
    ['digestAlgorithm', 'SHA-256'],
    ['valueDigests', new Map([[docType, new Map(items.map((item, i) => [i, sha256(cbor(item))]))]])],
    ['deviceKeyInfo', new Map([['deviceKey', deviceKey]])],
    ['docType', docType],
    ['validityInfo', new Map([['signed', tdate(now)], ['validFrom', tdate(now)], ['validUntil', tdate(new Date(now.getTime() + 86_400_000))]])],
  ])
  const protectedHeader = cbor(new Map([[1, -7]]))
  const payload = cbor(embedded(mso))
  const toBeSigned = cbor(['Signature1', protectedHeader, Buffer.alloc(0), payload])
  const signature = sign('sha256', toBeSigned, { key, dsaEncoding: 'ieee-p1363' })
  const issuerAuth = [protectedHeader, new Map([[33, certificate]]), payload, signature]
  return b64url(cbor(new Map([['nameSpaces', new Map([[docType, items]])], ['issuerAuth', issuerAuth]])))
}

const { walletId } = await call('POST', '/wallet', {})
// The wallet generates the holder key. Its API does not return the public part, but a did:jwk made from the key
// carries it.
const { keyId } = await call('POST', `/wallet/${walletId}/keys/generate`, { backend: 'jwk', keyType: 'secp256r1' })
const { did } = await call('POST', `/wallet/${walletId}/dids/create`, { method: 'jwk', keyId })
const { kty, crv, x, y } = JSON.parse(Buffer.from(did.slice('did:jwk:'.length), 'base64url'))
const rawCredential = mode === 'mdoc' ? mdoc({ x, y }) : sdJwtVc({ kty, crv, x, y })
await call('POST', `/wallet/${walletId}/credentials/import`, { rawCredential })

const result = await call('POST', `/wallet/${walletId}/credentials/present`, { requestUrl: launchUri, keyId })
console.log(JSON.stringify({ transmission_success: result.transmission_success, verifier_response: result.verifier_response }))
if (result.transmission_success !== true) process.exitCode = 1
