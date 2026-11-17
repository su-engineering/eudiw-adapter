// Encodes launch URIs with the vendored encoder exactly as the component does (error correction M, quiet zone of
// four modules), writes PNG images and decodes them back with zbarimg. CI installs zbar and sets REQUIRE_ZBAR=1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { qrcode } from '../vendor/qrcode.mjs';

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([length, body, crc]);
}

function png(text, scale = 6) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const size = (count + 8) * scale;
  const rows = [];
  for (let y = 0; y < size; y += 1) {
    const row = Buffer.alloc(size + 1, 0xff);
    row[0] = 0; // filter: none
    const r = Math.floor(y / scale) - 4;
    for (let x = 0; x < size; x += 1) {
      const c = Math.floor(x / scale) - 4;
      if (r >= 0 && r < count && c >= 0 && c < count && qr.isDark(r, c)) {
        row[x + 1] = 0;
      }
    }
    rows.push(row);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 0; // greyscale
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function zbarAvailable() {
  try {
    execFileSync('zbarimg', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const LAUNCH_URIS = [
  'openid4vp://?client_id=x509_hash%3AUvRWzvCUh1PDfqMXvGCKxkIb1nOR6TkNI0oAOGqFNIw'
    + '&request_uri=https%3A%2F%2Fadapter.example%2Foid4vp%2Frequests%2FAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEf'
    + '&request_uri_method=post',
  'haip-vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fa.example%2Fr%2F1&request_uri_method=post',
];

test('the QR code decodes back to the launch URI', { skip: !zbarAvailable() && !process.env.REQUIRE_ZBAR }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'eudiw-qr-'));
  LAUNCH_URIS.forEach((uri, i) => {
    const file = join(dir, `qr-${i}.png`);
    writeFileSync(file, png(uri));
    const decoded = execFileSync('zbarimg', ['--raw', '-q', file], { encoding: 'utf8' }).trim();
    assert.equal(decoded, uri);
  });
});
