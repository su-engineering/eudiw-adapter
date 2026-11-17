// Verifies the shared vector, which the adapter's own signer reproduces (WebhookVectorTest in the service).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyWebhook } from '../server.mjs';

const vector = JSON.parse(readFileSync(new URL('../../shared/webhook-vector.json', import.meta.url), 'utf8'));
const body = Buffer.from(vector.body, 'utf8');
const at = Number(vector.headers['webhook-timestamp']) * 1000;

test('accepts what the adapter signs, with either secret during a rotation', () => {
  assert.equal(verifyWebhook(body, vector.headers, [vector.secret], at).data.status, 'verified');
  assert.equal(verifyWebhook(body, vector.headers, [vector.previous_secret], at).data.status, 'verified');
});

test('rejects a changed body, a wrong secret, an old timestamp and missing headers', () => {
  const secrets = [vector.secret];
  assert.throws(() => verifyWebhook(Buffer.from(vector.body.replace('verified', 'rejected')), vector.headers, secrets, at));
  assert.throws(() => verifyWebhook(body, vector.headers, ['whsec_' + Buffer.alloc(32).toString('base64')], at));
  assert.throws(() => verifyWebhook(body, vector.headers, secrets, at + 301_000));
  assert.throws(() => verifyWebhook(body, { ...vector.headers, 'webhook-signature': undefined }, secrets, at));
  const otherId = { ...vector.headers, 'webhook-id': 'msg_ffffffffffffffffffffffffffffffff' };
  assert.throws(() => verifyWebhook(body, otherId, secrets, at));
});
