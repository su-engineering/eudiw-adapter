// Copyright 2026 su-engineering. Licensed under the Apache License, Version 2.0.
//
// A minimal relying-party backend for eudiw-adapter, with no dependencies (Node 22 or later).
//
//   POST /verifications                 start a session; returns the launch URI and URLs for the browser
//   GET  /verifications/{id}/status     {"status": ...} for the <eudiw-request> component
//   POST /verifications/{id}/result     fetch the verified claims once (a real app acts on them server-side)
//   POST /webhooks/eudiw                signed session notifications from the adapter
//
// The browser only ever sees a random local id. The adapter's client credentials, session id and result stay here.
import { createServer } from 'node:http';
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const config = {
  port: Number(process.env.PORT ?? 3000),
  adapterUrl: (process.env.ADAPTER_URL ?? 'http://localhost:8080').replace(/\/$/, ''),
  tokenUrl: process.env.TOKEN_URL ?? 'http://localhost:8081/realms/demo/protocol/openid-connect/token',
  clientId: process.env.CLIENT_ID ?? 'demo-portal',
  clientSecret: process.env.CLIENT_SECRET ?? 'demo-only-secret',
  policyId: process.env.POLICY_ID ?? 'age-over-18',
  // whsec_ secrets: the current one, and during a rotation also the previous one.
  webhookSecrets: [process.env.WEBHOOK_SECRET, process.env.WEBHOOK_PREVIOUS_SECRET].filter(Boolean),
};

/** Standard Webhooks verification over the raw body. Returns the parsed event, or throws. */
export function verifyWebhook(rawBody, headers, secrets, now = Date.now(), toleranceSeconds = 300) {
  const id = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signatures = headers['webhook-signature'];
  if (!id || !timestamp || !signatures || !/^\d+$/.test(timestamp)) {
    throw new Error('missing webhook headers');
  }
  if (Math.abs(now / 1000 - Number(timestamp)) > toleranceSeconds) {
    throw new Error('webhook timestamp outside tolerance');
  }
  const content = Buffer.concat([Buffer.from(`${id}.${timestamp}.`, 'utf8'), rawBody]);
  const expected = secrets.map((secret) =>
    createHmac('sha256', Buffer.from(secret.replace(/^whsec_/, ''), 'base64')).update(content).digest());
  for (const entry of signatures.split(' ')) {
    const [version, value] = entry.split(',', 2);
    if (version !== 'v1' || !value) {
      continue;
    }
    const given = Buffer.from(value, 'base64');
    if (expected.some((e) => e.length === given.length && timingSafeEqual(e, given))) {
      return JSON.parse(rawBody.toString('utf8'));
    }
  }
  throw new Error('no valid webhook signature');
}

let token = null;
async function accessToken() {
  if (token && token.expiresAt > Date.now() + 30_000) {
    return token.value;
  }
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
  });
  if (!response.ok) {
    throw new Error(`token endpoint answered ${response.status}`);
  }
  const body = await response.json();
  token = { value: body.access_token, expiresAt: Date.now() + (body.expires_in ?? 60) * 1000 };
  return token.value;
}

async function adapter(method, path, body, idempotencyKey) {
  const headers = { Authorization: `Bearer ${await accessToken()}`, Accept: 'application/json' };
  if (body) {
    headers['Content-Type'] = 'application/json';
  }
  if (idempotencyKey) {
    headers['Idempotency-Key'] = idempotencyKey;
  }
  const response = await fetch(`${config.adapterUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

// Local id (random, given to the browser) -> adapter session id. Use your database in a real application.
const sessions = new Map();
const STATIC = {
  '/': [join(HERE, '..', 'shared', 'index.html'), 'text/html; charset=utf-8'],
  '/eudiw/eudiw-request.js': [join(HERE, '..', '..', 'clients', 'web', 'eudiw-request.js'), 'text/javascript'],
  '/eudiw/vendor/qrcode.mjs': [join(HERE, '..', '..', 'clients', 'web', 'vendor', 'qrcode.mjs'), 'text/javascript'],
};

function send(res, status, body, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(type === 'application/json' ? JSON.stringify(body) : body);
}

async function readBody(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw new Error('body too large');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const match = url.pathname.match(/^\/verifications\/([A-Za-z0-9_-]{43})\/(status|result)$/);

  if (req.method === 'GET' && STATIC[url.pathname]) {
    const [file, type] = STATIC[url.pathname];
    return send(res, 200, await readFile(file), type);
  }
  if (req.method === 'POST' && url.pathname === '/verifications') {
    const created = await adapter(
      'POST', '/v1/verification-sessions', { policy_id: config.policyId, mode: 'cross_device' }, randomUUID());
    if (created.status !== 201) {
      return send(res, 502, { error: 'could_not_start' });
    }
    const local = randomBytes(32).toString('base64url');
    sessions.set(local, created.body.id);
    return send(res, 201, {
      launch_uri: created.body.wallet_launch.launch_uri,
      status_url: `/verifications/${local}/status`,
      result_url: `/verifications/${local}/result`,
    });
  }
  if (match && sessions.has(match[1])) {
    const id = sessions.get(match[1]);
    if (req.method === 'GET' && match[2] === 'status') {
      const session = await adapter('GET', `/v1/verification-sessions/${id}`);
      return session.status === 200 ? send(res, 200, { status: session.body.status }) : send(res, 404, {});
    }
    if (req.method === 'POST' && match[2] === 'result') {
      const result = await adapter('GET', `/v1/verification-sessions/${id}/result`);
      sessions.delete(match[1]);
      return result.status === 200 ? send(res, 200, { claims: result.body.claims }) : send(res, 404, {});
    }
  }
  if (req.method === 'POST' && url.pathname === '/webhooks/eudiw') {
    try {
      const event = verifyWebhook(await readBody(req), req.headers, config.webhookSecrets);
      console.log(`webhook: session ${event.id} is ${event.status}`);
      res.writeHead(204).end();
    } catch {
      send(res, 401, { error: 'invalid_signature' });
    }
    return;
  }
  send(res, 404, { error: 'not_found' });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createServer((req, res) => {
    handle(req, res).catch((e) => {
      console.error(e.message);
      if (!res.headersSent) {
        send(res, 500, { error: 'internal_error' });
      }
    });
  }).listen(config.port, '127.0.0.1', () => console.log(`example backend on http://localhost:${config.port}`));
}
