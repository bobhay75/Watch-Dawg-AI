import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createFrontendServer } from '../server.mjs';

async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

function request(base, path = '/', { method = 'GET', headers = {}, body, end = true } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(base, { path, method, headers, agent: false }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers,
        text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(2000, () => req.destroy(new Error('Test request timeout')));
    if (end) req.end(body);
    else { req.flushHeaders(); if (body) req.write(body); }
  });
}

async function gateway(t, handler = (_req, res) => res.end('{}'), config = {}) {
  const upstream = await listen(t, http.createServer(handler));
  return listen(t, createFrontendServer({ backend: upstream, ...config }));
}

test('serves real checkout assets with exact MIME types and supports HEAD', async t => {
  const base = await gateway(t);
  for (const [path, type] of [['/', 'text/html'], ['/watchdawg.js', 'text/javascript'],
    ['/assets/brand/watchdawg-bobsome1.png', 'image/png'], ['/assets/css/watchdawg-attribution.css', 'text/css']]) {
    const res = await request(base, path);
    assert.equal(res.status, 200);
    assert.ok(res.headers['content-type'].startsWith(type));
    assert.ok(Number(res.headers['content-length']) > 0);
  }
  const head = await request(base, '/', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.text, '');
});

test('malformed and authority paths fail without terminating later requests', async t => {
  const base = await gateway(t);
  for (const path of ['/%', '/%E0%A4%A', '//other.invalid/api/health', '/%00', '/%5c', 'https://other.invalid/api/health']) {
    assert.equal((await request(base, path)).status, 400, path);
    assert.equal((await request(base)).status, 200);
  }
});

test('unknown files, private files, and unsupported methods fail closed', async t => {
  const base = await gateway(t);
  for (const path of ['/missing', '/backend/server.py', '/frontend/.env', '/.git/config', '/field/unknown.js']) {
    const res = await request(base, path);
    assert.equal(res.status, 404);
    assert.equal(res.headers['x-robots-tag'], 'noindex, nofollow');
  }
  assert.equal((await request(base, '/', { method: 'POST' })).status, 405);
  assert.equal((await request(base, '/api/health', { method: 'POST' })).status, 405);
  assert.equal((await request(base, '/api/not-approved')).status, 404);
  assert.equal((await request(base, '/api/health?token=synthetic')).status, 400);
  assert.equal((await request(base, '/api%2fhealth')).status, 400);
});

test('preserves backend authentication status without forwarding spoofed identity or cookies', async t => {
  let seen;
  const base = await gateway(t, (req, res) => {
    seen = req.headers;
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer',
      'set-cookie': 'upstream-secret=must-not-pass', 'x-powered-by': 'private-runtime' });
    res.end('{"detail":"Authentication required"}');
  });
  const res = await request(base, '/api/health', { headers: {
    authorization: 'Bearer synthetic-test-only', origin: 'https://console.example.invalid',
    host: 'attacker.invalid', cookie: 'private=do-not-forward', 'x-role': 'admin',
    'x-forwarded-proto': 'https', 'x-forwarded-for': '127.0.0.1',
  } });
  assert.equal(res.status, 401);
  assert.equal(res.headers['www-authenticate'], 'Bearer');
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers['set-cookie'], undefined);
  assert.equal(res.headers['x-powered-by'], undefined);
  assert.match(seen.host, /^127\.0\.0\.1:/);
  assert.equal(seen.authorization, 'Bearer synthetic-test-only');
  assert.equal(seen.origin, 'https://console.example.invalid');
  for (const name of ['cookie', 'x-role', 'x-forwarded-proto', 'x-forwarded-for']) assert.equal(seen[name], undefined);
});

test('streams audit response bytes without changing SSE frames', async t => {
  let captured;
  const base = await gateway(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    captured = Buffer.concat(chunks).toString();
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: {"delta":"One"}\n\n');
    setImmediate(() => res.end('data: {"done":true}\n\n'));
  });
  const body = '{"synthetic":true}';
  const res = await request(base, '/api/ai/audit', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body });
  assert.equal(captured, body);
  assert.equal(res.status, 200);
  assert.equal(res.text, 'data: {"delta":"One"}\n\ndata: {"done":true}\n\n');
});

test('oversized and stalled request bodies are rejected before reaching the upstream', async t => {
  let calls = 0;
  const base = await gateway(t, (_req, res) => { calls++; res.end('{}'); },
    { bodyLimit: 16, bodyTimeoutMs: 40 });
  const tooBig = await request(base, '/api/ai/audit', { method: 'POST',
    headers: { 'content-length': '17' }, body: 'x'.repeat(17) });
  assert.equal(tooBig.status, 413);
  const chunked = await request(base, '/api/ai/audit', { method: 'POST',
    headers: { 'transfer-encoding': 'chunked' }, body: 'x'.repeat(17) });
  assert.equal(chunked.status, 413);
  const stalled = await request(base, '/api/ai/audit', { method: 'POST',
    headers: { 'content-length': '10' }, body: 'x', end: false });
  assert.equal(stalled.status, 408);
  assert.equal(calls, 0);
  assert.equal((await request(base)).status, 200);
});

test('upstream connection failure and response timeout do not crash the frontend', async t => {
  const unused = http.createServer();
  unused.listen(0, '127.0.0.1');
  await once(unused, 'listening');
  const deadPort = unused.address().port;
  await new Promise(resolve => unused.close(resolve));
  const dead = await listen(t, createFrontendServer({ backend: `http://127.0.0.1:${deadPort}` }));
  assert.equal((await request(dead, '/api/health')).status, 502);
  assert.equal((await request(dead)).status, 200);
  const slow = await gateway(t, () => {}, { upstreamTimeoutMs: 40 });
  assert.equal((await request(slow, '/api/health')).status, 504);
  assert.equal((await request(slow)).status, 200);
});

test('truncated and excessive upstream streams fail without a successful full body', async t => {
  const base = await gateway(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: partial\n');
    setImmediate(() => res.destroy());
  });
  await assert.rejects(request(base, '/api/health'));
  assert.equal((await request(base)).status, 200);
  const excessive = await gateway(t, (_req, res) => res.end('x'.repeat(1024)), { responseLimit: 16 });
  await assert.rejects(request(excessive, '/api/health'));
  assert.equal((await request(excessive)).status, 200);
});

test('HTTPS upstream uses certificate verification and supports an explicitly trusted CA', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'watchdawg-gateway-tls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cert = join(dir, 'certificate.pem');
  const key = join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', key, '-out', cert],
  { stdio: 'ignore' });
  const tls = https.createServer({ cert: await readFile(cert), key: await readFile(key) }, (_req, res) => res.end('verified TLS'));
  const tlsAddress = (await listen(t, tls)).replace('http:', 'https:');
  const untrusted = await listen(t, createFrontendServer({ backend: tlsAddress }));
  assert.equal((await request(untrusted, '/api/health')).status, 502);
  const modulePath = fileURLToPath(new URL('../server.mjs', import.meta.url));
  const child = spawn(process.execPath, ['--input-type=module', '-e',
    `import {createFrontendServer} from ${JSON.stringify(modulePath)}; const s=createFrontendServer({backend:process.env.TEST_BACKEND}); s.listen(0,'127.0.0.1',()=>console.log(s.address().port));`],
  { env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: cert, TEST_BACKEND: tlsAddress }, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (!child.killed) child.kill(); });
  let output = '';
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`HTTPS test startup failed: ${stderr}`)), 3000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output.includes('\n')) { clearTimeout(timer); resolve(Number(output.trim())); }
    });
  });
  const verified = await request(`http://127.0.0.1:${port}`, '/api/health');
  assert.equal(verified.status, 200);
  assert.equal(verified.text, 'verified TLS');
});

test('invalid backend origins fail at startup', () => {
  for (const backend of ['file:///tmp/private', 'https://user:secret@example.invalid',
    'https://example.invalid/private', 'https://example.invalid/?token=private']) {
    assert.throws(() => createFrontendServer({ backend }));
  }
});
