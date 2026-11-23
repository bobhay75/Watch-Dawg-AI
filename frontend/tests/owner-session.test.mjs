import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { chmod, link, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { createFrontendServer } from '../server.mjs';
import { createOwnerSession, hashOwnerPassword, loadOwnerConfig, readPrivateFile } from '../owner-session.mjs';

const PASSWORD = 'Synthetic-owner-passphrase-only-2026';
const BACKEND_TOKEN = 'synthetic_backend_owner_token_only_0000000000000000';
const passwordHash = hashOwnerPassword(PASSWORD);
const ORIGIN = 'https://console.example.invalid';

async function config(overrides = {}) {
  return { ownerId: 'owner-test', passwordHash: await passwordHash, backendToken: BACKEND_TOKEN,
    publicOrigin: ORIGIN, trustedProxyAddresses: ['127.0.0.1'], ...overrides };
}
async function listen(t, server, tls = false) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return `${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
}
function request(base, path, { method = 'GET', headers = {}, body, ca } = {}) {
  return new Promise((resolve, reject) => {
    const transport = base.startsWith('https:') ? https : http;
    const req = transport.request(base + path, { method, headers, ca, agent: false }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, text,
          data: res.headers['content-type']?.includes('application/json') ? JSON.parse(text) : null });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Test request timeout')));
    req.end(body);
  });
}
const approved = (extra = {}) => ({ host: 'console.example.invalid', origin: ORIGIN,
  'x-forwarded-proto': 'https', ...extra });
async function fixture(t, overrides = {}, handler = (_req, res) => res.end('{}')) {
  const backend = await listen(t, http.createServer(handler));
  return listen(t, createFrontendServer({ backend, ownerConfig: await config(), ...overrides }));
}
async function login(base, extra = {}) {
  const result = await request(base, '/auth/login', { method: 'POST',
    headers: approved({ 'content-type': 'application/json', ...extra }),
    body: JSON.stringify({ username: 'owner-test', password: PASSWORD }) });
  assert.equal(result.status, 200, result.text);
  return { ...result, cookie: result.headers['set-cookie'][0].split(';')[0], csrf: result.data.csrf };
}

test('disabled owner mode is explicit and creates no account or session', async t => {
  const backend = await listen(t, http.createServer((_req, res) => res.end('{}')));
  const base = await listen(t, createFrontendServer({ backend }));
  const status = await request(base, '/auth/session');
  assert.deepEqual(status.data, { enabled: false, authenticated: false });
  assert.equal(status.headers['set-cookie'], undefined);
  assert.equal((await request(base, '/auth/login', { method: 'POST' })).status, 404);
  assert.equal((await request(base, '/')).status, 200);
});

test('private config rejects public permissions, symlinks, hardlinks and oversized files', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'watchdawg-owner-config-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const token = join(dir, 'backend-token');
  const file = join(dir, 'owner-config');
  await writeFile(token, BACKEND_TOKEN, { mode: 0o600 });
  await writeFile(file, JSON.stringify({ owner_id: 'owner-test', password_hash: await passwordHash,
    backend_token_file: token, public_origin: ORIGIN, trusted_proxy_addresses: ['127.0.0.1'] }), { mode: 0o600 });
  assert.equal(loadOwnerConfig(file).backendToken, BACKEND_TOKEN);
  assert.equal(loadOwnerConfig(undefined), undefined);
  await chmod(file, 0o644);
  assert.throws(() => loadOwnerConfig(file), /cannot be loaded safely/);
  await chmod(file, 0o600);
  await symlink(file, join(dir, 'linked'));
  assert.throws(() => loadOwnerConfig(join(dir, 'linked')), /cannot be loaded safely/);
  await link(file, join(dir, 'hardlink'));
  assert.throws(() => loadOwnerConfig(file), /cannot be loaded safely/);
  await writeFile(join(dir, 'large'), 'x'.repeat(16385), { mode: 0o600 });
  assert.throws(() => readPrivateFile(join(dir, 'large')), /cannot be loaded safely/);
});

test('unsafe owner origins, hashes, credentials and remote plaintext backends fail at startup', async () => {
  const valid = await config();
  for (const overrides of [
    { publicOrigin: 'http://console.example.invalid' }, { publicOrigin: ORIGIN + '/path' },
    { passwordHash: 'plaintext' }, { backendToken: 'short' },
    { trustedProxyAddresses: ['198.51.100.1'] }, { ownerId: 'owner\nadmin' },
  ]) assert.throws(() => createOwnerSession({ ...valid, ...overrides }));
  assert.throws(() => createFrontendServer({ backend: 'http://private.example.invalid', ownerConfig: {} }), /verified HTTPS/);
  await assert.rejects(hashOwnerPassword('short'));
});

test('TLS attestation is accepted only from explicitly configured loopback peers and exact origin', async t => {
  const untrusted = await fixture(t, { ownerConfig: await config({ trustedProxyAddresses: [] }) });
  assert.equal((await request(untrusted, '/auth/session', { headers: approved() })).status, 403);
  const base = await fixture(t);
  for (const headers of [
    { host: 'console.example.invalid' }, approved({ host: 'attacker.invalid' }),
    approved({ origin: 'https://attacker.invalid' }), approved({ origin: 'null' }),
    approved({ 'x-forwarded-proto': 'https,http' }), approved({ 'sec-fetch-site': 'cross-site' }),
  ]) assert.equal((await request(base, '/auth/session', { headers })).status, 403);
  assert.equal((await request(base, '/auth/session', { headers: approved() })).status, 200);
  assert.equal((await request(base, '/auth%2flogin', { method: 'POST', headers: approved() })).status, 400);
  assert.equal((await request(base, '/auth/login?role=admin', { method: 'POST', headers: approved() })).status, 400);
});

test('login has a secure opaque cookie, rotated sessions and no secret response content', async t => {
  const base = await fixture(t);
  const first = await login(base);
  assert.match(first.headers['set-cookie'][0], /^__Host-WatchDawgSession=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800$/);
  assert.equal(first.headers['cache-control'], 'no-store');
  assert.equal(first.data.owner, 'owner-test');
  assert.match(first.csrf, /^[A-Za-z0-9_-]{43}$/);
  const next = await login(base, { cookie: first.cookie });
  assert.notEqual(next.cookie, first.cookie);
  assert.notEqual(next.csrf, first.csrf);
  assert.equal((await request(base, '/auth/session', { headers: approved({ cookie: first.cookie }) })).data.authenticated, false);
  for (const path of ['/', '/owner-client.js', '/auth/session']) {
    const res = await request(base, path, { headers: approved({ cookie: next.cookie }) });
    for (const secret of [PASSWORD, BACKEND_TOKEN, await passwordHash]) assert.equal(res.text.includes(secret), false);
  }
  assert.equal((await request(base, '/frontend/owner-session.mjs')).status, 404);
});

test('valid sessions and CSRF are required before the scoped backend credential is used', async t => {
  const seen = [];
  const base = await fixture(t, {}, (req, res) => {
    seen.push(req.headers);
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end('{"detail":"Backend scope denied"}');
  });
  const audit = headers => request(base, '/api/ai/audit', { method: 'POST', headers: approved({ 'content-type': 'application/json', ...headers }), body: '{}' });
  assert.equal((await audit({})).status, 401);
  const session = await login(base);
  assert.equal((await audit({ cookie: session.cookie })).status, 403);
  assert.equal((await audit({ cookie: session.cookie, 'x-csrf-token': 'x'.repeat(43) })).status, 403);
  assert.equal((await audit({ cookie: session.cookie, 'x-csrf-token': session.csrf, authorization: 'Bearer override' })).status, 400);
  assert.equal((await audit({ cookie: session.cookie + '; ' + session.cookie, 'x-csrf-token': session.csrf })).status, 401);
  assert.equal(seen.length, 0);
  const result = await audit({ cookie: session.cookie, 'x-csrf-token': session.csrf, 'x-role': 'admin', 'x-scopes': '*' });
  assert.equal(result.status, 403);
  assert.equal(result.data.detail, 'Backend scope denied');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].authorization, `Bearer ${BACKEND_TOKEN}`);
  for (const name of ['cookie', 'x-csrf-token', 'x-role', 'x-scopes', 'x-forwarded-proto']) assert.equal(seen[0][name], undefined);
});

test('logout invalidates the server session and cannot be invoked without same-origin CSRF', async t => {
  const base = await fixture(t);
  const session = await login(base);
  assert.equal((await request(base, '/auth/logout', { method: 'POST', headers: approved({ cookie: session.cookie }) })).status, 403);
  const logout = await request(base, '/auth/logout', { method: 'POST', headers: approved({ cookie: session.cookie, 'x-csrf-token': session.csrf }) });
  assert.equal(logout.status, 200);
  assert.match(logout.headers['set-cookie'][0], /Max-Age=0$/);
  assert.equal((await request(base, '/api/health', { headers: approved({ cookie: session.cookie }) })).status, 401);
});

test('idle and absolute expiry reject old cookies without relaxing backend authorization', async t => {
  let time = Date.now();
  const base = await fixture(t, { ownerClock: () => time });
  const first = await login(base);
  time += 30 * 60_000;
  assert.equal((await request(base, '/api/health', { headers: approved({ cookie: first.cookie }) })).status, 401);
  const second = await login(base);
  for (let i = 0; i < 23; i++) {
    time += 20 * 60_000;
    assert.equal((await request(base, '/auth/session', { headers: approved({ cookie: second.cookie }) })).data.authenticated, true);
  }
  time += 20 * 60_000;
  assert.equal((await request(base, '/api/health', { headers: approved({ cookie: second.cookie }) })).status, 401);
});

test('failed login attempts are bounded and spoofed forwarding addresses cannot reset the peer limit', async t => {
  const base = await fixture(t);
  for (let i = 0; i < 5; i++) {
    const result = await request(base, '/auth/login', { method: 'POST',
      headers: approved({ 'content-type': 'application/json', 'x-forwarded-for': `198.51.100.${i}` }),
      body: JSON.stringify({ username: i ? 'unknown-owner' : 'owner-test', password: 'wrong synthetic password' }) });
    assert.equal(result.status, 401);
  }
  const blocked = await request(base, '/auth/login', { method: 'POST', headers: approved({ 'content-type': 'application/json' }),
    body: JSON.stringify({ username: 'owner-test', password: PASSWORD }) });
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers['retry-after']) > 0);
  assert.equal(blocked.headers['set-cookie'], undefined);
});

test('real HTTPS frontend accepts its origin without trusting proxy headers', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'watchdawg-owner-tls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const certPath = join(dir, 'cert.pem');
  const keyPath = join(dir, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=console.example.invalid', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:console.example.invalid',
    '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' });
  const cert = await readFile(certPath);
  const backend = await listen(t, http.createServer((_req, res) => res.end('{}')));
  const base = await listen(t, createFrontendServer({ backend, ownerConfig: await config({ trustedProxyAddresses: [] }),
    tls: { key: await readFile(keyPath), cert } }), true);
  const result = await request(base, '/auth/login', { method: 'POST', ca: cert,
    headers: { host: 'console.example.invalid', origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'owner-test', password: PASSWORD }) });
  assert.equal(result.status, 200, result.text);
  await assert.rejects(request(base, '/auth/session', { headers: { host: 'console.example.invalid' } }));
});
