import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scryptSync } from 'node:crypto';
import { scryptOptions } from '../operator-auth.mjs';

const token = 'local-test-credential-'.repeat(3);

test('proxy authenticates callers and bounds bodies before any upstream call', async () => {
  const seen = [];
  const upstream = http.createServer(async (req, res) => {
    let bytes = 0;
    for await (const chunk of req) bytes += chunk.length;
    seen.push({ bytes, authorization: req.headers.authorization, cookie: req.headers.cookie });
    res.end('mock backend');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const reserve = http.createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const password = 'a unique test passphrase';
  const salt = 'ab'.repeat(16);
  const directory = mkdtempSync(join(tmpdir(), 'watchdawg-session-'));
  const usersFile = join(directory, 'operators.json');
  writeFileSync(usersFile, JSON.stringify([{username: 'reviewer', salt,
    hash: scryptSync(password, Buffer.from(salt, 'hex'), 64, scryptOptions).toString('hex'),
    scopes: ['ai:audit']}]), {mode: 0o600});
  const child = spawn(process.execPath, ['frontend/server.mjs'], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port),
      REACT_APP_BACKEND_URL: `http://127.0.0.1:${upstream.address().port}`,
      WATCH_DAWG_AI_API_TOKEN: token, WATCH_DAWG_USERS_FILE: usersFile,
      WATCH_DAWG_PUBLIC_ORIGIN: origin },
    stdio: 'ignore',
  });
  const exited = once(child, 'exit');
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        await fetch(`http://127.0.0.1:${port}/test-readiness`);
        ready = true;
        break;
      } catch { await new Promise(resolve => setTimeout(resolve, 25)); }
    }
    assert.ok(ready, 'frontend starts');
    async function request(body, cookie, chunked = false, requestOrigin = origin) {
      return new Promise((resolve, reject) => {
        const headers = { 'content-type': 'application/json' };
        if (cookie) headers.cookie = cookie;
        headers.origin = requestOrigin;
        if (!chunked) headers['content-length'] = Buffer.byteLength(body);
        const req = http.request({ host: '127.0.0.1', port,
          path: '/api/ai/audit', method: 'POST', headers }, res => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', reject);
        if (chunked) {
          req.write(body.slice(0, 32000));
          req.write(body.slice(32000));
          req.end();
        } else req.end(body);
      });
    }
    assert.equal(await request('{}'), 401);
    assert.equal(await request('{}', 'Bearer wrong'), 401);
    assert.equal(seen.length, 0, 'anonymous callers never reach upstream');
    const loginPage = await fetch(`${origin}/login.html`);
    assert.equal(loginPage.status, 200);
    assert.match(loginPage.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.doesNotMatch(loginPage.headers.get('content-security-policy'), /unsafe-inline/);
    const loginStyles = await fetch(`${origin}/login.css`);
    assert.equal(loginStyles.status, 200);
    assert.equal(loginStyles.headers.get('cache-control'), 'no-store');
    const oversizedLogin = await fetch(`${origin}/auth/login`, {method:'POST', headers:{origin}, body:'x'.repeat(4097)});
    assert.equal(oversizedLogin.status, 413);
    const loginResponse = await fetch(`${origin}/auth/login`, {method: 'POST',
      headers: {origin, 'content-type': 'application/json'},
      body: JSON.stringify({username:'reviewer', password})});
    assert.equal(loginResponse.status, 200);
    const loginText = await loginResponse.text();
    assert.ok(!loginText.includes(token) && !loginText.includes(password));
    const cookieHeader = loginResponse.headers.get('set-cookie');
    assert.match(cookieHeader, /HttpOnly/);
    assert.match(cookieHeader, /SameSite=Strict/);
    assert.match(cookieHeader, /Priority=High/);
    const cookie = cookieHeader.split(';')[0];
    assert.equal(await request('{}', cookie, false, 'https://evil.example'), 403);
    assert.equal(seen.length, 0);
    const rawToken = await fetch(`${origin}/api/ai/audit`, {method:'POST',
      headers:{authorization:`Bearer ${token}`}, body:'{}'});
    assert.equal(rawToken.status, 401, 'service token is not browser authentication');
    for (const chunked of [false, true]) {
      assert.equal(await request('x'.repeat(64001), cookie, chunked), 413);
      assert.equal(seen.length, 0, 'oversized requests never reach upstream');
    }
    assert.equal(await request('x'.repeat(64000), cookie, true), 200);
    assert.deepEqual(seen, [{ bytes: 64000, authorization: `Bearer ${token}`, cookie: undefined }]);
    const out = await fetch(`${origin}/auth/logout`, {method:'POST', headers:{origin, cookie}});
    assert.equal(out.status, 200);
    assert.equal(await request('{}', cookie), 401);
    assert.equal(seen.length, 1, 'logged-out session cannot call upstream');
  } finally {
    child.kill();
    await exited;
    upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve));
    rmSync(directory, {recursive: true});
  }
});
