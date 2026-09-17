import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';

const token = 'local-test-credential-'.repeat(3);

test('proxy authenticates callers and bounds bodies before any upstream call', async () => {
  const seen = [];
  const upstream = http.createServer(async (req, res) => {
    let bytes = 0;
    for await (const chunk of req) bytes += chunk.length;
    seen.push({ bytes, authorization: req.headers.authorization });
    res.end('mock backend');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const reserve = http.createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  const child = spawn(process.execPath, ['frontend/server.mjs'], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port),
      REACT_APP_BACKEND_URL: `http://127.0.0.1:${upstream.address().port}`,
      WATCH_DAWG_AI_API_TOKEN: token },
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
    async function request(body, authorization, chunked = false) {
      return new Promise((resolve, reject) => {
        const headers = { 'content-type': 'application/json' };
        if (authorization) headers.authorization = authorization;
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
    for (const chunked of [false, true]) {
      assert.equal(await request('x'.repeat(64001), `Bearer ${token}`, chunked), 413);
      assert.equal(seen.length, 0, 'oversized requests never reach upstream');
    }
    assert.equal(await request('x'.repeat(64000), `Bearer ${token}`, true), 200);
    assert.deepEqual(seen, [{ bytes: 64000, authorization: `Bearer ${token}` }]);
  } finally {
    child.kill();
    await exited;
    upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve));
  }
});
