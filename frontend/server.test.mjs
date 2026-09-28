import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDir = dirname(fileURLToPath(import.meta.url));
const projectRoot = fileURLToPath(new URL('../', import.meta.url));

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function reservePort() {
  const reservation = net.createServer();
  const port = await listen(reservation);
  await new Promise((resolve, reject) => reservation.close((error) => (error ? reject(error) : resolve())));
  return port;
}

async function waitForFrontend(baseUrl, child, stderr) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Frontend exited early (${child.exitCode}).\n${stderr()}`);
    try {
      const response = await fetch(`${baseUrl}/`, { signal: AbortSignal.timeout(500) });
      if (response.status === 200) return;
    } catch {
      // The child may still be binding its socket.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Frontend did not become ready.\n${stderr()}`);
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    once(child, 'exit'),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
}

const api = createServer((request, response) => {
  if (request.url === '/api/health') {
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ status: 'ok', service: 'watch-dawg-test' }));
    return;
  }
  response.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify({ detail: 'Not found' }));
});

const apiPort = await listen(api);
const frontendPort = await reservePort();
const baseUrl = `http://127.0.0.1:${frontendPort}`;
let frontendStderr = '';
const frontend = spawn(process.execPath, [join(frontendDir, 'server.mjs')], {
  cwd: projectRoot,
  env: {
    ...process.env,
    HOST: '127.0.0.1',
    PORT: String(frontendPort),
    REACT_APP_BACKEND_URL: `http://127.0.0.1:${apiPort}`,
    STATIC_ROOT: projectRoot,
  },
  stdio: ['ignore', 'ignore', 'pipe'],
});
frontend.stderr.setEncoding('utf8');
frontend.stderr.on('data', (chunk) => { frontendStderr += chunk; });

try {
  await waitForFrontend(baseUrl, frontend, () => frontendStderr);

  const root = await fetch(`${baseUrl}/`);
  assert.equal(root.status, 200);
  assert.match(root.headers.get('content-type') || '', /^text\/html\b/);
  assert.match(await root.text(), /Watch-Dawg/);

  const script = await fetch(`${baseUrl}/watchdawg.js`);
  assert.equal(script.status, 200);
  assert.match(script.headers.get('content-type') || '', /javascript/);
  assert.doesNotMatch(await script.text(), /<!doctype html>/i);

  const health = await fetch(`${baseUrl}/api/health`);
  assert.equal(health.status, 200);
  assert.match(health.headers.get('content-type') || '', /^application\/json\b/);
  assert.deepEqual(await health.json(), { status: 'ok', service: 'watch-dawg-test' });

  for (const path of ['/__missing_route__/', '/__missing_route__/watchdawg.js', '/app.js']) {
    const missing = await fetch(`${baseUrl}${path}`);
    assert.equal(missing.status, 404, `${path} must fail closed`);
    assert.match(missing.headers.get('content-type') || '', /^text\/plain\b/);
    assert.match(missing.headers.get('x-robots-tag') || '', /noindex/i);
    assert.equal(await missing.text(), 'Not found');
  }

  const verifier = spawn(process.execPath, [join(projectRoot, 'scripts/verify-emergent-routing.mjs'), baseUrl], {
    cwd: projectRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let verifierOutput = '';
  verifier.stdout.setEncoding('utf8');
  verifier.stderr.setEncoding('utf8');
  verifier.stdout.on('data', (chunk) => { verifierOutput += chunk; });
  verifier.stderr.on('data', (chunk) => { verifierOutput += chunk; });
  const [verifierCode] = await once(verifier, 'exit');
  assert.equal(verifierCode, 0, verifierOutput);
  assert.match(verifierOutput, /PASS: known routes remain available/);

  console.log('Frontend fail-closed routing tests passed');
} finally {
  await stopChild(frontend);
  await new Promise((resolve, reject) => api.close((error) => (error ? reject(error) : resolve())));
}
