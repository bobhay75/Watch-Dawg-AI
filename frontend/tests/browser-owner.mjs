import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { chromium } from 'playwright';
import { createFrontendServer } from '../server.mjs';
import { hashOwnerPassword } from '../owner-session.mjs';
import { runWatchDawg, sampleScenarios } from '../../watchdawg.js';

const password = 'Synthetic-owner-browser-passphrase-only';
const token = 'synthetic_browser_backend_token_only_000000000000';
const directory = await mkdtemp(join(tmpdir(), 'watchdawg-owner-browser-'));
const output = new URL('../test-results/', import.meta.url);
await mkdir(output, { recursive: true });
const certPath = join(directory, 'certificate.pem');
const keyPath = join(directory, 'key.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
  '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' });
const tls = { cert: await readFile(certPath), key: await readFile(keyPath) };
const passwordHash = await hashOwnerPassword(password);
const browser = await chromium.launch({ headless: true,
  executablePath: process.env.WATCHDAWG_TEST_CHROMIUM_PATH || undefined });
const servers = [];
const results = [];

async function listen(server, port = 0) {
  servers.push(server);
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
async function fixture(enabled) {
  const captured = [];
  const held = [];
  let mode = 'complete';
  let offset = 0;
  let closed = 0;
  const backendPort = await listen(http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    assert.equal(req.headers.authorization, `Bearer ${token}`);
    captured.push(JSON.parse(Buffer.concat(chunks).toString()));
    res.on('close', () => { closed++; });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: {"delta":"Synthetic local test insight."}\n\n');
    if (mode === 'hold') held.push(res);
    else if (mode === 'truncated') res.end();
    else res.end('data: {"done":true}\n\n');
  }));
  const reservation = http.createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const origin = `https://127.0.0.1:${port}`;
  await listen(createFrontendServer({ backend: `http://127.0.0.1:${backendPort}`, tls,
    ownerClock: () => Date.now() + offset,
    ownerConfig: enabled ? { ownerId: 'owner-test', passwordHash, backendToken: token,
      publicOrigin: origin, trustedProxyAddresses: [] } : undefined }), port);
  return { origin, captured, held, mode(value) { mode = value; },
    advance(value) { offset += value; }, closed: () => closed };
}
async function signIn(page) {
  await page.locator('#ownerUsername').fill('owner-test');
  await page.locator('#ownerPassword').fill(password);
  await page.locator('#ownerSubmit').click();
  await page.waitForFunction(() => document.querySelector('#ownerStatus').textContent.startsWith('Signed in as owner-test'));
  assert.equal(await page.locator('#ownerPassword').inputValue(), '');
}
async function waitStatus(page, text) {
  await page.waitForFunction(value => document.querySelector('#aiStatus').textContent === value, text);
}

try {
  const disabled = await fixture(false);
  const disabledContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const disabledPage = await disabledContext.newPage();
  await disabledPage.goto(disabled.origin);
  await disabledPage.waitForFunction(() => document.querySelector('#ownerStatus').textContent.includes('not configured'));
  await disabledPage.locator('#runButton').click();
  await waitStatus(disabledPage, 'Owner sign-in required');
  assert.equal(disabled.captured.length, 0);
  assert.notEqual(await disabledPage.locator('#report').textContent(), 'Ready.');
  assert.equal(await disabledPage.locator('#ownerLogin').isVisible(), false);
  results.push('Disabled mode remains a usable deterministic audit and makes no AI request');
  await disabledContext.close();

  const live = await fixture(true);
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  await page.clock.install();
  const browserHeaders = [];
  page.on('request', req => { if (req.url().includes('/api/')) browserHeaders.push(req.headers()); });
  await page.goto(live.origin);
  await page.locator('#ownerUsername').waitFor({ state: 'visible' });
  await page.locator('[data-testid="ai-insights-panel"]').screenshot({ path: new URL('owner-login-desktop.png', output).pathname });
  await signIn(page);
  const cookies = await context.cookies();
  const session = cookies.find(cookie => cookie.name === '__Host-WatchDawgSession');
  assert.equal(session.secure, true);
  assert.equal(session.httpOnly, true);
  assert.equal(session.sameSite, 'Strict');
  const browserStorage = await page.evaluate(() => ({ cookie: document.cookie,
    local: Object.entries(localStorage), session: Object.entries(sessionStorage) }));
  const visible = await page.content();
  for (const value of [token, passwordHash, password]) {
    assert.equal((visible + JSON.stringify(browserStorage)).includes(value), false);
  }
  assert.equal(browserStorage.cookie.includes('__Host-WatchDawgSession'), false);
  results.push('Real HTTPS login sets an HttpOnly Secure Strict cookie and clears the password without exposing server secrets');

  const arrived = deferred();
  const release = deferred();
  let delayNext = true;
  await page.route('**/auth/session', async route => {
    if (delayNext) { delayNext = false; arrived.resolve(); await release.promise; }
    await route.continue();
  });
  await page.locator('#input').fill(JSON.stringify(sampleScenarios.verified));
  await page.locator('#runButton').click();
  await arrived.promise;
  await page.locator('#input').fill(JSON.stringify(sampleScenarios.anomaly));
  release.resolve();
  await waitStatus(page, 'ChatGPT analysis complete');
  await page.unroute('**/auth/session');
  assert.deepEqual(live.captured.at(-1).payload, sampleScenarios.verified);
  assert.deepEqual(live.captured.at(-1).deterministic_result, runWatchDawg(sampleScenarios.verified));
  assert.equal(live.captured.at(-1).report, runWatchDawg(sampleScenarios.verified).report);
  assert.equal(browserHeaders.some(headers => headers.authorization !== undefined), false);
  results.push('Run button reaches the authorized synthetic backend and preserves its input/result snapshot during delayed session IO');

  live.mode('truncated');
  await page.locator('#runButton').click();
  await waitStatus(page, 'AI analysis incomplete');
  assert.match(await page.locator('#aiInsights').textContent(), /partial answer is incomplete/);
  results.push('Early SSE EOF never displays a successful completed analysis');

  live.mode('hold');
  await page.locator('#runButton').click();
  await page.waitForFunction(() => document.querySelector('#aiInsights').textContent.includes('Synthetic local test insight'));
  await page.locator('#ownerLogout').click();
  await waitStatus(page, 'Owner signed out');
  for (const res of live.held.splice(0)) if (!res.destroyed) res.end('data: {"done":true}\n\n');
  assert.equal((await page.locator('#aiInsights').textContent()).includes('Synthetic local test insight'), false);
  assert.equal(await page.locator('#ownerLogout').isVisible(), false);
  assert.equal((await context.cookies()).some(cookie => cookie.name === '__Host-WatchDawgSession'), false);
  results.push('Logout during a real streamed request clears results, aborts the request and revokes the cookie');

  await signIn(page);
  await page.locator('#runButton').click();
  await page.waitForFunction(() => document.querySelector('#aiInsights').textContent.includes('Synthetic local test insight'));
  live.advance(31 * 60_000);
  await page.clock.fastForward(31 * 60_000);
  await waitStatus(page, 'Owner sign-in required');
  assert.equal(await page.locator('#ownerLogout').isVisible(), false);
  assert.equal((await page.locator('#aiInsights').textContent()).includes('Synthetic local test insight'), false);
  for (const res of live.held.splice(0)) if (!res.destroyed) res.end('data: {"done":true}\n\n');
  assert.equal(await page.locator('#aiStatus').textContent(), 'Owner sign-in required');
  results.push('Session deadline while an audit is pending cancels the old result and leaves sign-in required');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('[data-testid="ai-insights-panel"]').screenshot({ path: new URL('owner-login-mobile.png', output).pathname });
  const mobileLayout = await page.evaluate(() => ({
    viewportWidth: innerWidth,
    documentWidth: document.documentElement.scrollWidth,
    controls: ['ownerUsername', 'ownerPassword', 'ownerSubmit'].map(id => {
      const { x, width, height } = document.getElementById(id).getBoundingClientRect();
      return { id, x, width, height };
    })
  }));
  await writeFile(new URL('owner-mobile-layout.json', output), JSON.stringify(mobileLayout, null, 2) + '\n');
  assert.ok(mobileLayout.documentWidth <= mobileLayout.viewportWidth + 1);
  for (const control of mobileLayout.controls) {
    assert.ok(control.x >= 0 && control.x + control.width <= mobileLayout.viewportWidth);
    assert.ok(control.width > 0 && control.height > 0);
  }
  results.push('Owner form remains usable at a 390-pixel mobile viewport');
  await context.close();
  await writeFile(new URL('owner-browser-results.json', output), JSON.stringify({
    browser: browser.version(), assertions: results, syntheticOnly: true,
    note: 'A temporary self-signed loopback certificate is accepted only by this test browser context.'
  }, null, 2) + '\n');
  console.log(JSON.stringify({ browser: browser.version(), passed: results.length, assertions: results }, null, 2));
} finally {
  await browser.close();
  for (const server of servers.reverse()) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  await rm(directory, { recursive: true, force: true });
}
