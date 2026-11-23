import assert from 'node:assert/strict';
import test from 'node:test';
import { createOwnerClient, readAiStream } from '../../owner-client.js';

const encoder = new TextEncoder();
const signedIn = () => ({ enabled: true, authenticated: true, owner: 'synthetic-owner',
  csrf: 'x'.repeat(43), expiresAt: Date.now() + 60_000 });
const json = data => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
function stream(chunks) {
  return new Response(new ReadableStream({ start(controller) {
    for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
    controller.close();
  } }), { headers: { 'content-type': 'text/event-stream' } });
}

test('SSE accepts chunk boundaries and CRLF only with a complete done frame', async () => {
  let answer = '';
  await readAiStream(stream(['data: {"del', 'ta":"hello"}\r\n\r\n', 'data: {"done":true}\n', '\n']), part => { answer += part; });
  assert.equal(answer, 'hello');
});

test('EOF, truncated completion, provider errors and output after completion stay incomplete', async () => {
  for (const chunks of [
    ['data: {"delta":"partial"}\n\n'],
    ['data: {"delta":"partial"}\n\ndata: {"done":true}'],
    ['data: {"error":"synthetic failure"}\n\n'],
    ['data: {"done":true}\n\ndata: {"delta":"late"}\n\n'],
  ]) await assert.rejects(readAiStream(stream(chunks), () => {}));
});

test('disabled mode never requests AI or invents an authenticated owner', async () => {
  const calls = [];
  let state;
  const client = createOwnerClient(value => { state = value; }, async path => {
    calls.push(path);
    return json({ enabled: false, authenticated: false });
  });
  await assert.rejects(client.audit({}, undefined, () => {}), /not configured/);
  assert.deepEqual(calls, ['/auth/session']);
  assert.equal(state.authenticated, false);
});

test('a late pre-logout session response cannot restore authenticated UI', async () => {
  const initial = deferred();
  const states = [];
  let queries = 0;
  const client = createOwnerClient(value => states.push(value), async path => {
    if (path === '/auth/session' && ++queries === 1) return initial.promise;
    if (path === '/auth/logout') return json({ enabled: true, authenticated: false });
    return json(signedIn());
  });
  const old = client.refresh();
  await client.logout();
  const afterLogout = states.length;
  initial.resolve(json(signedIn()));
  await old;
  await client.refresh();
  assert.equal(states.at(-1).authenticated, false);
  assert.equal(states.slice(afterLogout).some(state => state.authenticated), false);
});

test('logout waits for a pending login cookie before revoking the server session', async () => {
  const pendingLogin = deferred();
  const calls = [];
  const states = [];
  const client = createOwnerClient(value => states.push(value), async path => {
    calls.push(path);
    if (path === '/auth/login') return pendingLogin.promise;
    return json(path === '/auth/logout' ? { enabled: true, authenticated: false } : signedIn());
  });
  const login = client.login('synthetic-owner', 'synthetic-password');
  const logout = client.logout();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['/auth/login']);
  pendingLogin.resolve(json(signedIn()));
  await Promise.all([login, logout]);
  assert.deepEqual(calls, ['/auth/login', '/auth/session', '/auth/logout']);
  assert.equal(states.some(state => state.authenticated), false);
});

test('an older failed session check cannot replace a newer successful login', async () => {
  const initial = deferred();
  let state;
  const client = createOwnerClient(value => { state = value; }, async path => {
    if (path === '/auth/session') return initial.promise;
    return json(signedIn());
  });
  const old = client.refresh();
  const rejected = assert.rejects(old);
  await client.login('synthetic-owner', 'synthetic-password');
  initial.resolve(new Response('unavailable', { status: 503 }));
  await rejected;
  assert.equal(state.authenticated, true);
  assert.equal(state.unavailable, false);
});

async function pendingAuditFixture(expiry = 60_000) {
  let state;
  let abortSignal;
  const began = deferred();
  const session = { ...signedIn(), expiresAt: Date.now() + expiry };
  const client = createOwnerClient(value => { state = value; }, async (path, options) => {
    if (path === '/api/ai/audit') {
      abortSignal = options.signal;
      return new Response(new ReadableStream({ start(controller) {
        controller.enqueue(encoder.encode('data: {"delta":"partial"}\n\n'));
        options.signal.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), { once: true });
        began.resolve();
      } }));
    }
    return json(path === '/auth/logout' ? { enabled: true, authenticated: false } : session);
  });
  let answer = '';
  const audit = client.audit({ synthetic: true }, undefined, delta => { answer += delta; });
  const rejected = assert.rejects(audit, /Abort|superseded/);
  await began.promise;
  return { client, rejected, state: () => state, signal: () => abortSignal, answer: () => answer };
}

test('logout aborts an in-flight stream and rejects completion under the old session', async () => {
  const f = await pendingAuditFixture();
  await f.client.logout();
  await f.rejected;
  assert.equal(f.signal().aborted, true);
  assert.equal(f.state().authenticated, false);
});

test('absolute/idle deadline expires the client while an audit response is pending', async () => {
  const f = await pendingAuditFixture(70);
  // Hold the test process while the session's unref'ed deadline cancels the pending stream.
  await new Promise(resolve => setTimeout(resolve, 100));
  await f.rejected;
  assert.equal(f.signal().aborted, true);
  assert.equal(f.state().authenticated, false);
  await f.client.refresh();
  assert.equal(f.state().authenticated, false);
});

test('new login aborts the older streamed request before publishing the new session', async () => {
  const f = await pendingAuditFixture();
  await f.client.login('synthetic-owner', 'synthetic-password');
  await f.rejected;
  assert.equal(f.signal().aborted, true);
  assert.equal(f.state().authenticated, true);
});

test('unconfirmed logout stays locally blocked and can be retried without restoring UI', async () => {
  let unavailable = true;
  let state;
  const client = createOwnerClient(value => { state = value; }, async path => {
    if (path === '/auth/logout' && unavailable) throw new Error('Synthetic connection failure');
    return json(path === '/auth/logout' ? { enabled: true, authenticated: false } : signedIn());
  });
  await client.refresh();
  await assert.rejects(client.logout(), /Synthetic/);
  assert.equal(state.authenticated, false);
  assert.equal(state.signoutUnconfirmed, true);
  await client.refresh();
  assert.equal(state.authenticated, false);
  unavailable = false;
  await client.logout();
  assert.equal(state.signoutUnconfirmed, false);
});

test('backend credential refusal is distinct from an expired browser session', async () => {
  let state;
  const client = createOwnerClient(value => { state = value; }, async path => {
    if (path === '/api/ai/audit') return new Response('{}', { status: 401, headers: { 'www-authenticate': 'Bearer' } });
    return json(signedIn());
  });
  await assert.rejects(client.audit({}, undefined, () => {}), /backend authorization/);
  assert.equal(state.authenticated, true);
});

test('late 401 from an aborted old audit cannot clear a newer login', async () => {
  const oldResponse = deferred();
  const started = deferred();
  let state;
  let nonce = 'x';
  const client = createOwnerClient(value => { state = value; }, async path => {
    if (path === '/api/ai/audit') { started.resolve(); return oldResponse.promise; }
    if (path === '/auth/login') nonce = 'y';
    return json({ ...signedIn(), csrf: nonce.repeat(43) });
  });
  const audit = client.audit({}, undefined, () => {});
  const rejected = assert.rejects(audit, /superseded/);
  await started.promise;
  await client.login('synthetic-owner', 'synthetic-password');
  oldResponse.resolve(new Response('{}', { status: 401 }));
  await rejected;
  assert.equal(state.authenticated, true);
});

test('a never-resolving login has a deadline and logout cannot wait forever behind it', async () => {
  const delayed = deferred();
  let loginSignal;
  let state;
  const client = createOwnerClient(value => { state = value; }, async (path, options) => {
    if (path === '/auth/login') { loginSignal = options.signal; return delayed.promise; }
    return json(path === '/auth/logout' ? { enabled: true, authenticated: false } : signedIn());
  }, { authTimeoutMs: 25 });
  const login = client.login('synthetic-owner', 'synthetic-password');
  const rejected = assert.rejects(login, /timed out/);
  const logout = client.logout();
  await Promise.all([rejected, logout]);
  assert.equal(loginSignal.aborted, true);
  assert.equal(state.authenticated, false);
  delayed.resolve(json(signedIn()));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(state.authenticated, false);
});

test('the authentication deadline also covers a stalled JSON response body', async () => {
  let signal;
  let state;
  const client = createOwnerClient(value => { state = value; }, async (_path, options) => {
    signal = options.signal;
    return { ok: true, json: () => new Promise(() => {}) };
  }, { authTimeoutMs: 20 });
  await assert.rejects(client.refresh(), /timed out/);
  assert.equal(signal.aborted, true);
  assert.equal(state.authenticated, false);
  assert.equal(state.unavailable, true);
});
