import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import { OperatorAuth, scryptOptions } from '../operator-auth.mjs';

const origin = 'https://watchdawg.example';
const password = 'a unique test passphrase';
const salt = 'cd'.repeat(16);
const record = { username: 'robert', salt, scopes: ['ai:audit'],
  hash: scryptSync(password, Buffer.from(salt, 'hex'), 64, scryptOptions).toString('hex') };
const req = cookie => ({ headers: { origin, cookie } });
const makeAuth = extras => new OperatorAuth({ users: [record], origin, ...extras });
const creds = { username: 'robert', password };

async function signIn(auth, credentials = creds) {
  const result = await auth.login(req(), credentials);
  assert.equal(result.status, 200);
  return result.cookie.split(';')[0];
}

test('configuration requires HTTPS and validates individual account records', () => {
  assert.throws(() => makeAuth({ origin: 'http://public.example' }));
  assert.throws(() => makeAuth({ origin: undefined }));
  assert.throws(() => makeAuth({ users: [record, record] }));
  assert.throws(() => makeAuth({ users: [{ ...record, scopes: ['admin'] }] }));
  assert.doesNotThrow(() => makeAuth({ origin: 'http://localhost:3000', bindHost: '127.0.0.1' }));
});

test('login cookies are protected, rotated, expiring, and revoked on logout', async () => {
  let now = 1000;
  const auth = makeAuth({ now: () => now });
  const first = await signIn(auth);
  assert.match(auth.cookie('fixture'), /__Host-watchdawg_session=.*HttpOnly; SameSite=Strict; Max-Age=900; Secure/);
  assert.equal(auth.authorize(req(first)).status, 200);
  assert.equal(auth.authorize(req(`${first}; ${first}`)).status, 401);
  const second = await signIn(auth);
  assert.notEqual(first, second);
  assert.equal(auth.authorize(req(first)).status, 401, 'previous login revoked');
  assert.equal(auth.authorize({headers:{cookie:second, origin:'https://evil.example'}}).status, 403);
  assert.equal(auth.logout({headers:{cookie:second}}).status, 403, 'logout requires origin');
  now += 900001;
  assert.equal(auth.authorize(req(second)).status, 401, 'expired session rejected');
  const third = await signIn(auth);
  assert.equal(auth.logout(req(third)).status, 200);
  assert.equal(auth.authorize(req(third)).status, 401);
});

test('unknown users and wrong passwords fail; scopes are checked separately', async () => {
  const auth = makeAuth();
  assert.equal((await auth.login(req(), {username:'nobody', password})).status, 401);
  assert.equal((await auth.login(req(), {username:'robert', password:'incorrect password value'})).status, 401);
  assert.equal((await auth.login({headers:{origin:'https://evil.example'}}, creds)).status, 403);
  assert.equal(auth.sessions.size, 0);
  const limited = makeAuth({users:[{...record, scopes:[]}]});
  const cookie = await signIn(limited);
  assert.equal(limited.authorize(req(cookie)).status, 403);
});

test('sign-in throttles guesses and paid calls are bounded per operator', async () => {
  const auth = makeAuth();
  const cookie = await signIn(auth);
  for (let i=0;i<5;i++) assert.equal(auth.authorize(req(cookie)).status, 200);
  assert.equal(auth.authorize(req(cookie)).status, 429);
  for (let i=0;i<5;i++) {
    assert.equal((await auth.login(req(), {...creds,password:'incorrect password value'})).status, 401);
  }
  assert.equal((await auth.login(req(), creds)).status, 429);
});

test('unconfigured accounts stay closed and arbitrary cookies grant nothing', async () => {
  const auth = new OperatorAuth();
  assert.equal((await auth.login(req(), creds)).status, 503);
  assert.equal(auth.authorize(req('watchdawg_local_session='+'ab'.repeat(32))).status, 401);
});
