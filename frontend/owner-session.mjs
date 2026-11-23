import { constants, closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const HASH_FORMAT = /^watchdawg-scrypt-v1\$([0-9a-f]{32})\$([0-9a-f]{64})$/;
const HASH_OPTIONS = Object.freeze({ N: 131072, r: 8, p: 1, maxmem: 160 * 1024 * 1024 });
const COOKIE = '__Host-WatchDawgSession';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const MINUTE = 60_000;
const IDLE_MS = 30 * MINUTE;
const ABSOLUTE_MS = 8 * 60 * MINUTE;
const ATTEMPT_WINDOW_MS = 15 * MINUTE;

function digest(value) { return createHash('sha256').update(value).digest(); }
function equal(left, right) { return timingSafeEqual(digest(left), digest(right)); }
function peer(req) { return (req.socket.remoteAddress || '').replace(/^::ffff:/, ''); }
function headerCount(req, name) {
  let count = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === name) count++;
  }
  return count;
}

function json(res, status, data, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store', 'pragma': 'no-cache', ...headers });
  res.end(JSON.stringify(data));
}

function reject(req, res, status, detail, headers = {}) {
  req.resume();
  json(res, status, { detail }, headers);
  return null;
}

/** Private configuration must be an owned regular file, not a link or shared-readable file. */
export function readPrivateFile(path, maximum = 16 * 1024) {
  let fd;
  try {
    if (typeof path !== 'string' || !path.startsWith('/')) throw new Error();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077) || info.nlink !== 1
        || info.size > maximum) throw new Error();
    const value = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < value.length) {
      const count = readSync(fd, value, length, value.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > maximum) throw new Error();
    return new TextDecoder('utf-8', { fatal: true }).decode(value.subarray(0, length));
  } catch {
    throw new Error('Owner configuration cannot be loaded safely');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function loadOwnerConfig(path) {
  if (!path) return undefined;
  try {
    const raw = JSON.parse(readPrivateFile(path));
    const allowed = new Set(['owner_id', 'password_hash', 'backend_token_file', 'public_origin',
      'trusted_proxy_addresses']);
    if (!raw || Array.isArray(raw) || Object.keys(raw).some(key => !allowed.has(key))) throw new Error();
    return { ownerId: raw.owner_id, passwordHash: raw.password_hash,
      backendToken: readPrivateFile(raw.backend_token_file, 256).trim(),
      publicOrigin: raw.public_origin, trustedProxyAddresses: raw.trusted_proxy_addresses || [] };
  } catch {
    throw new Error('Owner configuration cannot be loaded safely');
  }
}

/** Setup helper only: no password or account is generated automatically. */
export async function hashOwnerPassword(password) {
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 12 || bytes > 1024 || password.includes('\0')) {
    throw new Error('Choose a password of 12–1024 UTF-8 bytes without NUL characters');
  }
  const salt = randomBytes(16);
  const key = await derive(password, salt, 32, HASH_OPTIONS);
  return `watchdawg-scrypt-v1$${salt.toString('hex')}$${key.toString('hex')}`;
}

/** One explicitly configured owner; state is bounded, in memory, and lost on restart. */
export function createOwnerSession(config, { now = () => Date.now() } = {}) {
  const origin = new URL(config.publicOrigin);
  const match = typeof config.passwordHash === 'string' && HASH_FORMAT.exec(config.passwordHash);
  if (origin.protocol !== 'https:' || origin.origin !== config.publicOrigin || origin.username
      || origin.password || origin.pathname !== '/' || origin.search || origin.hash
      || !/^[A-Za-z0-9_-]{1,64}$/.test(config.ownerId || '') || !match
      || !/^[A-Za-z0-9_-]{43,128}$/.test(config.backendToken || '')
      || !Array.isArray(config.trustedProxyAddresses)
      || config.trustedProxyAddresses.some(address => !['127.0.0.1', '::1'].includes(address))) {
    throw new Error('Invalid owner session configuration');
  }
  const ownerId = config.ownerId;
  const backendAuthorization = `Bearer ${config.backendToken}`;
  const salt = Buffer.from(match[1], 'hex');
  const passwordDigest = Buffer.from(match[2], 'hex');
  const trustedProxies = new Set(config.trustedProxyAddresses);
  const sessions = new Map();
  const attempts = new Map();
  let globalAttempts = { start: now(), count: 0 };
  let activeHash = false;

  function secureRequest(req, res, requireOrigin = false) {
    const encrypted = req.socket.encrypted === true;
    const proxyTls = trustedProxies.has(peer(req))
      && headerCount(req, 'x-forwarded-proto') === 1 && req.headers['x-forwarded-proto'] === 'https';
    if ((!encrypted && !proxyTls) || headerCount(req, 'host') !== 1
        || req.headers.host?.toLowerCase() !== origin.host) {
      return reject(req, res, 403, 'Approved HTTPS origin required');
    }
    const requestOrigin = req.headers.origin;
    if ((requireOrigin && requestOrigin !== origin.origin)
        || (requestOrigin !== undefined && (headerCount(req, 'origin') !== 1 || requestOrigin !== origin.origin))
        || (req.headers['sec-fetch-site'] !== undefined
          && !['same-origin', 'none'].includes(req.headers['sec-fetch-site']))) {
      return reject(req, res, 403, 'Same-origin request required');
    }
    return true;
  }

  function prune() {
    const time = now();
    for (const [id, session] of sessions) {
      if (time >= session.created + ABSOLUTE_MS || time >= session.last + IDLE_MS) sessions.delete(id);
    }
    for (const [address, attempt] of attempts) {
      if (time >= attempt.start + ATTEMPT_WINDOW_MS) attempts.delete(address);
    }
    if (time >= globalAttempts.start + ATTEMPT_WINDOW_MS) globalAttempts = { start: time, count: 0 };
  }

  function sessionFor(req) {
    if (headerCount(req, 'cookie') > 1) return null;
    const values = (req.headers.cookie || '').split(';').map(part => part.trim())
      .filter(part => part.startsWith(`${COOKIE}=`)).map(part => part.slice(COOKIE.length + 1));
    if (values.length !== 1 || !TOKEN.test(values[0])) return null;
    const id = digest(values[0]).toString('hex');
    const session = sessions.get(id);
    return session ? { id, ...session } : null;
  }

  function csrfValid(req, session) {
    return headerCount(req, 'x-csrf-token') === 1 && typeof req.headers['x-csrf-token'] === 'string'
      && TOKEN.test(req.headers['x-csrf-token']) && equal(req.headers['x-csrf-token'], session.csrf);
  }

  function touch(session) {
    session.last = now();
    sessions.set(session.id, { created: session.created, last: session.last, csrf: session.csrf });
  }

  function cookie(value, age = ABSOLUTE_MS / 1000) {
    return `${COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${age}`;
  }

  function snapshot(session) {
    return session ? { enabled: true, authenticated: true, owner: ownerId, csrf: session.csrf,
      expiresAt: Math.min(session.created + ABSOLUTE_MS, session.last + IDLE_MS) }
      : { enabled: true, authenticated: false };
  }

  async function handle(req, res, path, readBody) {
    if (!['/auth/session', '/auth/login', '/auth/logout'].includes(path)) {
      return reject(req, res, 404, 'Not found');
    }
    const method = path === '/auth/session' ? 'GET' : 'POST';
    if (req.method !== method) return reject(req, res, 405, 'Method not allowed', { allow: method });
    if (req.url !== path) return reject(req, res, 400, 'Invalid authentication path');
    if (!secureRequest(req, res, method === 'POST')) return;
    prune();
    let session = sessionFor(req);
    if (path === '/auth/session') {
      if (session) touch(session);
      return json(res, 200, snapshot(session));
    }
    if (path === '/auth/logout') {
      if (!session) return reject(req, res, 401, 'Owner sign-in required');
      if (!csrfValid(req, session)) return reject(req, res, 403, 'Session verification required');
      sessions.delete(session.id);
      req.resume();
      return json(res, 200, snapshot(null), { 'set-cookie': cookie('', 0) });
    }
    if (req.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
      return reject(req, res, 415, 'JSON sign-in required');
    }
    const address = peer(req);
    const attempt = attempts.get(address) || { start: now(), count: 0 };
    if (activeHash || attempt.count >= 5 || globalAttempts.count >= 20
        || (!attempts.has(address) && attempts.size >= 128)) {
      return reject(req, res, 429, 'Sign-in temporarily limited', { 'retry-after': activeHash ? '2' : '900' });
    }
    attempt.count++;
    globalAttempts.count++;
    attempts.set(address, attempt);
    let payload;
    try {
      payload = JSON.parse((await readBody(req, 8192, 5000)).toString('utf8'));
      if (!payload || Array.isArray(payload) || Object.keys(payload).sort().join(',') !== 'password,username'
          || typeof payload.username !== 'string' || payload.username.length > 64
          || typeof payload.password !== 'string' || Buffer.byteLength(payload.password) > 1024
          || payload.password.includes('\0')) throw new Error();
    } catch (error) {
      return reject(req, res, error.status || 400, 'Invalid sign-in request');
    }
    // Check again after body IO so simultaneous slow requests cannot start parallel KDFs.
    if (activeHash) return reject(req, res, 429, 'Sign-in temporarily limited', { 'retry-after': '2' });
    activeHash = true;
    let valid = false;
    try {
      const computed = await derive(payload.password, salt, 32, HASH_OPTIONS);
      valid = timingSafeEqual(computed, passwordDigest) && equal(payload.username, ownerId);
    } finally {
      payload.password = '';
      activeHash = false;
    }
    if (!valid) return reject(req, res, 401, 'Sign-in details were not accepted');
    if (res.destroyed) return;
    prune();
    if (session) sessions.delete(session.id);
    // At most 16 sessions. Eviction never grants access or changes backend privileges.
    if (sessions.size >= 16) sessions.delete(sessions.keys().next().value);
    const value = randomBytes(32).toString('base64url');
    const id = digest(value).toString('hex');
    session = { id, created: now(), last: now(), csrf: randomBytes(32).toString('base64url') };
    touch(session);
    return json(res, 200, snapshot(session), { 'set-cookie': cookie(value) });
  }

  function authorizeApi(req, res) {
    if (!secureRequest(req, res, req.method !== 'GET')) return null;
    prune();
    const session = sessionFor(req);
    if (!session) return reject(req, res, 401, 'Owner sign-in required');
    if (req.headers.authorization !== undefined) return reject(req, res, 400, 'Caller authorization is not accepted here');
    if (req.method !== 'GET' && !csrfValid(req, session)) {
      return reject(req, res, 403, 'Session verification required');
    }
    touch(session);
    return backendAuthorization;
  }

  return Object.freeze({ handle, authorizeApi });
}
