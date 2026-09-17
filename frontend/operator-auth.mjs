import { randomBytes, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { readFileSync, statSync } from 'node:fs';

const derive = promisify(scrypt);
export const scryptOptions = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const fingerprint = value => createHash('sha256').update(value).digest('hex');
const lifetime = 15 * 60 * 1000;

export function loadOperators(path) {
  if (!path) return [];
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > 32000 || (stat.mode & 0o077)) {
    throw new Error('Operator file must be private (0600) and at most 32 KB');
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

export class OperatorAuth {
  constructor({ users = [], origin, bindHost, now = Date.now } = {}) {
    this.users = new Map();
    if (!Array.isArray(users) || users.length > 20) throw new Error('Invalid operator list');
    for (const user of users) {
      if (!user || typeof user.username !== 'string' || typeof user.salt !== 'string'
          || typeof user.hash !== 'string' || !/^[a-z0-9_-]{3,40}$/.test(user.username || '')
          || !/^[a-f0-9]{32}$/.test(user.salt || '')
          || !/^[a-f0-9]{128}$/.test(user.hash || '')
          || !Array.isArray(user.scopes) || user.scopes.some(s => s !== 'ai:audit')
          || this.users.has(user.username)) throw new Error('Invalid operator record');
      this.users.set(user.username, user);
    }
    if (this.users.size && !origin) throw new Error('Operator sign-in requires a fixed public origin');
    this.origin = origin;
    this.secure = true;
    if (origin) {
      const url = new URL(origin);
      const loopback = url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)
        && ['127.0.0.1', 'localhost'].includes(bindHost);
      if (url.origin !== origin || (url.protocol !== 'https:' && !loopback)) {
        throw new Error('Use an HTTPS origin, or HTTP bound to loopback for local tests');
      }
      this.secure = !loopback;
    }
    this.cookieName = this.secure ? '__Host-watchdawg_session' : 'watchdawg_local_session';
    this.now = now;
    this.sessions = new Map();
    this.loginAttempts = [];
    this.userAttempts = new Map();
    this.auditAttempts = new Map();
    this.hashing = false;
  }

  sameOrigin(req) {
    return Boolean(this.origin) && req.headers.origin === this.origin;
  }

  cookie(id, clear = false) {
    return `${this.cookieName}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${clear ? 0 : lifetime / 1000}${this.secure ? '; Secure' : ''}`;
  }

  session(req) {
    const cookies = (req.headers.cookie || '').split(';').map(x => x.trim())
      .filter(x => x.startsWith(`${this.cookieName}=`));
    if (cookies.length !== 1) return null;
    const id = cookies[0].slice(this.cookieName.length + 1);
    if (!/^[a-f0-9]{64}$/.test(id)) return null;
    const key = fingerprint(id);
    const session = this.sessions.get(key);
    if (!session || session.expires <= this.now()) {
      this.sessions.delete(key);
      return null;
    }
    return { ...session, key };
  }

  async login(req, credentials) {
    if (!this.users.size) return { status: 503, detail: 'Operator sign-in is not configured' };
    if (!this.sameOrigin(req)) return { status: 403, detail: 'Same-origin request required' };
    const { username, password } = credentials || {};
    if (typeof username !== 'string' || !/^[a-z0-9_-]{3,40}$/.test(username)
        || typeof password !== 'string' || password.length < 15 || Buffer.byteLength(password) > 1024) {
      return { status: 401, detail: 'Invalid username or password' };
    }
    const now = this.now();
    this.loginAttempts = this.loginAttempts.filter(t => t > now - 60000);
    const known = this.users.get(username);
    const attempts = (this.userAttempts.get(username) || []).filter(t => t > now - 900000);
    if (this.hashing || this.loginAttempts.length >= 10 || attempts.length >= 5) {
      return { status: 429, detail: 'Too many sign-in attempts; try again later' };
    }
    this.loginAttempts.push(now);
    // Store counters only for configured users so unknown names cannot fill memory.
    if (known) this.userAttempts.set(username, [...attempts, now]);
    this.hashing = true;
    let valid;
    try {
      const salt = known?.salt || '0'.repeat(32);
      const hash = await derive(password, Buffer.from(salt, 'hex'), 64, scryptOptions);
      valid = timingSafeEqual(hash, Buffer.from(known?.hash || '0'.repeat(128), 'hex')) && Boolean(known);
    } finally { this.hashing = false; }
    if (!valid) return { status: 401, detail: 'Invalid username or password' };
    this.userAttempts.delete(username);
    for (const [key, session] of this.sessions) {
      if (session.username === username || session.expires <= now) this.sessions.delete(key);
    }
    const id = randomBytes(32).toString('hex');
    this.sessions.set(fingerprint(id), { username, expires: now + lifetime });
    return { status: 200, detail: 'Signed in', cookie: this.cookie(id) };
  }

  authorize(req) {
    const session = this.session(req);
    if (!session) return { status: 401, detail: 'Operator sign-in required' };
    if (!this.sameOrigin(req)) return { status: 403, detail: 'Same-origin request required' };
    if (!this.users.get(session.username)?.scopes.includes('ai:audit')) {
      return { status: 403, detail: 'AI audit permission required' };
    }
    const now = this.now();
    const attempts = (this.auditAttempts.get(session.username) || []).filter(t => t > now - 60000);
    if (attempts.length >= 5) return { status: 429, detail: 'Operator audit limit reached' };
    this.auditAttempts.set(session.username, [...attempts, now]);
    return { status: 200 };
  }

  logout(req) {
    if (!this.sameOrigin(req)) return { status: 403, detail: 'Same-origin request required' };
    const session = this.session(req);
    if (session) this.sessions.delete(session.key);
    return { status: 200, detail: 'Signed out', cookie: this.cookie('', true) };
  }
}

export async function readBoundedBody(req, maximum) {
  if (Number(req.headers['content-length']) > maximum) {
    throw Object.assign(new Error('Request body is too large'), { status: 413 });
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    bytes += chunk.length;
    if (bytes > maximum) {
      req.resume();
      throw Object.assign(new Error('Request body is too large'), { status: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, bytes);
}
