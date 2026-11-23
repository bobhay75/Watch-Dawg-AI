import http from 'node:http';
import https from 'node:https';
import { createReadStream, readFileSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createOwnerSession, loadOwnerConfig, readPrivateFile } from './owner-session.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const staticFiles = new Set([
  '/index.html', '/watchdawg.js', '/owner-client.js', '/assets/brand/watchdawg-bobsome1.png',
  '/assets/css/watchdawg-attribution.css',
]);
const types = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.png', 'image/png'],
]);
const apiMethods = new Map([['/api/health', 'GET'], ['/api/ai/audit', 'POST']]);
const responseHeaders = ['content-type', 'retry-after', 'www-authenticate', 'x-request-id'];

function loadEnv(path) {
  try {
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
      const [key, ...rest] = trimmed.split('=');
      if (!process.env[key]) process.env[key] = rest.join('=');
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function reply(res, status, detail, headers = {}) {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) return res.destroy();
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify({ detail }));
}

function requestPath(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')
      || /[\\\x00-\x20\x7f]/.test(raw)) throw new Error('Invalid request path');
  const pathname = new URL(raw, 'http://local').pathname;
  const decoded = decodeURIComponent(pathname);
  if (/[\\\x00-\x1f\x7f]/.test(decoded)) throw new Error('Invalid request path');
  return decoded;
}

async function readBody(req, maximum, timeoutMs) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared)
      || !Number.isSafeInteger(Number(declared)))) {
    throw Object.assign(new Error('Invalid request body'), { status: 400 });
  }
  if (declared !== undefined && Number(declared) > maximum) {
    throw Object.assign(new Error('Request body too large'), { status: 413 });
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    const finish = (error) => {
      clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
      if (error) {
        req.resume();
        reject(error);
      } else resolve(Buffer.concat(chunks, length));
    };
    const onData = chunk => {
      length += chunk.length;
      if (length > maximum) finish(Object.assign(new Error('Request body too large'), { status: 413 }));
      else chunks.push(chunk);
    };
    const onEnd = () => finish();
    const onError = () => finish(Object.assign(new Error('Request body interrupted'), { status: 400 }));
    const onAborted = onError;
    const timer = setTimeout(() => finish(Object.assign(new Error('Request body timeout'), { status: 408 })), timeoutMs);
    timer.unref();
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAborted);
  });
}

/** Fixed upstream and explicit public files. The optional owner adapter keeps
 * its scoped credential on the server; otherwise caller authorization is forwarded.
 * Backend scopes/transport/origin/network/budget/audit remain authoritative.
 */
export function createFrontendServer({ backend, bodyLimit = 256 * 1024,
  bodyTimeoutMs = 10_000, upstreamTimeoutMs = 95_000,
  upstreamIdleTimeoutMs = 65_000, responseLimit = 2 * 1024 * 1024,
  ownerConfig, ownerClock, tls } = {}) {
  const base = new URL(backend);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password
      || base.search || base.hash || base.pathname !== '/') {
    throw new Error('REACT_APP_BACKEND_URL must be an HTTP(S) origin without credentials or a path');
  }
  for (const value of [bodyLimit, bodyTimeoutMs, upstreamTimeoutMs, upstreamIdleTimeoutMs, responseLimit]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error('Gateway limits must be positive integers');
  }
  if (ownerConfig && base.protocol !== 'https:' && !['127.0.0.1', '[::1]'].includes(base.hostname)) {
    throw new Error('Owner credentials require verified HTTPS or a private loopback backend');
  }
  const owner = ownerConfig ? createOwnerSession(ownerConfig, ownerClock ? { now: ownerClock } : {}) : null;

  async function proxyApi(req, res, path) {
    if (!apiMethods.has(path)) return reply(res, 404, 'Not found');
    if (req.method !== apiMethods.get(path)) {
      return reply(res, 405, 'Method not allowed', { allow: apiMethods.get(path) });
    }
    // API queries are not part of the current contract. Never forward alternate
    // URL encodings, user-supplied authorities, credentials or identity headers.
    if (req.url !== path) return reply(res, 400, 'Invalid API path');
    const ownerAuthorization = owner?.authorizeApi(req, res);
    if (owner && !ownerAuthorization) return;
    let body;
    try { body = await readBody(req, bodyLimit, bodyTimeoutMs); }
    catch (error) {
      req.resume();
      return reply(res, error.status || 400, error.message, { connection: 'close' });
    }
    const target = new URL(path, base);
    const headers = { host: target.host, 'content-length': String(body.length) };
    for (const name of ['authorization', 'content-type', 'accept', 'origin']) {
      if (typeof req.headers[name] === 'string') headers[name] = req.headers[name];
    }
    if (ownerAuthorization) headers.authorization = ownerAuthorization;
    const transport = target.protocol === 'https:' ? https : http;
    let upstream;
    const proxy = transport.request(target, { method: req.method, headers }, incoming => {
      upstream = incoming;
      let received = 0;
      const output = { 'cache-control': 'no-store', 'x-accel-buffering': 'no' };
      for (const name of responseHeaders) {
        if (typeof incoming.headers[name] === 'string') output[name] = incoming.headers[name];
      }
      res.writeHead(incoming.statusCode || 502, output);
      incoming.on('data', chunk => {
        received += chunk.length;
        if (received > responseLimit) {
          incoming.unpipe(res);
          reply(res, 502, 'API response exceeded limit');
          incoming.destroy();
          proxy.destroy();
        }
      });
      incoming.on('error', () => reply(res, 502, 'API service unavailable'));
      incoming.on('aborted', () => reply(res, 502, 'API service unavailable'));
      incoming.pipe(res);
    });
    const deadline = setTimeout(() => {
      reply(res, 504, 'API service timeout');
      proxy.destroy();
    }, upstreamTimeoutMs);
    deadline.unref();
    proxy.setTimeout(upstreamIdleTimeoutMs, () => {
      reply(res, 504, 'API service timeout');
      proxy.destroy();
    });
    proxy.on('error', () => reply(res, 502, 'API service unavailable'));
    res.once('close', () => {
      clearTimeout(deadline);
      upstream?.destroy();
      proxy.destroy();
    });
    proxy.end(body);
  }

  async function handle(req, res) {
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-frame-options', 'DENY');
    let path;
    try { path = requestPath(req.url); }
    catch { return reply(res, 400, 'Invalid path'); }
    if (path.startsWith('/auth/')) {
      if (owner) return owner.handle(req, res, path, readBody);
      if (req.url === '/auth/session' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        return res.end(JSON.stringify({ enabled: false, authenticated: false }));
      }
      return reply(res, 404, 'Owner sign-in is not configured');
    }
    if (path.startsWith('/api/')) return proxyApi(req, res, path);
    const mapped = path === '/' ? '/index.html' : path;
    if (!staticFiles.has(mapped)) {
      return reply(res, 404, 'Not found', { 'x-robots-tag': 'noindex, nofollow' });
    }
    if (!['GET', 'HEAD'].includes(req.method)) {
      return reply(res, 405, 'Method not allowed', { allow: 'GET, HEAD' });
    }
    const file = join(root, mapped);
    try {
      const info = await stat(file);
      if (!info.isFile()) return reply(res, 404, 'Not found');
      res.writeHead(200, { 'content-type': types.get(extname(file)),
        'content-length': info.size, 'cache-control': 'no-cache' });
      if (req.method === 'HEAD') return res.end();
      const stream = createReadStream(file);
      stream.on('error', () => reply(res, 500, 'Static asset unavailable'));
      res.once('close', () => stream.destroy());
      stream.pipe(res);
    } catch (error) {
      reply(res, ['ENOENT', 'ENOTDIR'].includes(error?.code) ? 404 : 500, 'Static asset unavailable');
    }
  }

  const listener = (req, res) => {
    handle(req, res).catch(() => reply(res, 500, 'Request could not be completed'));
  };
  const server = tls ? https.createServer(tls, listener) : http.createServer(listener);
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 100;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadEnv(fileURLToPath(new URL('.env', import.meta.url)));
  const port = Number(process.env.PORT);
  const host = process.env.HOST;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535 || !host || !process.env.REACT_APP_BACKEND_URL) {
    throw new Error('HOST, PORT (1-65535), and REACT_APP_BACKEND_URL are required');
  }
  const ownerConfig = loadOwnerConfig(process.env.WATCHDAWG_OWNER_CONFIG_FILE);
  const keyFile = process.env.FRONTEND_TLS_KEY_FILE;
  const certFile = process.env.FRONTEND_TLS_CERT_FILE;
  if (!!keyFile !== !!certFile) throw new Error('Both frontend TLS certificate and key are required');
  const tls = keyFile ? { key: readPrivateFile(keyFile), cert: readPrivateFile(certFile, 64 * 1024) } : undefined;
  if (ownerConfig && !tls && !['127.0.0.1', '::1'].includes(host)) {
    throw new Error('Owner HTTP ingress must bind to loopback behind its configured TLS proxy');
  }
  if (ownerConfig && !tls && !ownerConfig.trustedProxyAddresses.length) {
    throw new Error('Owner sign-in requires frontend TLS or an explicitly trusted loopback TLS proxy');
  }
  createFrontendServer({ backend: process.env.REACT_APP_BACKEND_URL, ownerConfig, tls }).listen(port, host);
}
