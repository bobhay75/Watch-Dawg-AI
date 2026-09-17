import http from 'node:http';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { OperatorAuth, loadOperators, readBoundedBody } from './operator-auth.mjs';
import { createReadStream } from 'node:fs';
import { readFileSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

function loadEnv(path) {
  try {
    const lines = readFileSync(path, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
      const [key, ...rest] = trimmed.split('=');
      if (!process.env[key]) process.env[key] = rest.join('=');
    }
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
  return true;
}

loadEnv('/app/frontend/.env');

const port = Number(process.env.PORT);
const host = process.env.HOST;
const root = fileURLToPath(new URL('../', import.meta.url));
const backend = process.env.REACT_APP_BACKEND_URL;
const aiApiToken = process.env.WATCH_DAWG_AI_API_TOKEN;

if (!port || !host || !backend || !aiApiToken || aiApiToken.length < 32 || /\s/.test(aiApiToken)) {
  throw new Error(
    'HOST, PORT, REACT_APP_BACKEND_URL, and a 32+ character '
    + 'WATCH_DAWG_AI_API_TOKEN are required',
  );
}

const types = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
]);

const maxRequestBytes = 64_000;
const backendURL = new URL(backend);
if (backendURL.protocol !== 'https:' && !(backendURL.protocol === 'http:'
    && ['127.0.0.1', 'localhost', '[::1]'].includes(backendURL.hostname))) {
  throw new Error('Backend must use HTTPS or loopback HTTP');
}
const operators = new OperatorAuth({ users: loadOperators(process.env.WATCH_DAWG_USERS_FILE),
  origin: process.env.WATCH_DAWG_PUBLIC_ORIGIN, bindHost: host });

function authReply(res, result) {
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (result.cookie) headers['set-cookie'] = result.cookie;
  if (result.status === 429) headers['retry-after'] = String(result.retryAfter || 60);
  res.writeHead(result.status, headers);
  res.end(JSON.stringify({ detail: result.detail }));
}

async function authRoute(req, res) {
  if (req.url === '/auth/session' && req.method === 'GET') {
    const session = operators.session(req);
    return authReply(res, { status: session ? 200 : 401,
      detail: session ? 'Signed in' : 'Sign-in required' });
  }
  if (req.url === '/auth/logout' && req.method === 'POST') {
    return authReply(res, operators.logout(req));
  }
  if (req.url !== '/auth/login' || req.method !== 'POST') return sendText(res, 404, 'Not found');
  if (!operators.sameOrigin(req)) return authReply(res, { status: 403, detail: 'Same-origin request required' });
  try {
    const body = await readBoundedBody(req, 4096);
    const credentials = JSON.parse(body.toString('utf8'));
    return authReply(res, await operators.login(req, credentials));
  } catch (error) {
    return authReply(res, { status: error.status || 400, detail: 'Sign-in request rejected' });
  }
}

async function proxyApi(req, res) {
  const publicHealth = req.method === 'GET' && req.url === '/api/health';
  if (!publicHealth) {
    if (req.url !== '/api/ai/audit' || req.method !== 'POST') return sendText(res, 404, 'Not found');
    const authorization = operators.authorize(req);
    if (authorization.status !== 200) return authReply(res, authorization);
  }
  let body;
  try {
    body = await readBoundedBody(req, maxRequestBytes);
  } catch (error) {
    if (!res.destroyed) sendText(res, error.status || 400, 'Request body rejected');
    return;
  }
  const target = new URL(req.url, backend);
  // Forward only required headers, never cookies or caller-controlled identity.
  const headers = { host: target.host, 'content-type': 'application/json',
    'content-length': String(body.length) };
  if (!publicHealth) headers.authorization = `Bearer ${aiApiToken}`;
  const transport = target.protocol === 'https:' ? https : http;
  const proxy = transport.request(
    target,
    { method: req.method, headers },
    (apiRes) => {
      res.writeHead(apiRes.statusCode || 502, {
        'content-type': apiRes.headers['content-type'] || 'application/json',
        'cache-control': 'no-store',
      });
      apiRes.pipe(res);
    },
  );
  proxy.on('error', () => {
    if (res.headersSent) {
      if (!res.writableEnded) res.destroy();
      return;
    }
    res.writeHead(502, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ detail: 'API service unavailable' }));
  });
  proxy.setTimeout(60_000, () => proxy.destroy(new Error('Upstream response timed out')));
  res.on('close', () => {
    if (!proxy.destroyed) proxy.destroy();
  });
  proxy.end(body);
}

function safeFilePath(urlPath) {
  const pathname = decodeURIComponent(new URL(urlPath, 'http://local').pathname);
  const mapped = pathname === '/' ? '/index.html' : pathname;
  if (!['/index.html', '/watchdawg.js', '/login.html', '/login.js', '/login.css'].includes(mapped)) return null;
  return normalize(join(root, mapped));
}

function sendText(res, statusCode, message) {
  res.writeHead(statusCode, { 'content-type': 'text/plain' });
  res.end(message);
}

function isMissingFileError(error) {
  return error && (error.code === 'ENOENT' || error.code === 'ENOTDIR');
}

const server = http.createServer(async (req, res) => {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-frame-options', 'DENY');
  if (req.url?.startsWith('/auth/')) return authRoute(req, res);
  if (req.url?.startsWith('/api/')) return proxyApi(req, res);
  if (req.url === '/login.html' || req.url === '/login.js' || req.url === '/login.css') {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('content-security-policy', "default-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  }

  let file;
  try { file = safeFilePath(req.url || '/'); }
  catch { return sendText(res, 400, 'Invalid path'); }
  if (!file) {
    sendText(res, 404, 'Not found');
    return;
  }

  try {
    await stat(file);
    res.writeHead(200, {
      'content-type': types.get(extname(file)) || 'application/octet-stream',
    });
    createReadStream(file).pipe(res);
  } catch (error) {
    if (isMissingFileError(error)) {
      sendText(res, 404, 'Not found');
      return;
    }
    sendText(res, 500, 'Static asset error');
  }
});

server.on('error', (error) => {
  throw error;
});

server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.maxRequestsPerSocket = 100;
server.listen(port, host);
