import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
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
const root = '/app';
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

async function proxyApi(req, res) {
  // Never turn an anonymous browser request into a privileged service request.
  const supplied = Buffer.from(req.headers.authorization || '');
  const expected = Buffer.from(`Bearer ${aiApiToken}`);
  const publicHealth = req.method === 'GET' && req.url === '/api/health';
  if (!publicHealth && (supplied.length !== expected.length || !timingSafeEqual(supplied, expected))) {
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer' });
    res.end(JSON.stringify({ detail: 'Authenticated API access is required' }));
    return;
  }
  if (Number(req.headers['content-length']) > maxRequestBytes) {
    sendText(res, 413, 'Request body is too large');
    return;
  }
  // Buffer only a bounded body; no upstream request exists until it is accepted.
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of req.iterator({ destroyOnReturn: false })) {
      bytes += chunk.length;
      if (bytes > maxRequestBytes) {
        sendText(res, 413, 'Request body is too large');
        req.resume();
        return;
      }
      chunks.push(chunk);
    }
  } catch {
    if (!res.destroyed) sendText(res, 400, 'Incomplete request body');
    return;
  }
  const target = new URL(req.url, backend);
  const headers = {
    ...req.headers,
    host: target.host,
  };
  delete headers['transfer-encoding'];
  headers['content-length'] = String(bytes);
  const proxy = http.request(
    target,
    { method: req.method, headers },
    (apiRes) => {
      res.writeHead(apiRes.statusCode || 502, apiRes.headers);
      apiRes.pipe(res);
    },
  );
  proxy.on('error', () => {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ detail: 'API service unavailable' }));
  });
  proxy.end(Buffer.concat(chunks, bytes));
}

function safeFilePath(urlPath) {
  const pathname = decodeURIComponent(new URL(urlPath, 'http://local').pathname);
  const mapped = pathname === '/' ? '/index.html' : pathname;
  if (!['/index.html', '/watchdawg.js'].includes(mapped)) return null;
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
  if (req.url?.startsWith('/api/')) return proxyApi(req, res);

  const file = safeFilePath(req.url || '/');
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

server.listen(port, host);
