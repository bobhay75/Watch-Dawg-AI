#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';

const baseInput = process.argv[2] || process.env.WATCH_DAWG_BASE_URL;
const timeoutMs = Number(process.env.WATCH_DAWG_HTTP_TIMEOUT_MS || 20_000);

if (!baseInput) {
  console.error('Usage: node scripts/verify-emergent-routing.mjs <base-url>');
  process.exit(2);
}

let baseUrl;
try {
  baseUrl = new URL(baseInput);
} catch {
  console.error(`Invalid base URL: ${baseInput}`);
  process.exit(2);
}

if (baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash) {
  console.error('The base URL must not contain credentials, a query, or a fragment.');
  process.exit(2);
}

if (baseUrl.protocol !== 'https:' && !(baseUrl.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(baseUrl.hostname))) {
  console.error('Use HTTPS for remote targets; HTTP is allowed only for loopback verification.');
  process.exit(2);
}

if (!Number.isFinite(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 60_000) {
  console.error('WATCH_DAWG_HTTP_TIMEOUT_MS must be between 1000 and 60000.');
  process.exit(2);
}

const origin = baseUrl.origin;
const rows = [];
const failures = [];

function fail(message) {
  failures.push(message);
}

function expect(condition, message) {
  if (!condition) fail(message);
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex').slice(0, 16);
}

async function probe(label, target) {
  const url = target instanceof URL ? target : new URL(target, `${origin}/`);
  try {
    const response = await fetch(url, {
      headers: { 'user-agent': 'Watch-Dawg-routing-verifier/1.0' },
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get('content-type') || '';
    const row = {
      label,
      path: `${url.pathname}${url.search}`,
      status: response.status,
      contentType: contentType.split(';')[0] || '-',
      bytes: bytes.length,
      sha256: digest(bytes),
      etag: response.headers.get('etag') || '-',
      robots: response.headers.get('x-robots-tag') || '-',
      finalUrl: response.url,
    };
    rows.push(row);
    return { response, bytes, text: bytes.toString('utf8'), row };
  } catch (error) {
    rows.push({
      label,
      path: `${url.pathname}${url.search}`,
      status: 'ERR',
      contentType: '-',
      bytes: 0,
      sha256: '-',
      etag: '-',
      robots: '-',
      finalUrl: url.href,
    });
    fail(`${label} request failed: ${error.message}`);
    return null;
  }
}

function discoverSameOriginAssets(html, documentUrl) {
  const references = [];
  const tagPattern = /<(?:script|link)\b[^>]*(?:src|href)=["']([^"']+)["']/gi;
  const importPattern = /\bfrom\s+["']([^"']+)["']/g;

  for (const pattern of [tagPattern, importPattern]) {
    for (const match of html.matchAll(pattern)) references.push(match[1]);
  }

  const unique = new Map();
  for (const reference of references) {
    if (!reference || reference.startsWith('#') || reference.startsWith('data:')) continue;
    const resolved = new URL(reference, documentUrl);
    if (resolved.origin !== origin) continue;
    unique.set(resolved.href, resolved);
  }
  return [...unique.values()];
}

function assertKnownAsset(result, assetUrl) {
  if (!result) return;
  const type = result.response.headers.get('content-type') || '';
  const path = assetUrl.pathname.toLowerCase();

  expect(result.response.status === 200, `${assetUrl.pathname} must return 200; observed ${result.response.status}`);
  expect(!type.toLowerCase().startsWith('text/html'), `${assetUrl.pathname} returned HTML instead of its asset MIME type`);

  if (path.endsWith('.js') || path.endsWith('.mjs')) {
    expect(/(?:java|ecma)script/i.test(type), `${assetUrl.pathname} must return a JavaScript MIME type; observed ${type || 'none'}`);
  } else if (path.endsWith('.css')) {
    expect(/^text\/css\b/i.test(type), `${assetUrl.pathname} must return text/css; observed ${type || 'none'}`);
  } else if (path.endsWith('.svg')) {
    expect(/^image\/svg\+xml\b/i.test(type), `${assetUrl.pathname} must return image/svg+xml; observed ${type || 'none'}`);
  }
}

function assertMissing(result, label) {
  if (!result) return;
  const robots = result.response.headers.get('x-robots-tag') || '';
  expect(result.response.status === 404, `${label} must return 404; observed ${result.response.status}`);
  expect(/(?:^|[,\s])noindex(?:$|[,\s])/i.test(robots), `${label} must include X-Robots-Tag: noindex; observed ${robots || 'none'}`);
  expect(!(result.response.status === 200 && result.row.contentType === 'text/html'), `${label} must never return the HTML shell with status 200`);
}

const root = await probe('root', '/');
let assets = [];

if (root) {
  const rootType = root.response.headers.get('content-type') || '';
  expect(root.response.status === 200, `/ must return 200; observed ${root.response.status}`);
  expect(/^text\/html\b/i.test(rootType), `/ must return text/html; observed ${rootType || 'none'}`);
  expect(new URL(root.response.url).origin === origin, `/ redirected outside ${origin}`);
  assets = discoverSameOriginAssets(root.text, root.response.url);
  expect(assets.length > 0, 'The root HTML did not expose any same-origin script, stylesheet, icon, or module asset to verify.');
}

const assetResults = await Promise.all(assets.map((asset) => probe(`asset ${asset.pathname}`, asset)));
assetResults.forEach((result, index) => assertKnownAsset(result, assets[index]));

const healthPromise = probe('API health', '/api/health');
const missingToken = `__watch_dawg_missing_${Date.now()}_${randomBytes(4).toString('hex')}__`;
const missingRoutePath = `/${missingToken}/`;
const nestedNames = [...new Set([
  ...assets.map((asset) => asset.pathname.split('/').filter(Boolean).at(-1)),
  'app.js',
  'styles.css',
  'favicon.svg',
  'watchdawg.js',
].filter(Boolean))];
const missingRoutePromise = probe('missing route', missingRoutePath);
const nestedPromises = nestedNames.map((name) => probe(`nested missing ${name}`, `${missingRoutePath}${encodeURIComponent(name)}`));

const [health, missingRoute, nestedResults] = await Promise.all([
  healthPromise,
  missingRoutePromise,
  Promise.all(nestedPromises),
]);

if (health) {
  const healthType = health.response.headers.get('content-type') || '';
  expect(health.response.status === 200, `/api/health must return 200; observed ${health.response.status}`);
  expect(/^application\/json\b/i.test(healthType), `/api/health must return application/json; observed ${healthType || 'none'}`);
  try {
    JSON.parse(health.text);
  } catch {
    fail('/api/health did not return valid JSON.');
  }
}

assertMissing(missingRoute, missingRoutePath);
nestedResults.forEach((result, index) => assertMissing(result, `${missingRoutePath}${nestedNames[index]}`));

rows.sort((left, right) => left.label.localeCompare(right.label));
console.log(`Watch-Dawg live routing matrix: ${origin}`);
console.log(`Observed: ${new Date().toISOString()}`);
for (const row of rows) {
  console.log([
    String(row.status).padEnd(3),
    row.contentType.padEnd(22),
    String(row.bytes).padStart(7),
    row.sha256,
    row.robots.padEnd(18),
    row.path,
  ].join('  '));
}

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} routing assertion${failures.length === 1 ? '' : 's'} failed.`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log('\nPASS: known routes remain available and every tested unknown route fails closed with noindex.');
}
