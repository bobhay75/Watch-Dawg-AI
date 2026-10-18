// Offline report runner: no fetch, notification, deployment or approval path.
import {dirname, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonicalURL, timestamp, LIMITS, validateRegistry} from './evidence.mjs';
import {readDocument, verifyDocument} from './prepare-evidence.mjs';
import {evaluateBatch} from './sentinel.mjs';

const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;
const captureKey = (url, digest) => `${canonicalURL(url)}\0${digest}`;
const validDigest = digest => typeof digest === 'string' && digest.length === 64 && /^[a-f0-9]{64}$/.test(digest);
const validPath = path => typeof path === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(path) && path === path.trim();

export function reviewDossier(dossier, loadCapture, now = new Date()) {
  if (!dossier || dossier.version !== 1 || dossier.mode !== 'review-only' ||
      !Array.isArray(dossier.evidenceReviews) || dossier.evidenceReviews.length > LIMITS.reviews ||
      !Array.isArray(dossier.signals) || dossier.signals.length > LIMITS.batch ||
      !Array.isArray(dossier.documents) || dossier.documents.length > LIMITS.sources ||
      typeof loadCapture !== 'function') throw new TypeError('Invalid review-only dossier');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError('Invalid evaluation clock');
  validateRegistry(dossier.registry,now.getTime());
  const documents = new Map();
  // Validate the entire manifest before opening any captured document.
  for (const document of dossier.documents) {
    if (!document || !validPath(document.path) || !validDigest(document.contentSha256)) throw new TypeError('Invalid capture manifest entry');
    const key = captureKey(document.url,document.contentSha256);
    if (documents.has(key)) throw new TypeError('Ambiguous capture manifest');
    documents.set(key,document);
  }
  for (const signal of dossier.signals) {
    if (!signal || !Array.isArray(signal.sources) || signal.sources.length > LIMITS.sources) throw new TypeError('Invalid signal sources');
    for (const source of signal.sources) {
      if (!source || !validDigest(source.contentSha256) || !documents.has(captureKey(source.url,source.contentSha256))) throw new TypeError('Missing preserved document for a signal source');
    }
  }
  // Policy and signal validation run before document I/O. Results are not
  // returned unless every manifest document passes its exact-byte check.
  const results = evaluateBatch(dossier.signals,now,{registry:dossier.registry,evidenceReviews:dossier.evidenceReviews});
  const documentChecks = [];
  let total = 0;
  for (const document of documents.values()) {
    const bytes = loadCapture(document.path);
    if (!(bytes instanceof Uint8Array)) throw new TypeError('Capture loader must return bytes');
    total += bytes.byteLength;
    if (total > MAX_CAPTURE_BYTES) throw new TypeError('Dossier captures exceed 64 MiB');
    if (!verifyDocument(bytes,document.contentSha256)) throw new Error('Preserved document SHA-256 mismatch; no report produced');
    documentChecks.push({url:canonicalURL(document.url),contentSha256:document.contentSha256,byteLength:bytes.byteLength,hashVerified:true});
  }
  return {version:1,mode:'review-only',synthetic:dossier.synthetic === true,evaluatedAt:now.toISOString(),
    reviewRequired:true,documentChecks,results};
}

export function runDossierCLI(args) {
  const options = new Map();
  for (let i=0; i<args.length; i+=2) {
    if (!['--dossier','--at'].includes(args[i]) || options.has(args[i]) || !args[i+1] || args[i+1].startsWith('--')) throw new TypeError('Use --dossier PATH [--at UTC_ISO_REPLAY_TIME]');
    options.set(args[i],args[i+1]);
  }
  if (!options.has('--dossier')) throw new TypeError('Use --dossier PATH [--at UTC_ISO_REPLAY_TIME]');
  const replay = options.has('--at');
  if (replay && !Number.isFinite(timestamp(options.get('--at')))) throw new TypeError('Replay time must be a valid UTC ISO timestamp');
  const now = replay ? new Date(options.get('--at')) : new Date();
  const path = resolve(options.get('--dossier'));
  const dossier = JSON.parse(readDocument(path).toString('utf8'));
  const report = reviewDossier(dossier,name => readDocument(resolve(dirname(path),name)),now);
  return {...report,clockMode:replay?'explicit-historical-replay':'current-clock'};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(runDossierCLI(process.argv.slice(2)),null,2)+'\n'); }
  catch (error) {
    // Parser and filesystem errors can expose raw evidence or local paths.
    const message = error instanceof SyntaxError ? 'Invalid dossier JSON' : error.code || error.message;
    process.stderr.write(`Dossier review failed: ${message}\n`);
    process.exitCode = 1;
  }
}
