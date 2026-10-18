// Offline evidence preparation. Hashing bytes cannot approve their authenticity
// or factual support. This module deliberately never produces approved reviews.
import {createHash} from 'node:crypto';
import {openSync, fstatSync, readSync, closeSync, constants} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {canonicalURL} from './evidence.mjs';

export const MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;

export function prepareEvidence(bytes, url, now = new Date()) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_DOCUMENT_BYTES) throw new TypeError('Document must be bytes, at most 16 MiB');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError('Invalid preparation clock');
  const canonical = canonicalURL(url);
  const digest = createHash('sha256').update(bytes).digest('hex');
  return {
    version:1, status:'pending', preparedAt:now.toISOString(),
    capture:{submittedURL:url, byteLength:bytes.byteLength},
    source:{url:canonical,contentSha256:digest},
    reviewDraft:{
      id:null, url:canonical, contentSha256:digest, sourceId:null, claimId:null,
      category:null, headline:null, eventAt:null, publishedAt:null,
      retrievedAt:null, verifiedAt:null, expiresAt:null,
      support:'unreviewed', maxImpact:null, originId:null, documentId:null,
      reviewer:null, reviewNote:null
    }
  };
}

export function verifyDocument(bytes, expectedDigest) {
  if (typeof expectedDigest !== 'string' || expectedDigest.length !== 64 || !/^[a-f0-9]{64}$/.test(expectedDigest)) throw new TypeError('Expected SHA-256 must be lowercase hexadecimal');
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_DOCUMENT_BYTES) throw new TypeError('Document must be bytes, at most 16 MiB');
  return createHash('sha256').update(bytes).digest('hex') === expectedDigest;
}

function readDocument(file) {
  // Linux/macOS: reject symlinks and avoid blocking on named pipes. fstat also
  // rejects directories/devices. No network or output file is opened.
  if (constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined) throw new Error('Safe local file flags unavailable');
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size > MAX_DOCUMENT_BYTES) throw new Error('Expected a regular file of at most 16 MiB');
    const buffer = Buffer.alloc(MAX_DOCUMENT_BYTES + 1);
    let size = 0, count;
    while (size < buffer.length && (count = readSync(fd,buffer,size,buffer.length-size,null)) > 0) size += count;
    const after = fstatSync(fd);
    if (size > MAX_DOCUMENT_BYTES || size !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error('Document changed while reading or exceeds 16 MiB');
    return buffer.subarray(0,size);
  } finally { closeSync(fd); }
}

export function runCLI(args, now = new Date()) {
  const options = new Map();
  for (let i=0; i<args.length; i+=2) {
    if (!['--file','--url','--expected-sha256'].includes(args[i]) || options.has(args[i]) || !args[i+1] || args[i+1].startsWith('--')) throw new TypeError('Use --file PATH --url HTTPS_URL [--expected-sha256 HASH]');
    options.set(args[i],args[i+1]);
  }
  if (!options.has('--file') || !options.has('--url')) throw new TypeError('Use --file PATH --url HTTPS_URL [--expected-sha256 HASH]');
  // Validate URLs and options before reading any file.
  canonicalURL(options.get('--url'));
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError('Invalid preparation clock');
  const expected = options.get('--expected-sha256');
  if (expected !== undefined && (expected.length !== 64 || !/^[a-f0-9]{64}$/.test(expected))) throw new TypeError('Expected SHA-256 must be lowercase hexadecimal');
  const bytes = readDocument(options.get('--file'));
  if (expected !== undefined && !verifyDocument(bytes,expected)) throw new Error('Document SHA-256 mismatch; no review record prepared');
  return prepareEvidence(bytes,options.get('--url'),now);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(runCLI(process.argv.slice(2)),null,2)+'\n'); }
  catch (error) {
    // Do not echo local paths or document contents into logs on failure.
    process.stderr.write(`Evidence preparation failed: ${error.code || error.message}\n`);
    process.exitCode = 1;
  }
}
