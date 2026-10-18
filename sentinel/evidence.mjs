// Offline policy enforcement. Caller-supplied reviews are trusted configuration,
// never facts inferred by this module or fields accepted from a signal payload.
const HOUR = 3600000;
export const LIMITS = Object.freeze({sources:256, registrySources:1024, reviews:4096, batch:256, indicators:256});
const identity = value => typeof value === 'string' && value.length <= 128 && value === value.trim() && /^[a-z0-9]+(?:[-_.:][a-z0-9]+)*$/.test(value);
const text = value => typeof value === 'string' && value.trim().length > 0;
export function timestamp(value) {
  // Require an actual UTC instant; Date.parse alone normalizes impossible dates.
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value.replace(/Z$/, value.includes('.') ? 'Z' : '.000Z') ? time : NaN;
}

export function canonicalURL(raw) {
  if (typeof raw !== 'string' || raw.length > 4096 || /[^\x21-\x7e]|\\|%(?![0-9a-fA-F]{2})|%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(raw) || !raw.startsWith('https://')) throw new TypeError('Invalid evidence URL');
  const authority = raw.slice(8).split(/[/?#]/, 1)[0];
  if (!authority || /[\x25@]/.test(authority) || authority.endsWith(':')) throw new TypeError('Encoded host or credentials');
  const url = new URL(raw);
  const host = url.hostname;
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      host.length > 253 || !host.includes('.') || /^\d+(?:\.\d+)*$/.test(host) ||
      !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) && !label.startsWith('xn--')) ||
      /\.(?:local|localhost|internal|test|invalid)$/.test(host)) throw new TypeError('Unsupported evidence host');
  url.hash = '';
  for (const key of [...url.searchParams.keys()]) if (/^utm_/i.test(key) || /^(fbclid|gclid)$/i.test(key)) url.searchParams.delete(key);
  url.searchParams.sort();
  return url.href;
}

export function validateRegistry(registry, now) {
  if (!registry || registry.version !== 1 || !Array.isArray(registry.sources) || registry.sources.length > LIMITS.registrySources) throw new TypeError('Invalid source registry');
  const hosts = new Map(), ids = new Set();
  for (const source of registry.sources) {
    if (!source || !['id','ownerId','editorialGroupId'].every(k => identity(source[k])) || !['reviewer','reviewNote'].every(k => text(source[k])) ||
        !['approved','pending','revoked'].includes(source.status) || !Array.isArray(source.hosts) || !source.hosts.length || source.hosts.length > 16 ||
        !Array.isArray(source.reviewReferences) || !source.reviewReferences.length ||
        !source.reviewReferences.every(text) || ids.has(source.id) ||
        !Number.isFinite(timestamp(source.reviewedAt)) || !Number.isFinite(timestamp(source.expiresAt)) ||
        timestamp(source.expiresAt) <= timestamp(source.reviewedAt)) throw new TypeError('Invalid or ambiguous source registry entry');
    ids.add(source.id);
    for (const host of source.hosts) {
      if (typeof host !== 'string' || canonicalURL(`https://${host}/`) !== `https://${host}/` || /[/:?#]/.test(host) || hosts.has(host)) throw new TypeError('Invalid or duplicate registry host');
      hosts.set(host, {...source, active: source.status === 'approved' && !Object.hasOwn(source,'revokedAt') && timestamp(source.reviewedAt) <= now && now < timestamp(source.expiresAt)});
    }
  }
  return hosts;
}

export function verifyEvidence(input, now, registry, reviews, severity) {
  const hosts = validateRegistry(registry, now);
  if (!Array.isArray(reviews) || reviews.length > LIMITS.reviews) throw new TypeError('Evidence reviews array required');
  // Deny-only tombstones override approvals with the same stable review ID,
  // regardless of the claim/document metadata or historical evaluation clock.
  const revokedIds = new Set(reviews.filter(r => r && identity(r.id) &&
    (r.status === 'revoked' || Object.hasOwn(r,'revokedAt'))).map(r => r.id));
  const candidates = [], rejected = [], seenURLs = new Set(), seenHashes = new Set();
  const eventTime = timestamp(input.observedAt);
  for (let index = 0; index < input.sources.length; index++) {
    const evidence = input.sources[index];
    const reject = reason => rejected.push({index, reason});
    let url;
    try { url = canonicalURL(evidence?.url); } catch { reject('INVALID_URL'); continue; }
    const source = hosts.get(new URL(url).hostname);
    if (!source?.active) { reject('SOURCE_NOT_APPROVED'); continue; }
    if (typeof evidence?.contentSha256 !== 'string' || evidence.contentSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(evidence.contentSha256)) { reject('MISSING_CONTENT_DIGEST'); continue; }
    // Only an exact reviewed claim and preserved document may qualify. Signal
    // flags, source IDs, ownership assertions and supplied dates grant no trust.
    const matches = reviews.filter(r => r && r.url === url && r.contentSha256 === evidence.contentSha256 && r.claimId === input.id);
    if (matches.some(r => revokedIds.has(r.id))) { reject('REVIEW_REVOKED'); continue; }
    if (matches.length !== 1) { reject(matches.length ? 'AMBIGUOUS_REVIEW' : 'NO_CLAIM_REVIEW'); continue; }
    const r = matches[0];
    if (r.status !== 'approved') { reject('REVIEW_NOT_APPROVED'); continue; }
    if (r.sourceId !== source.id || r.category !== input.category || r.headline !== input.headline ||
        timestamp(r.eventAt) !== eventTime || r.support !== 'direct' ||
        !Number.isInteger(r.maxImpact) || r.maxImpact < severity || r.maxImpact > 4 ||
        !['id','originId','documentId'].every(k => identity(r[k])) || !['reviewer','reviewNote'].every(k => text(r[k]))) { reject('UNSUPPORTED_CLAIM'); continue; }
    const published = timestamp(r.publishedAt), retrieved = timestamp(r.retrievedAt), verified = timestamp(r.verifiedAt), expires = timestamp(r.expiresAt);
    if (![published,retrieved,verified,expires].every(Number.isFinite) ||
        eventTime > retrieved || published > retrieved || retrieved > verified || verified > now ||
        expires <= verified || now >= expires || published > now) { reject('INVALID_REVIEW_TIMESTAMPS'); continue; }
    // A fresh observation/retrieval cannot rejuvenate an old event or report.
    if (now - eventTime > 72 * HOUR || eventTime > now || now - published > 72 * HOUR) { reject('STALE_EVIDENCE'); continue; }
    const duplicate = seenURLs.has(url) || seenHashes.has(evidence.contentSha256);
    if (duplicate) reject('DUPLICATE_EVIDENCE');
    seenURLs.add(url); seenHashes.add(evidence.contentSha256);
    candidates.push({duplicate,url,contentSha256:evidence.contentSha256,sourceId:source.id,ownerId:source.ownerId,
      editorialGroupId:source.editorialGroupId,originId:r.originId,documentId:r.documentId,reviewId:r.id});
  }
  // Connected components conservatively collapse shared owners, editorial desks,
  // syndicated origins and duplicate documents (including transitive links).
  const parent = candidates.map((_, i) => i);
  const root = i => parent[i] === i ? i : (parent[i] = root(parent[i]));
  for (const key of ['url','contentSha256','sourceId','ownerId','editorialGroupId','originId','documentId','reviewId']) {
    const seen = new Map();
    candidates.forEach((c, i) => { if (seen.has(c[key])) parent[root(i)] = root(seen.get(c[key])); else seen.set(c[key], i); });
  }
  const count = new Set(candidates.map((_, i) => root(i))).size;
  return {sources:candidates.filter(c => !c.duplicate).map(({duplicate, ...c}) => c),
    rejectedEvidence:rejected,independentSourceCount:count};
}
