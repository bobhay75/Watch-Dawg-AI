import { auditFieldSecuritySite, createFieldSecurityReceipt } from './field-security.js';
import { validateSite, clone } from './field-security-store.js';

export async function fingerprintFile(file) {
  if (file.size > 20 * 1024 * 1024) throw new Error('Choose a file of 20 MB or less.');
  const hash = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return {
    name: file.name, type: file.type || '', size: file.size,
    sha256: [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
    bytesIncluded: false,
  };
}

export function fieldReport(site, audit = auditFieldSecuritySite(site)) {
  site = validateSite(site);
  const lines = [
    'WATCH-DAWG / FIELD RECORD', site.siteName, `Site ID: ${site.siteId}`,
    `Record date: ${site.capturedAt || 'Not recorded'}`, '',
    ...(site.recordKind === 'sample' ? ['FICTIONAL SAMPLE — for workflow demonstration only.', ''] : []),
    'This is a local, user-entered record. No monitoring or AI service ran.',
    'File fingerprints identify bytes selected locally; original files are not included.',
    'Keep originals separately. Reviewer names are self-declared, not authenticated.', '',
    `Review: ${audit.findings.length ? 'Attention needed' : 'No rule findings in submitted record'}`,
    `Open incidents: ${audit.summary.openIncidents}`, '', 'RULE FINDINGS',
    ...audit.findings.map((item) => `[${item.severity}] ${item.message}`), '', 'INCIDENTS',
  ];
  for (const incident of site.incidents) {
    lines.push('', `${incident.id} / ${incident.title}`, `Zone: ${site.zones.find((zone) => zone.id === incident.zoneId)?.name || incident.zoneId}`,
      `Status: ${incident.status} | Severity: ${incident.severity} | Review: ${incident.reviewStatus}`,
      `Occurred: ${incident.occurredAt || 'Not recorded'} | Observed by: ${incident.observedBy || 'Not recorded'}`,
      `Notes: ${incident.notes || 'None'}`);
    for (const item of incident.evidence) {
      lines.push(`Evidence ${item.id} (${item.type}): ${item.description}`);
      if (item.attachment) lines.push(`File: ${item.attachment.name} (${item.attachment.size} bytes); SHA-256: ${item.attachment.sha256}; original not included.`);
    }
    if (incident.review) lines.push(`Review by ${incident.review.reviewer} at ${incident.review.at}: ${incident.review.note}`);
    if (incident.resolutionNote) lines.push(`Resolution: ${incident.resolutionNote}`);
  }
  lines.push('', `Local history entries: ${site.history.length}`, 'The JSON bundle includes the full local history. It is not an immutable or externally witnessed log.',
    'This record does not establish criminal intent, liability, truth, or complete surveillance coverage.');
  return lines.join('\n');
}

export async function createFieldBundle(input, options = {}) {
  const site = validateSite(input);
  const audit = auditFieldSecuritySite(site);
  const receipt = await createFieldSecurityReceipt(site, audit, options);
  return {
    format: 'watch-dawg-field-bundle', version: 1, site, audit, receipt,
    report: fieldReport(site, audit),
    limitations: 'Unsigned SHA-256 integrity record. No authenticated signer, trusted timestamp, or original file bytes. Hashes do not prove truth.',
  };
}

const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;

export async function verifyFieldBundle(input) {
  if (!input || input.format !== 'watch-dawg-field-bundle' || input.version !== 1 || !input.receipt) throw new Error('Unsupported field bundle.');
  if (typeof input.receipt.createdAt !== 'string' || !Number.isFinite(Date.parse(input.receipt.createdAt)) || typeof input.receipt.issuer !== 'string' || !input.receipt.issuer.trim()) throw new Error('Invalid receipt metadata.');
  const expected = await createFieldBundle(input.site, { createdAt: input.receipt.createdAt, issuer: input.receipt.issuer });
  if (JSON.stringify(canonical(expected)) !== JSON.stringify(canonical(input))) throw new Error('Bundle integrity check failed: content, report, audit, or receipt changed.');
  return { status: 'INTEGRITY_CHECKED', site: clone(expected.site), receiptDigest: expected.receipt.receiptDigest };
}
