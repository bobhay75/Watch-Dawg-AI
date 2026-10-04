import { sampleFieldSecurityPilot } from './field-security.js';

export const STORAGE_KEY = 'watch-dawg-field-security-site-v1';
export const MAX_RECORD_BYTES = 4 * 1024 * 1024;
export const clone = (value) => JSON.parse(JSON.stringify(value));
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = (message) => { throw new Error(message); };
const text = (value, label, required = false, max = 4000) => {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim())) fail(`${label} must be ${required ? 'non-empty ' : ''}text (up to ${max} characters).`);
};
const choice = (value, allowed, label) => { if (!allowed.includes(value)) fail(`Invalid ${label}.`); };
const list = (value, label, max = 1000) => { if (!Array.isArray(value) || value.length > max) fail(`Invalid ${label} (maximum ${max}).`); };
const date = (value, label) => { text(value, label, true, 64); if (!Number.isFinite(Date.parse(value))) fail(`Invalid ${label}.`); };
const unique = (items, label) => {
  const ids = new Set();
  for (const item of items) {
    if (!object(item)) fail(`Invalid ${label} entry.`);
    text(item.id, `${label} ID`, true, 120);
    if (ids.has(item.id)) fail(`Duplicate ${label} ID.`);
    ids.add(item.id);
  }
  return ids;
};

// Validate before persisting. Legacy v1 records remain readable without inventing review identity.
export function validateSite(input) {
  if (!object(input)) fail('Site record must be an object.');
  if (new TextEncoder().encode(JSON.stringify(input)).length > MAX_RECORD_BYTES) fail('Site record exceeds the 4 MB limit. Export and archive this record first.');
  const site = clone(input);
  text(site.siteId, 'Site ID', true, 120);
  text(site.siteName, 'Site name', true, 200);
  if (typeof site.authorizedUse !== 'boolean') fail('Authorization must be true or false.');
  if (!object(site.ownerContact)) fail('Owner contact is required.');
  text(site.ownerContact.primary, 'Primary contact', false, 200);
  if (site.ownerContact.escalation !== undefined) text(site.ownerContact.escalation, 'Escalation contact', false, 200);
  if (site.capturedAt !== undefined) date(site.capturedAt, 'Record date');
  list(site.zones, 'zones', 200);
  list(site.incidents, 'incidents', 1000);
  const zones = unique(site.zones, 'zone');
  unique(site.incidents, 'incident');
  for (const zone of site.zones) {
    text(zone.name, 'Zone name', true, 200);
    choice(zone.boundaryType, ['open', 'restricted'], 'boundary');
    choice(zone.status, ['normal', 'attention', 'unmonitored'], 'zone status');
    for (const key of ['allowedWindow', 'rule']) if (zone[key] !== undefined) text(zone[key], key);
  }
  const evidence = [];
  for (const incident of site.incidents) {
    text(incident.title, 'Incident title', true, 300);
    if (!zones.has(incident.zoneId)) fail('Incident must reference an existing zone.');
    choice(incident.status, ['open', 'resolved'], 'incident status');
    choice(incident.severity, ['low', 'medium', 'high', 'critical'], 'severity');
    choice(incident.reviewStatus, ['needs-evidence', 'needs-human-review', 'human-reviewed'], 'review status');
    if (incident.occurredAt !== undefined) date(incident.occurredAt, 'Incident date');
    for (const key of ['observedBy', 'notes', 'resolutionNote']) if (incident[key] !== undefined) text(incident[key], key);
    if (incident.review !== undefined) {
      if (!object(incident.review)) fail('Invalid review record.');
      text(incident.review.reviewer, 'Reviewer', true, 200);
      text(incident.review.note, 'Review note', true);
      date(incident.review.at, 'Review date');
    }
    list(incident.evidence, 'evidence', 200);
    evidence.push(...incident.evidence);
    for (const item of incident.evidence) {
      if (!object(item)) fail('Invalid evidence item.');
      text(item.type, 'Evidence type', true, 120);
      text(item.description, 'Evidence description', true);
      if (item.attachment !== undefined) {
        const a = item.attachment;
        if (!object(a)) fail('Invalid file metadata.');
        text(a.name, 'File name', true, 500);
        text(a.type, 'File type', false, 200);
        if (!Number.isSafeInteger(a.size) || a.size < 0 || a.size > 20 * 1024 * 1024) fail('Invalid file size.');
        if (!/^[a-f0-9]{64}$/.test(a.sha256)) fail('Invalid file fingerprint.');
        if (a.bytesIncluded !== false) fail('File bytes must remain outside this local record.');
      }
    }
  }
  unique(evidence, 'evidence');
  site.history ??= [];
  list(site.history, 'history', 2000);
  for (const entry of site.history) {
    if (!object(entry)) fail('Invalid history entry.');
    text(entry.action, 'History action', true, 100);
    date(entry.at, 'History date');
  }
  return site;
}

export const blankSite = () => ({
  recordKind: 'field',
  siteId: `SITE-${crypto.randomUUID()}`, siteName: 'My jobsite', authorizedUse: false,
  ownerContact: { primary: '', escalation: '' }, zones: [], incidents: [], history: [],
});

export function createSiteStore(storage, { clock = () => new Date().toISOString(), id = (prefix) => `${prefix}-${crypto.randomUUID()}` } = {}) {
  let site;
  let savedRaw;
  let blocked = false;
  let startupError = '';
  try {
    savedRaw = storage.getItem(STORAGE_KEY);
    site = validateSite(savedRaw === null ? clone(sampleFieldSecurityPilot) : JSON.parse(savedRaw));
  } catch (error) {
    blocked = true;
    startupError = `Saved data could not be loaded: ${error.message} The stored value has not been replaced. Download it before starting a new record.`;
    site = validateSite(blankSite());
  }
  let persisted = savedRaw !== null && !blocked;
  function write(next, allowRecovery = false) {
    if (blocked && !allowRecovery) fail(startupError);
    const validated = validateSite(next);
    if (storage.getItem(STORAGE_KEY) !== savedRaw) fail('This record changed in another tab. Reload before saving; your form has been kept.');
    const raw = JSON.stringify(validated);
    storage.setItem(STORAGE_KEY, raw); // State changes only after durable browser storage succeeds.
    site = validated;
    savedRaw = raw;
    blocked = false;
    startupError = '';
    persisted = true;
    return clone(site);
  }
  function transaction(action, change) {
    const next = clone(site);
    const detail = change(next);
    const at = clock();
    next.capturedAt = at;
    next.history.push({ action, at, ...detail });
    return write(next);
  }
  function find(next, incidentId) {
    const incident = next.incidents.find((item) => item.id === incidentId);
    if (!incident) fail('Select an incident first.');
    return incident;
  }
  function invalidate(incident) {
    incident.reviewStatus = 'needs-human-review';
    incident.status = 'open';
    delete incident.review;
    delete incident.resolutionNote;
  }
  return {
    get: () => clone(site),
    snapshot() {
      if (blocked) fail(startupError);
      if (storage.getItem(STORAGE_KEY) !== savedRaw) fail('This record changed in another tab. Reload before exporting.');
      return clone(site);
    },
    status: () => ({ blocked, startupError, persisted }),
    raw: () => savedRaw,
    replace(input) { return write(validateSite(input), true); },
    saveSite(fields) {
      return transaction('site-updated', (next) => {
        const before = { siteName: next.siteName, ownerContact: next.ownerContact, authorizedUse: next.authorizedUse };
        next.siteName = fields.siteName; next.ownerContact = clone(fields.ownerContact); next.authorizedUse = fields.authorizedUse;
        return { before, after: clone(fields) };
      });
    },
    addZone(fields) {
      return transaction('zone-added', (next) => {
        const zone = { ...fields, id: id('ZONE') }; next.zones.push(zone); return { zone: clone(zone) };
      });
    },
    addIncident(fields) {
      return transaction('incident-added', (next) => {
        const incident = { ...fields, id: id('INC'), status: 'open', reviewStatus: 'needs-human-review', evidence: [] };
        next.incidents.push(incident); return { incident: clone(incident) };
      });
    },
    editIncident(incidentId, fields) {
      return transaction('incident-edited', (next) => {
        const incident = find(next, incidentId), before = clone(incident);
        for (const key of ['title', 'zoneId', 'severity', 'occurredAt', 'observedBy', 'notes']) if (fields[key] !== undefined) incident[key] = fields[key];
        invalidate(incident);
        return { incidentId, before, after: clone(incident) };
      });
    },
    addEvidence(incidentId, fields) {
      return transaction('evidence-added', (next) => {
        const incident = find(next, incidentId), before = clone(incident);
        const item = { ...fields, id: id('EV'), addedAt: clock() };
        incident.evidence.push(item); invalidate(incident);
        return { incidentId, before, evidence: clone(item) };
      });
    },
    reviewIncident(incidentId, reviewer, note) {
      return transaction('incident-reviewed', (next) => {
        const incident = find(next, incidentId);
        if (!next.authorizedUse) fail('Confirm your authority in Site details before recording a review.');
        const before = clone(incident);
        incident.review = { reviewer: reviewer.trim(), note: note.trim(), at: clock() };
        incident.reviewStatus = 'human-reviewed';
        return { incidentId, before, review: clone(incident.review) };
      });
    },
    resolveIncident(incidentId, note) {
      return transaction('incident-resolved', (next) => {
        const incident = find(next, incidentId);
        if (!next.authorizedUse || incident.reviewStatus !== 'human-reviewed' || !incident.review || !incident.evidence.length) fail('Resolution requires authority, a recorded human review, and at least one evidence item.');
        text(note, 'Resolution note', true);
        const before = clone(incident);
        incident.status = 'resolved'; incident.resolutionNote = note.trim();
        return { incidentId, before, resolutionNote: incident.resolutionNote };
      });
    },
    reopenIncident(incidentId) {
      return transaction('incident-reopened', (next) => {
        const incident = find(next, incidentId), before = clone(incident);
        invalidate(incident); return { incidentId, before };
      });
    },
  };
}
