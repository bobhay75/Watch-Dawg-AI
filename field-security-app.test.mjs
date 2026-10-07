import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createSiteStore, STORAGE_KEY, blankSite, validateSite } from './field-security-store.js';
import { createFieldBundle, verifyFieldBundle, fingerprintFile, fieldReport } from './field-security-export.js';
import { auditFieldSecuritySite, sampleFieldSecurityPilot } from './field-security.js';
import { createPreviewServer } from './scripts/serve-field-desk.mjs';

const copy = (value) => JSON.parse(JSON.stringify(value));
function memory(raw = null) {
  return { value: raw, getItem(key) { assert.equal(key, STORAGE_KEY); return this.value; }, setItem(key, value) { assert.equal(key, STORAGE_KEY); this.value = value; } };
}
function fixture() {
  const storage = memory();
  let serial = 0;
  const store = createSiteStore(storage, { clock: () => '2026-10-03T12:00:00.000Z', id: (prefix) => `${prefix}-${++serial}` });
  store.replace(blankSite());
  store.saveSite({ siteName: 'Test jobsite', ownerContact: { primary: 'Owner', escalation: 'Lead' }, authorizedUse: true });
  store.addZone({ name: 'Tool area', boundaryType: 'restricted', status: 'normal' });
  const zoneId = store.get().zones[0].id;
  store.addIncident({ title: 'Latch open', zoneId, severity: 'high', occurredAt: '2026-10-03T10:00:00Z', observedBy: 'Owner', notes: 'Needs a check.' });
  const incidentId = store.get().incidents[0].id;
  return { store, storage, incidentId, zoneId };
}

test('fresh storage displays sample without persisting it; legacy v1 migrates in memory', () => {
  const storage = memory(), store = createSiteStore(storage);
  assert.equal(store.get().incidents.length, 3);
  assert.equal(storage.value, null);
  const raw = JSON.stringify(sampleFieldSecurityPilot), legacyStorage = memory(raw);
  const legacy = createSiteStore(legacyStorage);
  assert.deepEqual(legacy.get().history, []);
  assert.equal(legacyStorage.value, raw);
  assert.equal(legacy.get().incidents[2].review, undefined);
});

test('incident review does not resolve; resolution requires evidence and explicit note', () => {
  const { store, incidentId } = fixture();
  assert.throws(() => store.resolveIncident(incidentId, 'Done'), /requires/);
  store.reviewIncident(incidentId, 'Owner', 'Looked at the record.');
  assert.equal(store.get().incidents[0].status, 'open');
  assert.throws(() => store.resolveIncident(incidentId, 'Done'), /requires/);
  store.addEvidence(incidentId, { type: 'note', description: 'Latch inspected.' });
  assert.equal(store.get().incidents[0].reviewStatus, 'needs-human-review');
  store.reviewIncident(incidentId, 'Owner', 'Latch is intact.');
  assert.throws(() => store.resolveIncident(incidentId, '   '), /Resolution note/);
  store.resolveIncident(incidentId, 'Closed and photographed.');
  assert.equal(store.get().incidents[0].status, 'resolved');
  const loaded = createSiteStore(memory(JSON.stringify(store.get())));
  assert.equal(loaded.get().incidents[0].resolutionNote, 'Closed and photographed.');
});

test('editing preserves before values, invalidates review, reopens, and retains evidence', () => {
  const { store, incidentId } = fixture();
  store.addEvidence(incidentId, { type: 'note', description: 'Original note' });
  store.reviewIncident(incidentId, 'Owner', 'Reviewed original.');
  store.resolveIncident(incidentId, 'Resolved original.');
  store.editIncident(incidentId, { title: 'Latch open again', status: 'resolved', evidence: [] });
  const site = store.get(), incident = site.incidents[0];
  assert.equal(incident.title, 'Latch open again');
  assert.equal(incident.status, 'open');
  assert.equal(incident.reviewStatus, 'needs-human-review');
  assert.equal(incident.review, undefined);
  assert.equal(incident.evidence.length, 1);
  assert.equal(site.history.at(-1).before.title, 'Latch open');
  assert.equal(site.history.at(-1).before.review.reviewer, 'Owner');
  assert.equal(site.history.at(-1).before.resolutionNote, 'Resolved original.');
});

test('explicit reopen preserves prior resolution in history', () => {
  const { store, incidentId } = fixture();
  store.addEvidence(incidentId, { type: 'note', description: 'Noted' });
  store.reviewIncident(incidentId, 'Owner', 'Reviewed');
  store.resolveIncident(incidentId, 'Done');
  store.reopenIncident(incidentId);
  assert.equal(store.get().incidents[0].status, 'open');
  assert.equal(store.get().history.at(-1).before.resolutionNote, 'Done');
});

test('review requires authority, reviewer, and review note', () => {
  const { store, incidentId } = fixture();
  for (const [who, note] of [['', 'Note'], ['Owner', '']]) assert.throws(() => store.reviewIncident(incidentId, who, note), /Reviewer|Review note/);
  store.saveSite({ siteName: 'Test', ownerContact: { primary: 'Owner' }, authorizedUse: false });
  assert.throws(() => store.reviewIncident(incidentId, 'Owner', 'Reviewed'), /authority/);
});

test('invalid changes and full storage cannot alter in-memory or persisted records', () => {
  const { store, storage, incidentId } = fixture();
  const before = store.get(), raw = storage.value;
  assert.throws(() => store.editIncident(incidentId, { zoneId: 'missing' }), /existing zone/);
  assert.throws(() => store.editIncident(incidentId, { title: ' ' }), /Incident title/);
  assert.deepEqual(store.get(), before); assert.equal(storage.value, raw);
  storage.setItem = () => { throw new Error('Quota exceeded'); };
  assert.throws(() => store.editIncident(incidentId, { title: 'Cannot save' }), /Quota/);
  assert.deepEqual(store.get(), before); assert.equal(storage.value, raw);
});

test('stale tabs cannot overwrite a newer saved record', () => {
  const { storage, store, incidentId } = fixture(), other = createSiteStore(storage);
  store.editIncident(incidentId, { title: 'First tab edit' });
  const raw = storage.value;
  assert.throws(() => other.editIncident(incidentId, { title: 'Second tab edit' }), /another tab/);
  assert.throws(() => other.snapshot(), /Reload before exporting/);
  assert.equal(storage.value, raw);
  assert.equal(other.get().incidents[0].title, 'Latch open');
});

for (const bad of ['{broken', 'null', '{"zones":[]}']) {
  test(`corrupt storage stays untouched and blocks saves (${bad})`, () => {
    const storage = memory(bad), store = createSiteStore(storage);
    assert.equal(store.status().blocked, true);
    assert.equal(store.raw(), bad);
    assert.throws(() => store.addZone({ name: 'X', boundaryType: 'open', status: 'normal' }), /could not be loaded/);
    assert.equal(storage.value, bad);
    store.replace(blankSite());
    assert.equal(store.status().blocked, false);
    assert.equal(store.get().incidents.length, 0);
  });
}

test('disabled storage fails visibly without claiming persistence', () => {
  const storage = { getItem() { throw new Error('Storage disabled'); }, setItem() { throw new Error('Storage disabled'); } };
  const store = createSiteStore(storage);
  assert.equal(store.status().blocked, true);
  assert.equal(store.status().persisted, false);
  assert.match(store.status().startupError, /Storage disabled/);
});

test('schema rejects malformed records, duplicate IDs, foreign references, and oversized input', () => {
  const { store } = fixture();
  const original = store.get();
  const changes = [
    (s) => { s.zones = [null]; },
    (s) => { s.incidents[0].evidence = [null]; },
    (s) => { s.zones.push(copy(s.zones[0])); },
    (s) => { s.incidents[0].zoneId = 'not-a-zone'; },
    (s) => { s.incidents[0].severity = 'made-up'; },
    (s) => { s.incidents[0].occurredAt = 'not-a-date'; },
    (s) => { s.authorizedUse = 'true'; },
    (s) => { s.extra = 'x'.repeat(4 * 1024 * 1024); },
  ];
  for (const mutate of changes) { const next = copy(original); mutate(next); assert.throws(() => store.replace(next)); assert.deepEqual(store.get(), original); }
});

test('read snapshots cannot mutate the store', () => {
  const { store } = fixture();
  const snapshot = store.get(); snapshot.incidents[0].title = 'Tampered'; snapshot.history.length = 0;
  assert.equal(store.get().incidents[0].title, 'Latch open');
  assert.ok(store.get().history.length);
});

test('resolved imported incidents still surface missing evidence and review', () => {
  const { store } = fixture(); const site = store.get(); site.incidents[0].status = 'resolved';
  const audit = auditFieldSecuritySite(site);
  assert.equal(audit.status, 'REVIEW');
  assert.ok(audit.findings.some((item) => item.category === 'evidence'));
  assert.ok(audit.findings.some((item) => item.category === 'human-review'));
});

test('file fingerprints hash exact bytes and never retain file contents', async () => {
  const bytes = 'Synthetic field evidence\n';
  const file = new File([bytes], 'field-note.txt', { type: 'text/plain' });
  const metadata = await fingerprintFile(file);
  assert.equal(metadata.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.deepEqual(Object.keys(metadata).sort(), ['bytesIncluded', 'name', 'sha256', 'size', 'type']);
  assert.equal(metadata.bytesIncluded, false);
  await assert.rejects(fingerprintFile({ size: 20 * 1024 * 1024 + 1, arrayBuffer() { throw new Error('must not read'); } }), /20 MB/);
});

test('bundle round-trip binds source, history, audit, report, and receipt', async () => {
  const { store, incidentId } = fixture();
  store.addEvidence(incidentId, { type: 'photo-note', description: 'Synthetic photo note', attachment: await fingerprintFile(new File(['abc'], 'test.txt')) });
  store.reviewIncident(incidentId, 'Owner', 'Reviewed the note.');
  const bundle = await createFieldBundle(store.get(), { createdAt: '2026-10-03T12:00:00Z' });
  const result = await verifyFieldBundle(JSON.parse(JSON.stringify(bundle)));
  assert.equal(result.status, 'INTEGRITY_CHECKED');
  assert.deepEqual(result.site, store.get());
  assert.match(bundle.report, /Synthetic photo note/);
  assert.match(bundle.report, /Reviewed the note/);
  assert.match(bundle.report, /original not included/);
  assert.match(bundle.limitations, /Unsigned/);
  const restored = createSiteStore(memory()); restored.replace(result.site);
  assert.deepEqual(restored.get(), store.get());
  const reordered = Object.fromEntries(Object.entries(bundle).reverse());
  assert.equal((await verifyFieldBundle(reordered)).status, 'INTEGRITY_CHECKED');
});

test('bundle rejects content changes and stale or forged derived results', async () => {
  const { store } = fixture(); const bundle = await createFieldBundle(store.get());
  const changes = [
    (b) => { b.site.incidents[0].title = 'Changed'; },
    (b) => { b.site.history[0].action = 'Changed'; },
    (b) => { b.audit.findings = []; },
    (b) => { b.report += '\nChanged'; },
    (b) => { b.receipt.sourceDigest = '0'.repeat(64); },
    (b) => { b.receipt.receiptDigest = '0'.repeat(64); },
    (b) => { b.receipt.createdAt = ''; },
    (b) => { b.limitations = 'Verified truth'; },
    (b) => { b.version = 99; },
  ];
  for (const mutate of changes) { const bad = copy(bundle); mutate(bad); await assert.rejects(verifyFieldBundle(bad)); }
});

test('report contains resolution, evidence, and observer details', () => {
  const { store, incidentId } = fixture(); store.addEvidence(incidentId, { type: 'note', description: 'Checked hardware' });
  store.reviewIncident(incidentId, 'Reviewer A', 'No damage found'); store.resolveIncident(incidentId, 'Latch secured');
  const report = fieldReport(store.get());
  for (const text of ['Latch secured', 'Checked hardware', 'Reviewer A', 'No damage found', 'Observed by: Owner']) assert.ok(report.includes(text));
});

test('preview serves only public field desk assets and fails closed on unknown paths', async (t) => {
  const server = createPreviewServer(); await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const root = await fetch(base); assert.equal(root.status, 200); assert.match(root.headers.get('content-type'), /text\/html/);
  assert.match(root.headers.get('content-security-policy'), /connect-src 'none'/);
  for (const asset of ['field-security-app.js', 'field-security-store.js', 'field-security-export.js', 'field-security.js', 'field-security.css']) {
    const result = await fetch(`${base}/${asset}`); assert.equal(result.status, 200); assert.match(result.headers.get('content-type'), asset.endsWith('.css') ? /text\/css/ : /text\/javascript/);
  }
  for (const path of ['/unknown', '/missing/app.js', '/.git/config', '/README.md', '/field-security-store.js/extra']) {
    const result = await fetch(base + path); assert.equal(result.status, 404); assert.match(result.headers.get('x-robots-tag'), /noindex/);
  }
  assert.equal((await fetch(base, { method: 'POST' })).status, 405);
});

test('field desk loads external modules, labeled dialogs, and reduced-motion styles', async () => {
  const html = await readFile(new URL('./field-security-demo.html', import.meta.url), 'utf8');
  const css = await readFile(new URL('./field-security.css', import.meta.url), 'utf8');
  assert.match(html, /type="module" src="\.\/field-security-app.js"/);
  assert.match(html, /dialog id="formDialog" aria-labelledby="formTitle"/);
  assert.match(css, /prefers-reduced-motion/);
  assert.doesNotMatch(html, /https:\/\//);
});


test('original verification checks exact bytes and supports empty files', async () => {
  const { verifyOriginal } = await import('./field-security-files.js');
  const original = new Blob(['exact bytes']);
  const metadata = await fingerprintFile(original);
  assert.equal(await verifyOriginal(original, metadata), original);
  await assert.rejects(verifyOriginal(new Blob(['other bytes']), metadata), /fingerprint/);
  await assert.rejects(verifyOriginal(new Blob(['short']), metadata), /size/);
  await assert.rejects(verifyOriginal(new Blob(['wrong byte!']), { ...metadata, size: 11 }), /fingerprint/);
  await assert.rejects(verifyOriginal(undefined, metadata), /unavailable/);
  const empty = new Blob([]);
  assert.equal(await verifyOriginal(empty, await fingerprintFile(empty)), empty);
});

test('unavailable original storage fails without changing incident records', async () => {
  const { createOriginalStore } = await import('./field-security-files.js');
  const { store, incidentId } = fixture();
  const before = store.get();
  const originals = createOriginalStore(() => { throw new Error('storage disabled'); });
  const file = new Blob(['synthetic']);
  const attachment = await fingerprintFile(file);
  await assert.rejects((async () => {
    await originals.put(file, attachment);
    store.addEvidence(incidentId, { type: 'field-note', description: 'test', attachment });
  })(), /unavailable/);
  assert.deepEqual(store.get(), before);
});
