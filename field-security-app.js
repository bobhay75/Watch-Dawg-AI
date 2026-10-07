import { auditFieldSecuritySite, sampleFieldSecurityPilot } from './field-security.js';
import { createSiteStore, blankSite, validateSite } from './field-security-store.js';
import { fingerprintFile, createFieldBundle, verifyFieldBundle, fieldReport } from './field-security-export.js';
import { createOriginalStore } from './field-security-files.js';

const originals = createOriginalStore();
let detailRender = 0;

const $ = (id) => document.getElementById(id);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const pretty = (value) => JSON.stringify(value, null, 2);
// Access can itself throw in browsers with storage disabled, so defer it to the store's error boundary.
const store = createSiteStore({ getItem: (key) => localStorage.getItem(key), setItem: (key, value) => localStorage.setItem(key, value) });
let selectedId = null;
let submitAction;
let busy = false;
let toastTimer;
const dateText = (date) => date ? new Date(date).toLocaleString() : 'Date not recorded';
const localDate = (value = new Date().toISOString()) => {
  const date = new Date(value); date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
};
const tag = (text, kind = '') => `<span class="tag ${escape(kind)}">${escape(text)}</span>`;
function toast(message) { $('toast').textContent = message; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').textContent = ''; }, 5000); }
function showError(error) { $('error').textContent = error.message || String(error); $('error').hidden = false; }
function download(name, content, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
function safeAction(action) {
  return async () => { try { $('error').hidden = true; await action(); } catch (error) { showError(error); } };
}
function selected() { return store.get().incidents.find((incident) => incident.id === selectedId); }

function renderList(site) {
  const query = $('search').value.trim().toLowerCase(), filter = $('filter').value;
  const incidents = site.incidents.filter((incident) => {
    const zone = site.zones.find((item) => item.id === incident.zoneId)?.name || '';
    return `${incident.title} ${zone}`.toLowerCase().includes(query) && (filter === 'all' || (filter === 'review' ? incident.reviewStatus !== 'human-reviewed' : incident.status === filter));
  });
  $('incidentList').innerHTML = incidents.map((incident) => {
    const zone = site.zones.find((item) => item.id === incident.zoneId)?.name;
    return `<button class="incident-card" data-incident="${escape(incident.id)}" aria-pressed="${incident.id === selectedId}">${tag(incident.severity, incident.severity)} ${tag(incident.status, incident.status)}<strong>${escape(incident.title)}</strong><span class="meta"><span>${escape(zone)}</span><span>${incident.evidence.length} evidence · ${incident.reviewStatus === 'human-reviewed' ? 'Reviewed' : 'Needs review'}</span></span></button>`;
  }).join('') || '<p class="empty">No matching incidents. Report an incident or change your filters.</p>';
}

function renderDetail(site) {
  const renderId = ++detailRender;
  const incident = site.incidents.find((item) => item.id === selectedId);
  $('detail').hidden = !incident; $('detailEmpty').hidden = Boolean(incident);
  if (!incident) return;
  $('detailId').textContent = incident.id;
  $('detailTitle').textContent = incident.title;
  $('detailTags').innerHTML = tag(incident.severity, incident.severity) + tag(incident.status, incident.status) + tag(incident.reviewStatus === 'human-reviewed' ? 'Human reviewed' : 'Needs review', incident.reviewStatus === 'human-reviewed' ? 'reviewed' : '');
  const zone = site.zones.find((item) => item.id === incident.zoneId);
  $('detailMeta').textContent = `${zone.name} · ${dateText(incident.occurredAt)} · ${incident.observedBy || 'Observer not recorded'}`;
  $('detailNotes').textContent = incident.notes || 'No additional notes recorded.';
  $('evidenceList').innerHTML = incident.evidence.map((item) => `<article class="evidence-item"><span class="eyebrow">${escape(item.type)}</span><p>${escape(item.description)}</p>${item.attachment ? `<p class="hint">${escape(item.attachment.name)} · ${item.attachment.size.toLocaleString()} bytes · Original copy: <span data-file-status="${escape(item.id)}">checking this device…</span></p><code>SHA-256 ${escape(item.attachment.sha256)}</code><div class="tags"><button data-download-original="${escape(item.id)}" disabled>Download original ↓</button><button data-connect-original="${escape(item.id)}">Reconnect original</button></div>` : '<span class="hint">Note only · No file fingerprint</span>'}</article>`).join('') || '<p class="empty">No evidence yet. Add a note and, optionally, a file.</p>';
  for (const item of incident.evidence.filter((entry) => entry.attachment)) {
    originals.has(item.attachment).then((exists) => updateOriginal(item.id, exists, exists ? 'saved on this device' : 'not on this device')).catch(() => updateOriginal(item.id, false, 'storage unavailable'));
  }
  function updateOriginal(id, exists, message) {
    if (renderId !== detailRender) return;
    for (const label of $('evidenceList').querySelectorAll('[data-file-status]')) if (label.dataset.fileStatus === id) label.textContent = message;
    for (const button of $('evidenceList').querySelectorAll('[data-download-original]')) if (button.dataset.downloadOriginal === id) button.disabled = !exists;
  }
  $('reviewDetail').textContent = incident.review ? `${incident.review.reviewer} · ${dateText(incident.review.at)}\n${incident.review.note}\nReviewer name is self-declared.` : incident.reviewStatus === 'human-reviewed' ? 'Legacy record marked reviewed. No reviewer or review note was recorded; add a review before resolving.' : 'This incident needs a human review.';
  $('resolutionDetail').textContent = incident.resolutionNote ? `Resolution: ${incident.resolutionNote}` : '';
  $('resolveButton').hidden = incident.status === 'resolved'; $('reopenButton').hidden = incident.status !== 'resolved';
  $('resolveButton').disabled = incident.reviewStatus !== 'human-reviewed' || !incident.review || !incident.evidence.length || !site.authorizedUse;
  const history = site.history.filter((entry) => entry.incidentId === selectedId || entry.incident?.id === selectedId);
  $('historyList').innerHTML = history.slice().reverse().map((entry) => `<li>${escape(entry.action.replaceAll('-', ' '))} · ${escape(dateText(entry.at))}</li>`).join('') || '<li>No local activity recorded for this incident yet.</li>';
}

function render() {
  const site = store.get(), audit = auditFieldSecuritySite(site), status = store.status();
  $('siteHeading').textContent = site.siteName;
  $('siteMeta').textContent = `${site.ownerContact.primary || 'Add an owner contact'} · ${site.authorizedUse ? 'Authority declared by user' : 'Authority not yet confirmed'}`;
  $('siteKind').textContent = status.blocked ? 'Recovery needed' : site.recordKind === 'sample' ? 'Fictional sample workspace' : status.persisted ? 'Saved local record' : 'Unsaved record';
  $('storageStatus').textContent = status.blocked ? status.startupError : site.recordKind === 'sample' ? 'You are viewing fictional sample data. Start a new site for your own records, or edit the sample to try the workflow.' : status.persisted ? 'Saved in this browser. Export a bundle for backup; browser storage can be cleared or lost.' : 'This record has not been saved yet.';
  $('rawBackupButton').hidden = !status.blocked || store.raw() == null;
  for (const id of ['bundleButton', 'reportButton', 'receiptButton']) $(id).disabled = status.blocked;
  $('openCount').textContent = audit.summary.openIncidents;
  $('reviewCount').textContent = site.incidents.filter((item) => item.reviewStatus !== 'human-reviewed').length;
  $('evidenceCount').textContent = audit.summary.evidenceItems;
  $('zoneCount').textContent = site.zones.length;
  renderList(site); renderDetail(site);
  $('zoneList').innerHTML = site.zones.map((zone) => `<article class="zone-item"><strong>${escape(zone.name)}</strong><div class="tags">${tag(zone.boundaryType)}${tag(zone.status)}${tag(zone.allowedWindow || 'No hours recorded')}</div><p>${escape(zone.rule || 'No rule recorded.')}</p></article>`).join('') || '<p class="empty">Add a zone before reporting your first incident.</p>';
  $('findingList').innerHTML = audit.findings.map((finding) => `<article class="finding"><strong>${escape(finding.severity.toUpperCase())} / ${escape(finding.category)}</strong><p>${escape(finding.message)}</p></article>`).join('') || '<p class="empty">No rule findings in this record. This does not establish that the site is safe.</p>';
  $('report').textContent = fieldReport(site, audit);
  $('receipt').hidden = true; $('receipt').textContent = '';
}

const input = (name, label, value = '', extra = '') => `<label>${label}<input name="${name}" value="${escape(value)}" ${extra}></label>`;
const area = (name, label, value = '', required = '') => `<label>${label}<textarea name="${name}" maxlength="4000" ${required}>${escape(value)}</textarea></label>`;
const select = (name, label, options, value) => `<label>${label}<select name="${name}">${options.map(([id, title]) => `<option value="${escape(id)}" ${id === value ? 'selected' : ''}>${escape(title)}</option>`).join('')}</select></label>`;
const value = (data, name) => String(data.get(name) || '').trim();
function openForm(title, hint, fields, action, submit = 'Save') {
  $('formTitle').textContent = title; $('formHint').textContent = hint; $('formFields').innerHTML = fields;
  $('formError').hidden = true; $('submitForm').textContent = submit; submitAction = action;
  $('formDialog').showModal();
  $('formFields').querySelector('input,select,textarea')?.focus();
}
function closeForm() { if (!busy) $('formDialog').close(); }
$('closeDialog').addEventListener('click', closeForm); $('cancelDialog').addEventListener('click', closeForm);
$('formDialog').addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
$('entryForm').addEventListener('submit', async (event) => {
  event.preventDefault(); if (busy) return;
  busy = true; $('submitForm').disabled = true; $('cancelDialog').disabled = true; $('closeDialog').disabled = true;
  try { await submitAction(new FormData(event.target)); $('formDialog').close(); $('error').hidden = true; render(); }
  catch (error) { $('formError').textContent = error.message; $('formError').hidden = false; }
  finally { busy = false; $('submitForm').disabled = false; $('cancelDialog').disabled = false; $('closeDialog').disabled = false; }
});

function confirmReplace(title, message, record) {
  $('confirmTitle').textContent = title; $('confirmMessage').textContent = message;
  $('confirmDialog').showModal(); $('cancelConfirm').focus();
  $('acceptConfirm').onclick = safeAction(() => {
    store.replace(record); selectedId = null; $('search').value = ''; $('filter').value = 'all';
    $('confirmDialog').close(); render(); toast('Local record replaced.');
  });
}
$('cancelConfirm').addEventListener('click', () => $('confirmDialog').close());
$('newSiteButton').addEventListener('click', () => confirmReplace('Start a new site?', 'This replaces the current site in this browser. Export its evidence bundle first if you want to keep it. The new site starts empty.', blankSite()));
$('sampleButton').addEventListener('click', () => confirmReplace('Replace with sample data?', 'This replaces your current site. Export a backup first. The sample is fictional and is only for trying the workflow.', sampleFieldSecurityPilot));
$('siteDetailsButton').addEventListener('click', () => {
  const site = store.get();
  openForm('Site details', 'One site is saved in this browser. Start a new site to clear its incidents and zones.',
    input('siteName', 'Site name', site.siteName, 'required maxlength="200"') + input('primary', 'Primary contact', site.ownerContact.primary, 'maxlength="200"') + input('escalation', 'Escalation contact', site.ownerContact.escalation, 'maxlength="200"') + `<label class="check"><input name="authorized" type="checkbox" ${site.authorizedUse ? 'checked' : ''}>I own this site or have explicit authority to document it.</label>`,
    (data) => { store.saveSite({ siteName: value(data, 'siteName'), ownerContact: { primary: value(data, 'primary'), escalation: value(data, 'escalation') }, authorizedUse: data.has('authorized') }); toast('Site saved locally.'); });
});
$('addZoneButton').addEventListener('click', () => openForm('Add a site zone', 'Define where an incident can happen and what access you expect.',
  input('name', 'Zone name', '', 'required maxlength="200"') + select('boundaryType', 'Boundary', [['open', 'Open'], ['restricted', 'Restricted']], 'open') + select('status', 'Coverage status', [['normal', 'Normal'], ['attention', 'Needs attention'], ['unmonitored', 'Unmonitored']], 'normal') + input('allowedWindow', 'Allowed hours', '', 'maxlength="4000" placeholder="07:00–17:00"') + area('rule', 'Zone rule'),
  (data) => { store.addZone(Object.fromEntries(['name', 'boundaryType', 'status', 'allowedWindow', 'rule'].map((key) => [key, value(data, key)]))); toast('Zone added.'); }, 'Add zone'));

function incidentForm(edit = false) {
  const site = store.get(), incident = edit ? selected() : null;
  if (!site.zones.length) { toast('Add a site zone first.'); $('addZoneButton').focus(); return; }
  const incidentId = incident?.id;
  openForm(edit ? 'Edit incident' : 'Report an incident', edit ? 'Saving changes reopens this incident for human review. Previous values remain in local history.' : 'Record observations, not assumptions about intent. New incidents remain open until explicitly resolved.',
    input('title', 'Incident title', incident?.title, 'required maxlength="300"') + select('zoneId', 'Zone', site.zones.map((zone) => [zone.id, zone.name]), incident?.zoneId) + select('severity', 'Severity', ['low', 'medium', 'high', 'critical'].map((item) => [item, item[0].toUpperCase() + item.slice(1)]), incident?.severity || 'low') + input('occurredAt', 'Occurred at', localDate(incident?.occurredAt), 'type="datetime-local" required') + input('observedBy', 'Observed by', incident?.observedBy, 'maxlength="4000"') + area('notes', 'What happened?', incident?.notes),
    (data) => {
      const fields = Object.fromEntries(['title', 'zoneId', 'severity', 'observedBy', 'notes'].map((key) => [key, value(data, key)]));
      fields.occurredAt = new Date(value(data, 'occurredAt')).toISOString();
      const next = edit ? store.editIncident(incidentId, fields) : store.addIncident(fields);
      selectedId = edit ? incidentId : next.incidents.at(-1).id; $('search').value = ''; $('filter').value = 'all'; toast(edit ? 'Incident updated; review required.' : 'Incident added.');
    }, edit ? 'Save changes' : 'Add incident');
}
$('addIncidentButton').addEventListener('click', () => incidentForm()); $('editIncidentButton').addEventListener('click', () => incidentForm(true));
$('addEvidenceButton').addEventListener('click', () => {
  const incidentId = selectedId;
  openForm('Add evidence', 'Files stay on this device. Save an optional original copy so you can download it later. JSON bundles contain fingerprints, not files; keep separate backups. Maximum 20 MB per file.',
    select('type', 'Evidence type', ['field-note', 'photo-note', 'document-note', 'witness-note'].map((item) => [item, item.replace('-', ' ')]), 'field-note') + area('description', 'Evidence description', '', 'required') + '<label>Evidence file (optional)<input name="attachment" type="file"></label><label class="check"><input name="keepOriginal" type="checkbox" checked>Keep an original copy on this device</label>',
    async (data) => {
      const file = data.get('attachment');
      const fields = { type: value(data, 'type'), description: value(data, 'description') };
      if (file?.name) {
        fields.attachment = await fingerprintFile(file);
        if (data.has('keepOriginal')) await originals.put(file, fields.attachment);
      }
      store.addEvidence(incidentId, fields); toast('Evidence saved; incident needs review.');
    }, 'Save evidence');
});
$('evidenceList').addEventListener('click', (event) => {
  const downloadButton = event.target.closest('[data-download-original]');
  const connectButton = event.target.closest('[data-connect-original]');
  if (!downloadButton && !connectButton) return;
  const evidenceId = downloadButton?.dataset.downloadOriginal || connectButton.dataset.connectOriginal;
  const attachment = selected()?.evidence.find((item) => item.id === evidenceId)?.attachment;
  if (!attachment) return;
  if (downloadButton) {
    safeAction(async () => {
      downloadButton.disabled = true;
      try { download(attachment.name, await originals.get(attachment), 'application/octet-stream'); toast('Original fingerprint checked and file downloaded. Keep it alongside your JSON backup.'); }
      finally { if (downloadButton.isConnected) downloadButton.disabled = false; }
    })();
  } else {
    openForm('Reconnect an original', `Choose the original for ${attachment.name}. Its bytes must match the recorded size and SHA-256. This saves a local copy without changing the evidence record.`,
      '<label>Original file<input name="original" type="file" required></label>',
      async (data) => { await originals.put(data.get('original'), attachment); toast('Matching original saved on this device.'); }, 'Save matching original');
  }
});
$('reviewButton').addEventListener('click', () => {
  const incidentId = selectedId;
  openForm('Record human review', 'Your name is a self-declared review record, not authenticated identity. Reviewing does not resolve the incident.',
    input('reviewer', 'Reviewed by', '', 'required maxlength="200"') + area('note', 'Review note', '', 'required'),
    (data) => { store.reviewIncident(incidentId, value(data, 'reviewer'), value(data, 'note')); toast('Review recorded. Incident status is unchanged.'); }, 'Record review');
});
$('resolveButton').addEventListener('click', () => {
  const incidentId = selectedId;
  openForm('Resolve incident', 'Record what was done. Evidence and the review record remain available in the export.', area('note', 'Resolution note', '', 'required'),
    (data) => { store.resolveIncident(incidentId, value(data, 'note')); toast('Incident resolved.'); }, 'Resolve incident');
});
$('reopenButton').addEventListener('click', safeAction(() => { store.reopenIncident(selectedId); render(); toast('Incident reopened for review.'); }));
$('incidentList').addEventListener('click', (event) => {
  const button = event.target.closest('[data-incident]'); if (!button) return;
  selectedId = button.dataset.incident; renderDetail(store.get());
  for (const item of $('incidentList').querySelectorAll('[data-incident]')) item.setAttribute('aria-pressed', String(item.dataset.incident === selectedId));
  $('detailTitle').focus();
});
$('search').addEventListener('input', () => renderList(store.get())); $('filter').addEventListener('change', () => renderList(store.get()));
$('runButton').addEventListener('click', () => { render(); toast('Rule-based review updated from the current record.'); });
async function currentBundle() {
  if (store.status().blocked) throw new Error('Recover your stored data before exporting a record.');
  const site = store.snapshot(), snapshot = JSON.stringify(site);
  const bundle = await createFieldBundle(site);
  if (snapshot !== JSON.stringify(store.snapshot())) throw new Error('Record changed during export. Export again.');
  await verifyFieldBundle(bundle);
  return bundle;
}
$('bundleButton').addEventListener('click', safeAction(async () => { download('watch-dawg-field-bundle.json', pretty(await currentBundle())); toast('Bundle exported. Keep original files separately.'); }));
$('reportButton').addEventListener('click', safeAction(() => { download('watch-dawg-field-report.txt', fieldReport(store.snapshot()), 'text/plain'); toast('Readable report exported.'); }));
$('receiptButton').addEventListener('click', safeAction(async () => { const bundle = await currentBundle(); $('receipt').textContent = `${bundle.limitations}\n\n${pretty(bundle.receipt)}`; $('receipt').hidden = false; toast('Unsigned integrity receipt created for the current record.'); }));
$('rawBackupButton').addEventListener('click', safeAction(() => download('watch-dawg-recovery.txt', store.raw(), 'text/plain')));
$('importButton').addEventListener('click', () => openForm('Import or check a backup', 'Checks a Watch-Dawg bundle without replacing your record. Legacy site JSON can be restored but has no receipt. Maximum 16 MB.',
  '<label>Backup JSON file<input name="backup" type="file" accept=".json,application/json" required></label><label class="check"><input name="restore" type="checkbox">Restore this backup after checking it (asks before replacing)</label>',
  async (data) => {
    const file = data.get('backup');
    if (!file?.name || file.size > 16 * 1024 * 1024) throw new Error('Choose a JSON backup of 16 MB or less.');
    const parsed = JSON.parse(await file.text());
    const isBundle = parsed?.format !== undefined;
    const site = isBundle ? (await verifyFieldBundle(parsed)).site : validateSite(parsed);
    const message = isBundle ? 'Bundle integrity checked. It is unsigned; authorship and truth are not verified.' : 'Legacy site structure checked. No integrity receipt is present.';
    toast(message);
    if (data.has('restore')) {
      $('formDialog').close();
      confirmReplace(`Restore ${site.siteName}?`, `${message} This will replace the current site with ${site.incidents.length} incident(s) and ${site.zones.length} zone(s). Export the current record first if needed.`, site);
    }
  }, 'Check backup'));
window.addEventListener('storage', (event) => { if (event.key === 'watch-dawg-field-security-site-v1' || event.key === null) showError(new Error('The saved record changed in another tab. Reload before editing or exporting.')); });
render();
