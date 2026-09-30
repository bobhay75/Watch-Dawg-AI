import assert from 'node:assert/strict';
import fs from 'node:fs';

const demo = fs.readFileSync(new URL('./field-security-demo.html', import.meta.url), 'utf8');

for (const phrase of [
  'Open boundaries. Secured peace.',
  'Run Field Audit',
  'Create Evidence Receipt',
  'No live scan',
  'Create Site',
  'Create Zone',
  'Report Incident',
  'Add Evidence Item',
  'Mark Selected Human Reviewed',
  'Export Report',
  'Clear Local Data',
]) {
  assert.match(demo, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `missing UI phrase: ${phrase}`);
}

assert.match(demo, /from\s+["']\.\/field-security\.js["']/, 'field security demo must use the deterministic field-security core');
assert.match(demo, /const STORAGE_KEY = 'watch-dawg-field-security-site-v1'/, 'demo must declare the local storage key');
assert.match(demo, /localStorage\.setItem\(STORAGE_KEY/, 'demo must persist site records locally');
assert.match(demo, /localStorage\.removeItem\(STORAGE_KEY\)/, 'demo must allow local reset');
assert.match(demo, /URL\.createObjectURL\(new Blob/, 'demo must support report export');
assert.match(demo, /incident\.reviewStatus = 'human-reviewed'/, 'demo must support human review completion');
assert.match(demo, /incident\.evidence\.push/, 'demo must support evidence creation');
assert.match(demo, /currentSite\.zones\.push/, 'demo must support zone creation');
assert.match(demo, /currentSite\.incidents\.push/, 'demo must support incident creation');
assert.match(demo, /auditFieldSecuritySite\(currentSite\)/, 'demo must run the deterministic field audit on local records');

console.log('Watch-Dawg field-security app workflow tests passed');
