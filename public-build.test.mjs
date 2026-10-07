import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, readdir, writeFile, rm, access, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename, dirname } from 'node:path';
import { buildPublic } from './scripts/build-public.mjs';

async function removeTestOutput(output) {
  const path = await realpath(output);
  assert.equal(dirname(path), await realpath(tmpdir()));
  assert.ok(basename(path).startsWith('watch-dawg-public-'));
  await rm(path, { recursive: true, force: true });
}

async function inventory(root, prefix = '') {
  const files = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = `${prefix}${entry.name}`;
    if (entry.isDirectory()) files.push(...await inventory(root, `${path}/`));
    else files.push(path);
  }
  return files.sort();
}

test('public artifact includes both apps and all field dependencies without repository data', async (t) => {
  const output = await mkdtemp(join(tmpdir(), 'watch-dawg-public-'));
  t.after(() => removeTestOutput(output));
  await buildPublic(output);
  assert.deepEqual(await inventory(output), [
    '.nojekyll', 'index.html', 'watchdawg.js',
    'assets/brand/watchdawg-bobsome1.png', 'assets/css/watchdawg-attribution.css',
    'field/index.html', 'field/field-security.css', 'field/field-security.js',
    'field/field-security-app.js', 'field/field-security-store.js', 'field/field-security-export.js', 'field/field-security-files.js',
  ].sort());
  const rootPage = await readFile(join(output, 'index.html'), 'utf8');
  const fieldPage = await readFile(join(output, 'field/index.html'), 'utf8');
  assert.match(rootPage, /href="\.\/field\/"/);
  assert.match(rootPage, /id="demo"/); // Keep the existing anomaly demo available.
  assert.match(fieldPage, /href="\.\/" class="brand"/);
  assert.match(fieldPage, /http-equiv="Content-Security-Policy"/);
  assert.match(fieldPage, /connect-src 'none'/);
  for (const match of fieldPage.matchAll(/(?:src|href)="\.\/([^"#]+)"/g)) await access(join(output, 'field', match[1]));
  for (const name of ['field-security-app.js', 'field-security-store.js', 'field-security-export.js', 'field-security-files.js']) {
    const code = await readFile(join(output, 'field', name), 'utf8');
    for (const match of code.matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)) await access(join(output, 'field', match[1]));
  }
  await assert.rejects(access(join(output, 'backend')));
  await assert.rejects(access(join(output, '.git')));
  await assert.rejects(access(join(output, 'docs')));
  await buildPublic(output); // Rebuilding the same public-only output is safe.
});

test('build refuses unexpected leftover files and preserves them for inspection', async (t) => {
  const output = await mkdtemp(join(tmpdir(), 'watch-dawg-public-'));
  t.after(() => removeTestOutput(output));
  await writeFile(join(output, 'private-note.txt'), 'Synthetic private fixture');
  await assert.rejects(buildPublic(output), /Unexpected public output file/);
  assert.equal(await readFile(join(output, 'private-note.txt'), 'utf8'), 'Synthetic private fixture');
});
