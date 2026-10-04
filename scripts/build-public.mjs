import { copyFile, mkdir, readdir, lstat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
export const PUBLIC_FILES = Object.freeze({
  'index.html': 'public-demo.html',
  'watchdawg.js': 'watchdawg.js',
  'assets/brand/watchdawg-bobsome1.png': 'assets/brand/watchdawg-bobsome1.png',
  'assets/css/watchdawg-attribution.css': 'assets/css/watchdawg-attribution.css',
  'field/index.html': 'field-security-demo.html',
  'field/field-security.css': 'field-security.css',
  'field/field-security.js': 'field-security.js',
  'field/field-security-app.js': 'field-security-app.js',
  'field/field-security-store.js': 'field-security-store.js',
  'field/field-security-export.js': 'field-security-export.js',
});

// Refuse unexpected build content rather than shipping stale files or deleting them.
async function inspectOutput(output, prefix = '') {
  for (const entry of await readdir(join(output, prefix), { withFileTypes: true })) {
    const name = `${prefix}${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`Refusing symbolic link in public output: ${name}`);
    if (entry.isDirectory()) {
      if (!Object.keys(PUBLIC_FILES).some((path) => path.startsWith(`${name}/`))) throw new Error(`Unexpected public output directory: ${name}`);
      await inspectOutput(output, `${name}/`);
    } else if (!Object.hasOwn(PUBLIC_FILES, name) && name !== '.nojekyll') throw new Error(`Unexpected public output file: ${name}`);
  }
}

export async function buildPublic(output = join(root, 'build/public')) {
  const destination = resolve(output);
  await mkdir(destination, { recursive: true });
  if ((await lstat(destination)).isSymbolicLink()) throw new Error('Public output must not be a symbolic link.');
  await inspectOutput(destination);
  for (const [name, source] of Object.entries(PUBLIC_FILES)) {
    const target = join(destination, name);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(join(root, source), target);
  }
  await writeFile(join(destination, '.nojekyll'), '');
  return destination;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log(`Public demo and field desk built at ${await buildPublic()}`);
}
