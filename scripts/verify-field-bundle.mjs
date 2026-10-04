import { readFile } from 'node:fs/promises';
import { verifyFieldBundle } from '../field-security-export.js';

try {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/verify-field-bundle.mjs <bundle.json>');
  const result = await verifyFieldBundle(JSON.parse(await readFile(process.argv[2], 'utf8')));
  console.log(`${result.status}: ${result.receiptDigest}`);
  console.log('Unsigned integrity only. Does not authenticate the author or establish truth. Original files are not included.');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
