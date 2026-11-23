import { hashOwnerPassword } from './owner-session.mjs';

// Input comes from a hidden terminal prompt/pipe, never an argv or environment password.
if (process.argv.length !== 2 || process.stdin.isTTY) {
  console.error('Pipe a password from a hidden prompt into this command; no arguments are accepted.');
  process.exitCode = 1;
} else {
  let value = '';
  try {
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) {
      value += chunk.toString('utf8');
      if (Buffer.byteLength(value) > 1025) throw new Error('Password input exceeds the limit');
    }
    value = value.replace(/\r?\n$/, '');
    console.log(await hashOwnerPassword(value));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    value = '';
  }
}
