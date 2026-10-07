import { fingerprintFile } from './field-security-export.js';

// Records keep fingerprints only. Originals live separately, keyed by their bytes.
export async function verifyOriginal(blob, attachment) {
  if (!(blob instanceof Blob)) throw new Error('The original is unavailable on this device. Reconnect it from your backup.');
  if (blob.size !== attachment.size) throw new Error('This file does not match the recorded size.');
  const actual = await fingerprintFile(blob);
  if (actual.sha256 !== attachment.sha256) throw new Error('This file does not match the recorded SHA-256 fingerprint.');
  return blob;
}

export function createOriginalStore(getDatabase = () => indexedDB) {
  async function open() {
    return new Promise((resolve, reject) => {
      let request;
      try { request = getDatabase().open('watch-dawg-originals-v1', 1); }
      catch { reject(new Error('Original-file storage is unavailable. Uncheck the on-device copy option to save only a fingerprint.')); return; }
      let failed = false;
      request.onupgradeneeded = () => request.result.createObjectStore('files');
      request.onblocked = () => { failed = true; reject(new Error('Close other field-desk tabs and try saving the original again.')); };
      request.onerror = () => reject(new Error('Original-file storage could not open. Check browser storage permissions.'));
      request.onsuccess = () => {
        if (failed) { request.result.close(); return; }
        request.result.onversionchange = () => request.result.close();
        resolve(request.result);
      };
    });
  }
  async function operation(mode, action) {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction('files', mode);
        const request = action(transaction.objectStore('files'));
        transaction.oncomplete = () => resolve(request.result);
        transaction.onabort = () => reject(new Error('Original-file storage failed. Your incident record was not changed. Free browser storage or save only a fingerprint.'));
        transaction.onerror = () => {}; // The abort event reports the final transaction outcome.
      });
    } finally { db.close(); }
  }
  return {
    async put(blob, attachment) {
      await verifyOriginal(blob, attachment);
      // Only resolve after the write transaction commits, before recording its metadata.
      await operation('readwrite', (files) => files.put(blob, attachment.sha256));
    },
    async has(attachment) { return (await operation('readonly', (files) => files.getKey(attachment.sha256))) !== undefined; },
    async get(attachment) {
      return verifyOriginal(await operation('readonly', (files) => files.get(attachment.sha256)), attachment);
    },
  };
}
