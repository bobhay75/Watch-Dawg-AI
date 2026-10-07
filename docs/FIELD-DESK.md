# Watch-Dawg field desk

## Run

Use Node.js 22 or later. No npm packages need to be installed.

```sh
npm run field:preview
```

Open `http://127.0.0.1:4173`. Keep this origin/port consistent to see the same
browser storage. The preview binds only to `127.0.0.1`, serves an explicit asset
allowlist, uses a restrictive CSP, and returns real 404s for unknown paths.
It does not proxy APIs or serve repository files outside that allowlist.

The public GitHub Pages build serves this same browser-local app at `field/`,
linked from the existing demo homepage. `npm run build:public` creates the
explicitly allowlisted artifact under `build/public`; the Pages workflow runs
the full Node test suite before building or uploading it. Source/backend files,
local records, and original evidence files are not part of the published artifact.
The field page also declares a content security policy that blocks network
requests from its scripts. The host still receives normal page/asset requests.

Browser storage is per origin, not per path or device account. The hosted app
cannot automatically see records saved on localhost: export there and import
the bundle in the hosted app to transfer a record. Anyone with access to the
same browser profile, and scripts on the same origin, may access that browser's
stored record. Use an appropriate private device/profile and keep exported
backups under your control.

## Workflow

1. Try the clearly labeled fictional sample, or select **New site**. Replacement
   requires confirmation; export the old record first.
2. Save the site name, owner contact, and authority declaration in **Site details**.
3. Add a zone with its boundary, expected hours, and coverage status.
4. Report an incident with a title, severity, time, observer, and notes.
5. Select it to add evidence notes. Optionally select a local file up to 20 MB;
   the app hashes its exact bytes and records its name, size, media type, and
   SHA-256. Leave **Keep an original copy on this device** checked to retain
   the file locally, or uncheck it to save only its fingerprint. No file uploads.
6. Record a named human review and note. This never automatically resolves it.
7. Resolve explicitly with a resolution note. The app requires authority, a
   recorded review, and at least one evidence note. Resolution is not a finding
   about legal responsibility or the truth of submitted statements.
8. Export a readable report or a JSON record bundle. Download each original
   from its incident separately and keep the files alongside the JSON. Use **Import / check
   bundle** to check integrity without changing the active site, or choose to
   restore it and confirm replacement.

Editing details or adding evidence invalidates the current review and reopens
the incident. Previous incident values remain in local history; the current
app offers no editing of existing evidence notes. Correct an observation with
a new evidence note. The history is application-maintained and locally
editable outside the app; it is not an immutable audit log.

## Storage and recovery

The store keeps `watch-dawg-field-security-site-v1` for compatibility. Valid
legacy records receive an empty history array in memory. A legacy reviewed
entry does not acquire a fabricated reviewer or timestamp. Add a review before
resolving it in the updated app.

Validation occurs before saving. If a write fails, the dialog retains its input
and the last valid state remains unchanged. A tab detects intervening storage
changes before a write. This is conflict detection, not an atomic cross-tab
transaction; avoid editing the same record in multiple tabs at once.

Malformed stored data is never silently replaced. A recovery download preserves
the original value; start a new site or restore a validated backup explicitly.
Browser storage can be removed by browser settings, private-session closure,
eviction, or another same-origin application. Export backups regularly.

Bounds: 4 MB site JSON; 200 zones; 1,000 incidents; 200 evidence notes per
incident; 2,000 local history entries; 20 MB per selected original file; 16 MB
import file. Hitting a bound refuses the save instead of truncating history.

## Original files

Optional originals use IndexedDB (`watch-dawg-originals-v1`, store `files`),
keyed by SHA-256. Availability is checked on the current device; importing a
JSON bundle alone never claims that its originals are present. **Download
original** verifies the size and fingerprint again before downloading the exact
bytes. **Reconnect original** checks an externally saved file against the
record before retaining it. Reconnecting matching bytes does not change the
incident, its review, or its history.

File writes commit before incident metadata is saved. If metadata saving fails,
a successfully stored original may remain unreferenced; retrying with the same
file reuses its fingerprint. Changing sites or restoring a bundle does not
remove earlier originals. To recover them, restore the corresponding record
bundle. There is no automatic cleanup or application deletion control in this
release; clearing this site's browser storage removes both records and files.
Back up all records and download all needed originals before doing so. Browser
quotas apply; failed original saves leave the incident unchanged and offer a
fingerprint-only alternative. Stored originals are not encrypted by this app.

## Integrity boundary

`field-security-export.js` derives the audit and readable report from a copied,
validated site record. The receipt binds the site and deterministic audit by
SHA-256. Verification recalculates the audit, report, and receipt and compares
the complete expected bundle, including its limitations. It accepts object key
reordering but refuses changed evidence, history, results, or report text.

```sh
node scripts/verify-field-bundle.mjs exported-bundle.json
```

Exit 0 prints `INTEGRITY_CHECKED`; malformed or altered bundles exit 1. This
is unsigned integrity, not signed provenance: someone able to rewrite the
record and recompute every digest can create another internally consistent
bundle. Reviewer identity and timestamps are user/device supplied. Original
file bytes are not in the bundle and are not checked by the bundle verifier.
The current rules version is required to reproduce the derived audit; no
cross-version compatibility guarantee is made.

## Architecture and checks

- `field-security.js`: deterministic rules and legacy receipt interface.
- `field-security-store.js`: validation, local persistence, and state transitions.
- `field-security-export.js`: file fingerprints, readable reports, and bundle verification.
- `field-security-files.js`: local original storage and byte verification.
- `field-security-app.js`: DOM interaction and accessible native dialogs.
- `field-security.css`: responsive styles with reduced-motion handling.

```sh
npm test
npm run build:public
node --check field-security-app.js
python scripts/verify_supply_chain.py
```

The behavior tests cover review/resolution separation, history preservation,
edit invalidation, invalid schemas, storage quota/permission failures, corrupt
storage, stale tabs, exact-byte fingerprints, backup round trips, changed bundle
rejection, and the preview server's MIME/path/method boundary.

Browser acceptance: new site → zone → incident → evidence → review → resolve →
edit/reopen; reload persistence; search/filter; receipt invalidation; backup
check and restore; keyboard dialog close/focus return; narrow viewport layout.

## Next production boundary

Authenticated accounts, server-side authorization, durable private file storage,
trusted signing keys, external timestamps, backup/retention policy, and
multi-user concurrency belong in a separate reviewed backend implementation.
The public static app delivers a browser-local workflow without enabling those
backend services. The existing Emergent deployment is separate and unchanged.
