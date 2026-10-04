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

## Workflow

1. Try the clearly labeled fictional sample, or select **New site**. Replacement
   requires confirmation; export the old record first.
2. Save the site name, owner contact, and authority declaration in **Site details**.
3. Add a zone with its boundary, expected hours, and coverage status.
4. Report an incident with a title, severity, time, observer, and notes.
5. Select it to add evidence notes. Optionally select a local file up to 20 MB;
   the app hashes its exact bytes and stores only its name, size, media type, and
   SHA-256. No file is uploaded or retained. Keep the original separately.
6. Record a named human review and note. This never automatically resolves it.
7. Resolve explicitly with a resolution note. The app requires authority, a
   recorded review, and at least one evidence note. Resolution is not a finding
   about legal responsibility or the truth of submitted statements.
8. Export a readable report or a complete JSON bundle. Use **Import / check
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
- `field-security-app.js`: DOM interaction and accessible native dialogs.
- `field-security.css`: responsive styles with reduced-motion handling.

```sh
npm test
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
This slice deliberately delivers a local field workflow without enabling those
services or changing either production deployment.
