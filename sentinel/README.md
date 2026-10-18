# DAWG Sentinel — offline evidence triage

The JavaScript classifier (`sentinel.mjs`) is **review-only**. It reads supplied
records, performs deterministic policy checks, and returns a review candidate.
It does not fetch documents, resolve DNS, follow redirects, send notifications,
make autonomous decisions, or deploy. Existing Python monitoring/API modules are
separate; this change does not connect the classifier to them.

`alert: true` retains the v1 API name but means **eligible for human review only**.
Every result sets `reviewRequired: true` and `reviewOnly: true`. Thresholds are
policy choices, not calibrated probabilities or disaster predictions.

## Trust boundary and defaults

`source-registry.json` is the reviewable source-policy file. It deliberately ships
with **no approved real sources**. No evidence reviews are loaded automatically.
Unregistered sources, caller assertions such as `credible: true` or
`independent: true`, and registry/review objects embedded in a signal grant no trust.

```js
import {assessSignal, evaluateBatch} from './sentinel.mjs';
const result = assessSignal(signal, evaluationDate, {
  registry: reviewedRegistry,
  evidenceReviews: reviewedClaimRecords
});
const results = evaluateBatch(signals, evaluationDate, {
  registry: reviewedRegistry,
  evidenceReviews: reviewedClaimRecords
});
```

The third argument is **trusted curator configuration**, not an untrusted request
body. A caller who can supply or alter it can fabricate approvals. This library
has no authentication, signatures, role enforcement, or reviewer identity service.
Any future service must load protected, version-controlled policy and reviews
itself, and must never map user/AI-submitted data into that argument. An LLM must
not approve source credibility, ownership, editorial independence, origin IDs,
claim support, or timestamps. Supplying a reviewer string is not authentication.

## Source registry v1

Top-level shape: `{ "version": 1, "sources": [...] }`.
Each source entry requires:

| Field | Human-reviewed meaning |
| --- | --- |
| `id` | Unique stable source identity; aliases share this ID |
| `hosts` | Explicit lowercase ASCII HTTPS hostnames, with no wildcard/subdomain inheritance |
| `ownerId` | Common ultimate controlling organization; use the same ID across subsidiaries |
| `editorialGroupId` | Shared editorial control, even across different owners |
| `status` | `approved`, `pending`, or `revoked`; only approved entries can count |
| `reviewer`, `reviewNote` | Responsible curator and reasoning, including scope and uncertainty |
| `reviewReferences` | Nonempty list of records supporting identity/ownership/editorial findings |
| `reviewedAt`, `expiresAt` | Review validity interval; review must already have occurred and not expired |

Stable source, owner, editorial-group, review, origin and document IDs use
lowercase ASCII alphanumeric segments separated by `-`, `_`, `.`, or `:` (at most
128 characters). Whitespace and uppercase variants are rejected rather than
silently splitting a common identity. Reviewer names and notes remain free text.
Humans must still resolve genuinely different aliases for the same organization.

Duplicate identities, overlapping host assignments, malformed records or missing
ownership/editorial metadata cause a configuration error. Pending, revoked,
future-reviewed or expired entries do not qualify. Unknown independence must
remain pending; do not invent separate IDs to make counts pass. Host identities
are policy records, not a DNS, TLS, ownership, or authenticity check.

## Signal and claim-review records

A signal requires `id`, supported `category`, nonempty `headline`, UTC `observedAt`,
`indicators` (each integer `impact` 0–4), and `sources`. `observedAt` means the
**event time**, not when someone noticed an old article. Each source supplies
`url` and a lowercase 64-character `contentSha256` for preserved document bytes.

Each trusted evidence review requires:

| Field | Binding or assessment |
| --- | --- |
| `status` | Must be exactly `approved`; pending, missing or revoked status cannot grant trust |
| `id`, `reviewer`, `reviewNote` | Audit reference, responsible human and claim-support rationale |
| `url`, `contentSha256`, `sourceId` | Canonical URL, document digest and registered source identity |
| `claimId`, `category`, `headline`, `eventAt` | Exact reviewed signal; edits invalidate reuse |
| `support` | Must be `direct`; mentions, inference or contradictions cannot corroborate |
| `maxImpact` | Integer 0–4; highest impact supported by this review |
| `originId` | Original reporting/evidence chain; copies of one release share this ID |
| `documentId` | Stable document identity across mirrors, translations or revised byte encodings |
| `publishedAt`, `retrievedAt`, `verifiedAt`, `expiresAt` | Reviewed publication, capture, verification and expiry instants |

Claim reviews require an explicit `status: "approved"` in trusted curator
configuration. Legacy records with no status now fail closed. Filling in a
pending draft's other fields does not approve it; the draft's own status remains
`pending`. A status field is a policy declaration, not authenticated proof that a
human approved anything. Protect the ledger from untrusted writers.

A deny-only entry such as `{ "id": "review-beta", "status": "revoked" }` blocks
that stable review ID across all claims, documents, copies and evaluation clocks.
An older approved copy cannot override it by changing URL/hash/claim metadata or
by replaying a time before revocation. Any `revokedAt` field on a claim review or
source entry also blocks trust, even if another field says `approved` or the
marker is missing a valid timestamp. This deliberately fails closed on
contradictory records. Real revocation records should preserve the responsible
human, reason and timestamp in the protected ledger; incomplete deny records
still deny rather than accidentally approve.

Keep revocation tombstones when preparing a current review snapshot. This is
not an append-only event-history engine: duplicate full matching records remain
ambiguous and blocked. Reactivation requires a separately reviewed current
snapshot; merely appending a new approved record is not an undo operation.
Historical replay uses the supplied current revocation policy and cannot recover
an earlier state of trust. Different policy snapshots must be tracked separately.

The classifier matches exactly one review per canonical URL, digest and claim.
Absent or ambiguous matches cannot count. It checks the claim/category/headline,
event time and impact ceiling, not just whether the source is generally trusted.
The human curator must independently verify the document bytes and compute their
SHA-256 before recording the review. The classifier only compares supplied hashes;
it does not possess the document, compute its digest or authenticate its contents.
`documentId` and `originId` must be preserved across duplicates and syndication.

All timestamps require a real UTC ISO instant (`YYYY-MM-DDTHH:mm:ss[.sss]Z`).
Impossible dates, date-only values, missing timezones and implicit coercion fail.
Publication and event time must not exceed retrieval; retrieval must not exceed
verification; verification must not be in the future; expiry must be later than
verification and evaluation must precede expiry. Both event time and publication
must be within 72 hours of evaluation (inclusive). New retrieval/verification
cannot rejuvenate an old event or old publication. The evaluator's clock is
trusted; callers must not backdate it to bypass freshness or revocation.

## Corroboration and duplicates

HTTPS URLs are parsed rather than checked with a prefix. Credentials, malformed
escapes, whitespace/control characters, backslashes, encoded authority, nondefault
ports, IP literals, trailing dots, local hostnames and internationalized hostnames
are rejected conservatively. Punycode/IDN approval needs a separately reviewed
policy before support is added. No suffix or substring host matching is used.

Canonicalization removes fragments and known tracking parameters (`utm_*`,
`fbclid`, `gclid`), sorts query keys, and normalizes the HTTPS default port and
hostname case. Content query parameters remain significant. Redirects and
unrecognized tracking parameters are not resolved; humans must connect aliases
using document/origin records.

Corroboration requires at least two disconnected evidence groups. Shared source,
owner, editorial group, original reporting chain, document, review ID, canonical
URL or content digest joins evidence into one group, **transitively**. Duplicate
records retain their dependence links internally so removing a duplicate cannot
manufacture independence. Canonical URL and byte duplicates are omitted from the
returned `sources` and recorded as `DUPLICATE_EVIDENCE`.

`sourceCount` and `independentSourceCount` count groups, not domains or articles.
`rejectedEvidence` records each rejected input index and reason; accepted records
include source, owner, editorial group, origin, document, digest and review IDs.
Fresh evidence yields `UNVERIFIED`, `SINGLE_SOURCE` or `CORROBORATED`; stale/future
events yield `STALE`. Reviewed impact >=3 plus fresh corroboration sets eligibility.
An unreviewed indicator can still produce a high **submitted severity** level,
but cannot qualify for corroboration/eligibility without reviews supporting it.

Batch evaluation collapses byte-identical serialized signals with the same ID.
Conflicting reuse of an ID throws rather than silently replacing a claim.
Different IDs referring to the same real event are not automatically reconciled;
that remains a human review task before any future downstream action.

## Offline document preparation

Use a preserved local document, not a live URL fetch:

```sh
npm run --silent sentinel:prepare -- --file /path/to/preserved-report.html --url https://source.example.org/report
```

To check a previously reviewed SHA-256, add
`--expected-sha256` followed by its 64-character lowercase digest. A mismatch
returns a nonzero exit code and no JSON. Successful output goes to stdout; no
file, registry or approved review is written. Redirect stdout to your chosen
private review location if needed. The tool never executes or renders the file.

The output contains a canonical URL and SHA-256 source record, plus a
`reviewDraft` with `status: "pending"`, `support: "unreviewed"` and unresolved human-assessment fields.
Its top-level `status` is `pending`. It cannot qualify as reviewed evidence.
`preparedAt` records preparation time only: event, publication, retrieval,
verification and expiry times remain unset. The submitted URL is retained
separately for comparison with canonicalization.

The CLI reads exact binary bytes, at most 16 MiB, from a regular file. It rejects
final-component symlinks, directories, devices and named pipes, and detects
size/metadata changes during reading. It requires Linux/macOS-style safe file
flags. Intermediate directory symlinks are not a sandbox boundary; run it only
on paths you are authorized to read. A stable hash does not establish the file's
origin, completeness, truth or publication time. Private evidence contents must
not be committed to a public repository.

For offline JavaScript use, `prepareEvidence(bytes, url, evaluationDate)` prepares
the pending record; `verifyDocument(bytes, expectedDigest)` checks exact supplied
bytes. Both accept `Uint8Array`/`Buffer`, preserving typed-array slice boundaries.

Collection limits reject oversized evaluations: 256 source records and 256
indicators per signal, 256 signals per batch, 1,024 registered sources (up to 16
hosts each), and 4,096 claim reviews. These are count limits, not a replacement
for request-byte limits and authenticated policy loading in a future service.

## Offline dossier runner and synthetic demo

Requires Node 22 or newer; these commands use Node built-ins and need no package
installation. From the repository root:

```sh
npm run --silent sentinel:demo
```

This runs the synthetic `fixtures/offline-demo.json` at its explicit historical
evaluation time. Two preserved `.txt` documents are hashed and compared against
the manifest before the runner returns its JSON report. The fixture's approved
sources and claim reviews are **stipulated test data**, not real approvals. The
normal `source-registry.json` remains empty. The demo does not load that test
registry into any live service or alter configuration.

To review your own protected dossier:

```sh
npm run --silent sentinel:review -- --dossier /path/to/private-dossier.json
```

The dossier is a trusted curator-controlled JSON file with `version: 1`,
`mode: "review-only"`, `registry`, `evidenceReviews`, `signals`, and `documents`.
Use the synthetic dossier as a shape example only. Each document entry contains
`path`, `url`, and `contentSha256`; `path` is a simple filename alongside the
dossier. Absolute paths, directory components, traversal, trailing whitespace,
ambiguous manifest identities and final-component symlinks are rejected. The
CLI reads regular local files only. Each file, including dossier JSON, is
limited to 16 MiB; captures total at most 64 MiB, across at most 256 documents.

Every signal source must map to a preserved document by canonical URL and exact
SHA-256. All manifest files are rehashed at assessment time, including entries
not referenced by a signal. Missing or mismatched captures abort the entire run
with a nonzero exit code and **no partial JSON report**. Documents are not rendered
or executed, fetched from URLs, or included verbatim in output. Successful JSON
goes to stdout; the runner writes no files and changes no registry or review.

The report includes `documentChecks` with `hashVerified: true`, evaluation time,
per-signal rejection reasons, and mandatory review-only fields. Hash verification
means exact-byte agreement only; it does not establish authenticity or truth.
The `synthetic` flag reflects the dossier's declaration, not an authenticity test.
Local policy files and the filesystem must be protected from unauthorized edits;
this CLI is not a hostile-filesystem sandbox or an authenticated review service.

The default uses the current clock (`clockMode: "current-clock"`). To reproduce a
past assessment, add `--at` followed by a strict UTC ISO time. Reports then carry
`clockMode: "explicit-historical-replay"`; their eligibility findings must never
be presented as current warnings. Even a historical `alert: true` remains a
human-review candidate and performs no action.

## Deterministic validation and limitations

Run from the repository root:

```sh
node --test sentinel/sentinel.test.mjs sentinel/prepare-evidence.test.mjs sentinel/review-dossier.test.mjs
npm test
python -m unittest discover -s sentinel/tests -v
```

`fixtures/evidence-review.json` contains **synthetic test organizations and
stipulated reviews only**; it is never loaded by the classifier by default. It
is a schema example, not authorization to approve a real source. The JavaScript
suite is now included in `npm test` and the Sentinel validation workflow, closing
the previous gap where green workflows did not execute the classifier tests.

Human verification remains essential for true ownership/control, editorial
independence, syndication/common sourcing, document authenticity, claim support,
actual event/publication times and impact. A complete-looking forged registry or
review can still pass structural checks if a trusted caller admits it. Counts can
also overstate independence when a reviewer fails to identify a common source.
The conservative policy can undercount independent desks under one owner and
excludes older background context from fresh corroboration. This is intentional.

Live feeds, persistent history, authenticated review administration, geographic
relevance, cross-event correlation and delivery remain unimplemented in this
classifier. Require separate owner approval before activating any live integration,
notification, autonomous decision or production deployment. Do not auto-merge.
