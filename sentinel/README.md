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
| `id`, `reviewer`, `reviewNote` | Audit reference, responsible human and claim-support rationale |
| `url`, `contentSha256`, `sourceId` | Canonical URL, document digest and registered source identity |
| `claimId`, `category`, `headline`, `eventAt` | Exact reviewed signal; edits invalidate reuse |
| `support` | Must be `direct`; mentions, inference or contradictions cannot corroborate |
| `maxImpact` | Integer 0–4; highest impact supported by this review |
| `originId` | Original reporting/evidence chain; copies of one release share this ID |
| `documentId` | Stable document identity across mirrors, translations or revised byte encodings |
| `publishedAt`, `retrievedAt`, `verifiedAt`, `expiresAt` | Reviewed publication, capture, verification and expiry instants |

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

## Deterministic validation and limitations

Run from the repository root:

```sh
node --test sentinel/sentinel.test.mjs
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
