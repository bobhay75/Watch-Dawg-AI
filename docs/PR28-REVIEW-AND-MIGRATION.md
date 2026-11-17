# PR #28 follow-up review and migration gates

## Review and mergeability

Reviewed PR #28 against `feature/intelligence-brief-plan-2026-11-15` at `2e0b45f1cac4c7364547d04827b4e1160a5156a0`. The original audit head was `ab82b5ce216d7c54b5fd37896c453a6cde8fa900`. GitHub reported the draft PR mergeable, and local `merge-base --is-ancestor` plus `merge-tree --write-tree` confirmed no conflicts. No reconciliation commit was necessary. Follow-up changes stay on the audit branch; neither base branch was changed. Mergeability is a point-in-time result, not integration approval.

## Existing evidence permission migration

Stop collectors, report generators, readers and other writers first. Use a dedicated, owned evidence subtree on POSIX/Linux. Review a local backup and filesystem/ACL policy before application. The utility is standard-library-only, never reads evidence contents, prints counts rather than private names, and contains no network operations, deletion, renaming, upload, chown or content-writing logic.

```sh
python scripts/migrate_evidence_permissions.py --root local-data
# Inspect the dry-run counts locally, then explicitly apply when ready:
python scripts/migrate_evidence_permissions.py --root local-data --apply
```

The utility opens the root and every ancestor without following symlinks, then preflights the complete subtree through retained directory-relative descriptors. It refuses foreign ownership, cross-device entries, symbolic/hard links, FIFOs and other special files; it checks for detectable concurrent changes. It sets directories to 0700 and regular files to 0600, including historical dashboards/reports. It closes ancestor directory access first while retained descriptors allow child changes. It never changes ancestor permissions outside the selected root. Existing data bytes, names and history are preserved. Runs are idempotent.

Limits and recovery: at most 512 entries per invocation (including directories); for larger stores choose smaller dedicated subtrees and remediate their parent separately. Unreadable files or unsearchable directories fail safely. Quiescence is mandatory: descriptor-based traversal reduces substitution risks but is not a transactional filesystem snapshot or defense against a malicious process running under the same UID. Preflight refusals change nothing. An OS error during chmod can leave partially tightened permissions; stop and inspect locally, then rerun. No automatic rollback broadens permissions. Mode bits do not certify encryption, backups, remote filesystems or all ACL policies. The utility was tested on synthetic fixtures, not run on the owner's evidence.

## Provenance and correlation changes

- Raw-file references now require a syntactically valid SHA-256; missing/malformed digests fail closed. Existing digest-less, reference-less legacy fixtures remain readable and are explicitly identified as `legacy_unverified` in derived source identities.
- Manifest and raw-file reads are bounded, regular-file-only, and use no-follow opens; raw evidence links, path traversal, absolute references, missing files and digest mismatches are rejected. Hashes detect changes, not publisher authenticity or source independence. Normalized snapshot digests bind the report to the selected document, not a proof of correct derivation.
- Correlation requires nonempty source record IDs and emits a false publication flag on each candidate. Tests cover exactly ±72 hours, rejection one second outside the window, timezone equivalence, timezone-less dates, invalid identities and input immutability. Prior geographic-date association tests remain in place.
- Neither NOAA view counts as independent corroboration of the other. Candidate status, coarse geographic limits, source/license review and public-release prohibitions remain unchanged.

## Legacy backend investigation

Repeated direct-pin audit on November 17, 2026:

```sh
python -m pip_audit -r backend/requirements.txt --no-deps --disable-pip
```

Result: **124 advisory rows in 15 packages**, including duplicate advisory identifiers. This is not 124 independently exploitable application flaws or a complete transitive audit. Affected pins include aiohttp, black, certifi, dnspython, ecdsa, filelock, multidict, oauthlib, pillow, pyasn1, PyJWT, pymongo, python-jose, starlette and urllib3. Registry audit could not assess `emergentintegrations==0.2.0` or the version of the vendor-hosted LiteLLM wheel. No advisory was suppressed. TLS verification remains enabled.

`backend/server.py` directly imports FastAPI/Pydantic, Motor, dotenv and the vendor chat classes. The existing requirements mix runtime, development, image/scientific, cloud and multiple provider dependencies. Imports alone do not establish that every other package is removable: vendor transitive requirements need inspection. Notably:

- FastAPI 0.110.1 and Starlette 0.37.2 require a coordinated framework update; reported Starlette fixes span multiple later API generations.
- PyMongo 4.6.3 has reported fixes in 4.18.x; replacing that pin without testing Motor 3.3.1 is unsafe because legacy drivers may rely on private internals. Prefer a tested migration to maintained PyMongo async APIs over indefinite Motor retention.
- ecdsa/python-jose and some PyJWT advisories have no listed fixed release in the audit output. Determine actual reachability; remove unused packages or replace the consumer, rather than asserting a version bump fixes them.
- The server persists raw provider exception details in system messages even though client errors are generic. Redaction and persistence access/retention policy must be addressed in the provider stage.

### Staged proposal (not a runtime migration performed by this PR)

| Stage | Concrete change | Required integration evidence / exit gate |
| --- | --- | --- |
| 0: Baseline and isolation | Preserve requirements, deployment configuration and data backups privately; inventory import and transitive dependencies, licenses and advisories. Separate runtime from development inputs. | Reproduce current API/SSE contract; archive resolver/audit output locally. Inventory provider credentials without recording their values. No production data in fixtures. |
| 1: Framework and network libraries | Trial a coherent supported FastAPI/Starlette/Pydantic set in a separate environment. Start with the candidate framework used by the new contract CI, not independent Starlette pin replacement. Update compatible TLS/HTTP/parsing packages. | Run `test_backend_migration_contract.py`, existing lint, validation and SSE framing tests; test malformed/oversized requests, CORS policy, disconnect/cancellation, slow streaming, proxy headers and non-2xx behavior on the candidate runtime. Generate a fully resolved, hashed lock and audit every reachable dependency. |
| 2: Storage | Introduce an injectable storage boundary; migrate Motor to supported PyMongo async APIs with explicit connection startup/shutdown. Preserve collection fields, UTC timestamps and session IDs. | Disposable local MongoDB with synthetic records only: user/assistant round trip, database outage and recovery, failed insert, duplicate/retry behavior, concurrent sessions, cancellation cleanup and shutdown. Run the nine existing service/MongoDB tests against a local app with a deterministic provider. Assert test jobs fail if expected service settings are absent instead of silently skipping. Verify backups/restore before any real database migration. |
| 3: Provider and dependency reduction | Put streaming behind an adapter; retain a deterministic offline implementation. Replace the unauditable vendor SDK with an audited open-source client where compatible, or require inspectable vendor artifacts, SBOM and provenance. Remove unused auth/image/cloud packages only after transitive verification. | Synthetic provider tests for deltas, done, malformed chunks, timeout, partial failure, cancellation and error redaction in both HTTP output and stored system messages; no successful done event after failure. Add mocked HTTP transport tests for the actual selected client SDK. Paid/live model tests require separate approval; they are not needed for offline contract CI. |
| 4: Release candidate | Produce reproducible runtime/dev locks, SBOM and container; fix trust-store configuration using the appropriate CA bundle. | Fresh full dependency audit with documented residual reachability; build/import container with TLS verification enabled; local database/service suites with zero unexpected skips; restore drill; privacy, reviewer identity and approval checks. Owner approval before integrating into the intelligence base, and separate explicit approval before merge to main or deployment. |

Added four offline ASGI integration-contract tests and a CI job on candidate FastAPI 0.141.1 / HTTPX 0.28.1. They load the real server routes with synthetic database and provider modules, prevent dotenv loading, and do not require network, MongoDB, model credentials or paid services. They cover health, SSE framing/completion, persistence ordering/session linkage, validation/configuration failures, provider error responses and initial database-write failure. **They do not validate the real Motor driver, vendor SDK, container or MongoDB.** The current installed Starlette emits a TestClient HTTPX deprecation warning; migration testing should move to its supported transport after validating compatibility. Production backend pins remain unchanged pending these stages.

## Validation and blockers

- Intelligence and migration unittests: 52 passed. Combined Python run: **141 passed, nine pre-existing live backend tests skipped, six subtests passed**; one TestClient transport deprecation warning.
- Node engine suite and all 24 Node tests passed.
- Permission tests cover dry-run, exact byte/path retention, idempotence, symlink ancestors, symbolic/hard links, special files, owner and entry limits, and application failure behavior.
- Container import remains unverified because the prior build failed on the proxy CA chain. No certificate bypass was attempted. Correct trust-store configuration is still required.
- Legacy backend vulnerability/transitive/vendor audit gaps and real database/provider integration gates remain release blockers. Private data permissions remain unchanged until the owner explicitly runs the migration utility in a stopped local environment.
- PR #28 must remain draft pending owner review. No merge, deployment or intelligence publication is part of this work.
