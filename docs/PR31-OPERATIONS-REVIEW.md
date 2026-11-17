# PR #31 development integration review

PR: https://github.com/bobhay75/Watch-Dawg-AI/pull/31

Base: `feature/intelligence-brief-plan-2026-11-15`, `4c6f230be6e4f15ac5b512309fdab3bf29b4443b`.
Head branch: `feature/secure-operations-recovery`. Initial review head was `bc5039b`; remediation commits remain on that branch. The PR remains draft. No merge, deployment, production-data access/change, paid-provider call or intelligence publication was performed. All database operations, credential changes, TLS certificates, evidence and restore destinations in these checks were synthetic/disposable.

## Findings and fixes

| Finding | Resolution |
| --- | --- |
| KEY-9 build could not validate the inspected network's PyPI certificate chain | Add optional BuildKit `package_ca` secret, as already supported by the backend. Pip still verifies certificate chains. The CA is used only during installation and does not enter the image or runtime trust store. Build succeeds with the host-approved trust bundle; there is no insecure-host flag or verification bypass. |
| Existing pip audits did not scan OS libraries or pip's bundled dependencies | Add checksum-pinned FOSS Trivy 0.76.2 scans to CI for all five runtime images, including the MongoDB variant used by tests/reference Compose. Image-ID binding, OS analysis and expected Python analysis are required. Missing/malformed scans fail closed. |
| Fixable image findings in Debian zlib, Alpine libxslt/zlib and bundled pip code | Apply narrow signed-distribution updates and enforce the minimum patched Debian zlib version; pin patched Alpine packages. Remove pip after build-time dependency installation, including its vulnerable vendored msgpack/setuptools/urllib3. Application dependencies/API code remain unchanged. |
| Upstream MongoDB image includes vulnerable unused Go tools, gosu and standalone js-yaml | Derive a pinned non-root server/shell variant. Remove actual unused binaries/library files, not their advisory records. Keep the same MongoDB 8.0.38 engine and mongosh 2.14.2. No root entrypoint/chown/init script runs. Start `mongod` directly; roles/bootstrap remain explicit administrative actions. All test runners/reference Compose use this variant. |
| KEY-9 build context copied arbitrary remaining source files | Replace broad copying with runtime source allowlists and test the packaged filesystem, non-root execution and absence of build CA/pip. |
| Two existing container base-tag warnings | Pin KEY-9/Sentinel Python bases to inspected digests. All five Dockerfile bases now have digest pins. |

The original upstream MongoDB scan found one critical row in gosu's Go standard library and fixable high rows in bundled Go database tools/js-yaml. The minimal variant removes those artifacts. It intentionally does not provide `mongodump`, `mongorestore`, `mongoimport`, `mongoexport`, `bsondump`, `mongofiles`, `mongostat`, `mongotop`, gosu or root initialization. Operators needing these tools require a separately reviewed, patched utility image. Do not reinstall packages inside running containers. The server/shell variant is not a claim that upstream packages or historical vendor artifacts have been repaired.

## Current local image findings

Counts are **scanner package/advisory rows**, not counts of distinct exploitable issues. All severities remain visible; no `.trivyignore`, advisory suppression or invented clean-image result is used. The three Python images share 11 distinct high-severity advisory identifiers across 47 rows each. The current database lists no fixes for those high rows; exploitability/reachability was not proven or dismissed.

| Patched image | Critical | High | Medium | Low | Unknown | Fixable high |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Backend | 0 | 47 | 92 | 65 | 5 | 0 |
| TLS proxy | 0 | 0 | 0 | 0 | 0 | 0 |
| KEY-9 | 0 | 47 | 92 | 65 | 5 | 0 |
| Sentinel | 0 | 47 | 92 | 65 | 5 | 0 |
| MongoDB server/shell variant | 0 | 0 | 49 | 6 | 0 | 0 |

MongoDB has 13 fixable medium rows remaining. Local image IDs, database freshness, report hashes, counts and the distinct unfixed-high identifiers are in [security/PR31-IMAGE-SUMMARY.json](security/PR31-IMAGE-SUMMARY.json). CI independently rebuilds/scans its own artifacts and verifies the actual Docker image ID. Counts may change when signed distribution repositories, unpinned transitive KEY-9 dependencies or advisory data change; scan every new artifact.

The development policy blocks **every critical finding**, **high findings with listed fixes**, EOL images, invalid reports and missing expected analysis. Unfixed high/medium/low/unknown findings remain explicit residual risks and do not constitute production acceptance. This is a stated development threshold, not permission to deploy vulnerable images. Trivy cannot establish absence of vulnerabilities or exploitability. Distribution/vendor metadata and severities can differ from other sources.

## Security and recovery verification

- **Encrypted offline backups:** AES-256-GCM authenticity plus receipt/manifest/per-file hashes, wrong-key/corruption refusal, forged-receipt refusal, authenticated path traversal rejection, expansion/member limits, exclusive new restore destinations and prohibition on backups inside their source. Real evidence/provenance remains unchanged; no backup/upload/pruning of real files occurred.
- **Tokens:** live same-principal overlapping credentials, final removal/401 for old tokens, expiry-based revocation, stale-CAS refusal, corruption/missing-file fail-closed behavior and rejection of live network/HMAC/rate-policy changes. Shared budgets remain tied to the principal. Revocation does not retroactively terminate admitted bounded streams; compromise containment still needs approved drain/isolation.
- **MongoDB:** authenticated TLS three-voter replica set, exact app/backup grants, denial of private collection reads/user creation/deletion, actual primary loss/election, majority-loss 503/recovery, read-only synthetic export and encrypted restore into a different database using an insert-only restore principal. The new server/shell variant passes the same checks. Same-host voters do not certify host/site high availability.
- **TLS/mTLS/network:** verified CA/name/SAN trust, TLS 1.2/1.3, required backend client certificate, direct-peer spoof rejection, fixed proxy headers/host/routes, internal API/database networks, no backend/database published ports, unprivileged read-only containers and dropped capabilities. The proxy-only ingress bridge requires target-host deny-by-default egress/firewall validation.
- **Audit durability:** private fsynced admission/response records, dedicated directory/schema checks, rotation/storage/minimum-retention tests, concurrent writers, partial-tail refusal, fail-closed disk/capacity behavior and persistence after backend restart. Response audit failure releases an unstarted stream's leases. This is durable local storage, not WORM or independent custody.
- **Human review:** registered Ed25519 key, explicit private review decision/confirmation, signed ordered hash chain, independent head checkpoint detecting truncation, tamper/publication-decision rejection. Every record keeps `public_release_approved: false`; no publication action/privilege exists. Key possession/interactive confirmation is an attestation, not biological proof of human presence.
- **Actual KEY-9 package:** offline/no-network SDK import, private bridge 401, authorized app discovery, missing approval 400 and production refusal without durable session configuration. No model invocation, actual external accounting write or owner authentication certification occurred.

## Test results and exact-commit CI gate

| Local check | Result |
| --- | --- |
| Existing Python suites, real disposable MongoDB | 224 passed, six subtests; zero skipped |
| Operations/recovery/scanner-policy suite | 33 passed; zero skipped |
| Packaged backend / disposable database | 83 passed; overlaps the 224 and is not an additional distinct suite count |
| Three-voter TLS/mTLS outage/restore/audit-restart runner | Passed with the minimal MongoDB variant and patched backend/proxy |
| Root Node tests | Legacy engine checks plus 24 passed; zero skipped |
| KEY-9 Node | Lint, build and full npm audit passed; zero reported advisories |
| Python audits | Backend runtime/development, operations, KEY-9 requirements and actual Python 3.13 installed-image inventory passed; vendored pip findings required the separate image scanner and were removed |
| Containers | All five images built locally; actual offline KEY-9 boundary checks and Sentinel missing-token refusal passed |
| Quality/supply chain | Flake8, compileall, pip check, workflow YAML/bash parsing, public build and supply-chain verifier passed; five base digests, zero supply-chain errors/warnings |

The only Python warning is the existing Starlette test-client HTTPX deprecation. No live provider or private field bundle was used. Root npm has no dependencies, so an npm registry audit is inapplicable there. Production recovery, systemd scheduling and real firewall/certificate installation remain unperformed; systemd verification was restricted by the managed environment's read-only `/run/systemd`.

Before integration, verify the PR's **final head SHA**, current target base, GitHub `MERGEABLE` state and every applicable job's completed/success conclusion. The new KEY-9 and Sentinel changes also activate their workflows, in addition to Test Watch-Dawg, Validate Watch-Dawg AI and government evidence. A prior head's green checks, a queued job or a skipped path-filtered workflow is not validation of the final artifact. The review response records the exact final head and workflow results after push; the Checks tab retains the authoritative run links. Keep the PR draft and do not merge without owner approval.

## Readiness and remaining priorities

**Development integration:** acceptable for the isolated development branch once the exact-final-head GitHub jobs pass and GitHub confirms mergeability. Tests and the development image threshold support review/integration; they do not authorize a merge or live service.

**Production readiness remains blocked.** First triage/reassess the 47 high rows/11 advisories shared by each Debian Python image and the 13 fixable MongoDB medium rows, and plan patched supported base/package updates or further reviewed minimization. Retain full-image scanning as a release gate and review native/bundled cryptography/runtime coverage. KEY-9 still has direct version pins rather than a complete hash-locked Python 3.13 transitive resolution; create/review that lock before reproducible production release. Its production owner authentication is still explicitly unimplemented and cannot be replaced with a bridge token or sandbox confirmation header.

Then approve/validate actual host firewall/IPv6/proxy egress, certificate issuance/rotation and private secret mounts, principal assignments, independent MongoDB failure domains and administration, private audit disk/traffic capacity/monitoring, offline key escrow, consistent real database backups and isolated restore/RPO/RTO drills, independent reviewer/audit checkpoint custody, and on-host systemd behavior. Backup snapshots remain capped at 64 MiB/4096 files with private plaintext scratch requiring encrypted storage/tmpfs and stopped writers. Runtime pip/database tools are intentionally absent; recovery utilities must be reviewed separately. Private coordinates, retained evidence and source provenance remain outside public artifacts, and public intelligence always requires a separate explicit authorized human decision.
