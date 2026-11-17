# Secure operations validation — 2026-11-17

Feature branch: `feature/secure-operations-recovery`, created from `feature/intelligence-brief-plan-2026-11-15` at `4c6f230be6e4f15ac5b512309fdab3bf29b4443b`. No merge, deployment, production data change, live/paid provider contact or intelligence publication was performed. Secrets/certificates/evidence used in tests were generated synthetic fixtures. The new CI job builds/tests locally and never pushes images or starts a production deployment.

## Implemented controls

- Reviewed rootless Nginx/Compose TLS templates: fixed host/routes, overwritten forwarding headers, exact trusted proxy peer, verified upstream mTLS, TLS MongoDB, internal application/data networks, no backend/database published ports, read-only containers, dropped capabilities and bounded logs. A missing backend DNS alias was corrected. Docker cannot publish ingress on an internal-only network, so only the proxy has a separate ingress bridge; host-level deny-by-default proxy egress remains an installation requirement.
- Principal-only policy reload on each new request, safe same-principal overlap/final rotation, expiry-based revocation, private file checks, local locked compare-and-swap/atomic installation and fail-closed policy errors. HMAC/rate/network changes require restart. In-flight streams remain bounded, not instantly reauthenticated.
- Explicit MongoDB application/backup role provisioning with no admin grants to the application; three-member authenticated/TLS disposable elections and majority-outage recovery. Restore uses a distinct insert-only principal in a newly created synthetic destination database.
- Authenticated AES-256-GCM offline backups, ciphertext receipt, per-file manifest hashes, bounded safe extraction, exclusive destinations and standalone/CI synthetic restore drills. No deletion/upload of retained evidence or automatic restoration over existing data.
- Dedicated fsynced schema-limited private audit journal, thread/process locks, daily/size rotation, minimum retention, storage/free-space limits and fail-closed capacity errors. A response-header audit failure now releases stream slots even when stream iteration never starts.
- Private Ed25519 human-review attestations with explicit interactive confirmation, signature/hash-chain validation and independently held head-checkpoint support. Every receipt/record remains `public_release_approved: false`; there is no publication action or authority.
- Runbooks for deployment review, renewal, compromise, quorum outages, disk/log exhaustion, backup/restore, custody, host/site loss and disaster recovery: [SECURE-OPERATIONS-RUNBOOK.md](SECURE-OPERATIONS-RUNBOOK.md).

## Local validation

| Check | Result |
| --- | --- |
| All existing Python suites with disposable MongoDB | 224 passed, six subtests passed, no skipped tests; includes intelligence, Sentinel, KEY-9 trust-boundary and real backend database tests |
| New operational/security/recovery tests | 19 passed, no skipped tests |
| Packaged backend with disposable MongoDB | 83 passed, no skipped tests; these overlap the full Python suite and are not additional distinct tests |
| Three-voter TLS recovery runner | Passed: verified frontend/backend/Mongo TLS, missing backend client-certificate rejection, direct-peer spoof rejection, role denials, live overlap/final/revoked/corrupt policy, elected-primary failover, majority-loss fail-closed/recovery, encrypted restore and audit restart persistence |
| Standalone synthetic encrypted CLI drill | Passed; fixture/key/archive created locally and only its own disposable fixture removed |
| Python lint, compilation, dependency consistency | Passed: flake8 backend/operations/test runners, compileall, pip check, git diff whitespace checks |
| Root Node tests | Existing deterministic engine checks plus 24 Node tests passed, no skipped tests |
| Public artifact build and frontend server syntax | Passed; public allowlist/privacy regressions passed |
| KEY-9 Node | Exact-lock install, lint, production build and full npm audit passed; zero known advisories |
| Backend runtime/development, operations and KEY-9 Python locks | pip-audit passed for all four requirement sets; zero known advisories reported |
| Backend/proxy containers | Built locally; live TLS/mTLS checks passed with verification enabled; backend runtime allowlist/non-root UID 10001 verified |
| Compose | Configuration parsing and isolation/port/capability/mTLS contract tests passed without starting the template |
| Sentinel container | Built; correctly refused startup without a bearer token |
| Supply chain and government evaluation generator | Passed with two existing container digest warnings (below); four Dockerfile bases checked, including the new proxy Dockerfile |

The full Python runner was also invoked with deliberately invalid inherited audit settings to verify those settings are stripped before starting synthetic processes. The runner does not adopt a caller's production audit path. Compose validation explicitly ignores `.env`. Backend API response fields and retained message behavior remain covered by the existing suites.

FastAPI's test client emits one existing Starlette deprecation warning recommending `httpx2`. This does not fail the suites. Provider adapters/KEY-9 policies are exercised with synthetic/mock implementations; no live model/paid provider conformance claim is made.

## Blocked or intentionally unperformed checks

- The unrelated KEY-9 agent container rebuild failed while pip verified PyPI's certificate chain in this inspected build network (`CERTIFICATE_VERIFY_FAILED`, self-signed certificate in chain). Its sandbox image import therefore could not run on a newly built image. TLS verification was preserved. A reviewed build-only CA mechanism, analogous to the backend's existing BuildKit `package_ca` secret, and a successful Python 3.13 SDK/container rebuild are required before claiming that container is validated. No trust override, SDK upgrade or unrelated image publication was performed here.
- `systemd-analyze verify` could not create `/run/systemd` in this restricted environment. The timer/service were not installed or enabled. The underlying synthetic CLI and CI recovery drill ran successfully; validate units and scheduling on the approved target host before installation.
- No Trivy/Grype OS/image scanner was available. Registry dependency audits and digest pinning do not scan distribution packages, bundled OpenSSL/Rust cryptography or vendor runtime internals. Full final-image SBOM/CVE scanning remains required for production acceptance. No advisory allowlist or invented clean-image result was substituted.
- Root npm has no dependencies or lockfile; `npm audit` is inapplicable there (ENOLOCK). Its actual dependency-free Node tests ran; KEY-9's dependency lock received the npm audit. The field-bundle verification CLI requires an operator-selected bundle; no real/private bundle was supplied. Synthetic bundle/privacy behavior is covered by Node tests.
- No production database, real evidence recovery, real CA/secret installation, firewall alteration, systemd deployment, failover across independent hosts, live provider or public release was tested or authorized. Local validation does not establish GitHub checks on a future pull-request commit; the added `operations-recovery` PR job must pass on the integration candidate.

## Remaining risks and acceptance gates

**Development review:** the implemented controls are ready for review after the recorded local suites pass. Keep the feature branch isolated; integration still requires owner approval and applicable GitHub checks on the reviewed final commit. This document is not an authorization to merge.

**Production readiness remains blocked** on approval and validation of actual host isolation/IPv6/firewall and proxy egress denial, trusted certificate issuance/renewal and private secret ownership, principal assignments and private token delivery, MongoDB independent failure domains/admin provisioning, storage quotas/traffic capacity/monitoring, separately escrowed backup keys, real consistent backups/isolated restores, independent audit/reviewer checkpoint custody, and measurable RPO/RTO objectives. The optional same-host replica profile is not disaster-resilient high availability.

Existing supply-chain warnings remain: Sentinel's `python:3.12-slim` and KEY-9 agent's `python:3.13-slim` bases are tagged rather than digest-pinned. The new proxy and existing backend base are digest-pinned. The removed legacy vendor SDK/wheel remains absent from the backend; historical vendor provenance/audit gaps were not retroactively resolved. Unknown advisories, OS packages and cryptographic implementation vulnerabilities remain outside a clean pip/npm registry report.

Local audit files are durable fsynced storage, not WORM. A privileged/same-UID attacker can tamper with files, roll back credentials or remove the end of a chain; independent checkpoints/custody are required. Synchronous fsync can stall application workers on unhealthy storage, and abuse/disk exhaustion can intentionally trigger fail-closed outages. Audit retention/capacity must be sized for rejected as well as authorized traffic. Static tokens remain replayable if stolen and are not end-user MFA/tenant identity. Reviewer signing-key possession is an attestation mechanism, not proof of human presence.

Backups retain file bytes/provenance, not original mode/timestamp/empty-directory metadata; snapshots require stopped writers and private encrypted/tmpfs scratch. Current limits are 64 MiB/4096 files with bounded in-memory decryption, not a large live-database snapshot design. Archive and receipt publication are separate filesystem operations: an interruption may leave an incomplete pair, which must be preserved and investigated, never counted as a verified recovery point. Source evidence is never pruned. Review journals are bounded private volumes; rotation/custody linking and public intelligence approval require separate human procedures.
