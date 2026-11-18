# Legacy backend remediation

Implemented on `feature/legacy-backend-remediation`, created directly from the intelligence development branch at `ada276c` (which already contains PR #28). This implements the staged plan in `PR28-REVIEW-AND-MIGRATION.md`. No base branch was changed, and no production service, database or evidence store was accessed.

## Changes and compatibility

- Upgrade to a coherent FastAPI 0.141.1 / Starlette 1.10.0 / Pydantic 2.14.3 runtime. Patch HTTP/TLS/DNS dependencies, including certifi 2026.10.23 and dnspython 2.9.2. Replace the broad legacy environment with **18 resolved runtime packages** and a separate development lock. Both lockfiles contain exact versions and SHA-256 artifact hashes. The development resolution is constrained by the runtime lock.
- Replace Motor 3.3.1 / PyMongo 4.6.3 with PyMongo 4.20.0's `AsyncMongoClient`. Connect and ping during application lifespan, bound selection/operation timeouts, and close on normal shutdown or startup failure. Storage is injectable for deterministic unit tests. Existing collection, session IDs, user/assistant/system roles, UTC string timestamps and message fields remain compatible. No indexes, validators, TTL policies, bulk rewrites, database schema migration, pruning or production data changes are performed by application startup.
- Remove `emergentintegrations`, its vendor-hosted LiteLLM wheel, and their unused dependency graph from the candidate runtime. Use an explicit provider interface and HTTPX-based OpenAI-compatible SSE adapter, suitable for a free self-hosted HTTPS service. A deterministic synthetic adapter is available only when explicitly selected with test mode. No provider or paid service is enabled by default.
- Preserve `/api/health`, `/api/ai/audit`, request fields, SSE `delta`, `done`/`session_id`, generic stream-error text, and persistence before successful completion. Initial database-write failures now return a controlled HTTP 500 rather than an unhandled exception. SSE failure paths never emit `done`, even when writing the system-error record also fails. Cancellation propagates and closes the provider stream.
- Redact errors by storing a fixed failure classification, never exception messages, exception class names, URLs, keys or prompts from errors. This affects new failure records only. Historical system-message contents are untouched and need a separately approved review if they may contain secrets.
- Add a **256 KiB request-body limit** before parsing/storage, a 90-second provider-stream deadline, a one-million-character normalized output cap, bounded raw SSE response/frame sizes, provider timeouts and no automatic retries. Oversized requests now return HTTP 413; this is an intentional hardening change for formerly unbounded payloads. Existing report-length validation remains 12,000 characters. Malformed JSON continues to return 422.
- Provider TLS verification remains enabled. Redirects and ambient proxy configuration are disabled for the provider client. Explicit MongoDB certificate/hostname verification bypass options and `tls=false`/`ssl=false` are rejected. Local disposable MongoDB uses its normal loopback test transport without TLS bypass flags; remote databases still require a deployment-appropriate valid TLS configuration.

## Provider configuration migration

`EMERGENT_LLM_KEY` alone no longer activates the vendor service. Its credential is not assumed to be portable, forwarded to another provider, or tested live. Select an approved adapter explicitly. Existing `.env` files are not read automatically by this backend or its integration tests; export server settings explicitly. No production configuration files were edited.

```sh
python -m pip install --require-hashes -r backend/requirements.txt
export MONGO_URL='mongodb://YOUR_APPROVED_DATABASE'
export DB_NAME='YOUR_APPROVED_DATABASE_NAME'
export LLM_PROVIDER='disabled'
uvicorn backend.server:app --host 127.0.0.1 --port 8001
```

For an operator-approved free self-hosted provider, explicitly configure `LLM_PROVIDER=openai_compatible`, `LLM_BASE_URL` ending in the API prefix such as `/v1` (not `/chat/completions`), `LLM_MODEL`, and `LLM_API_KEY`. The endpoint must use HTTPS with a valid certificate. These values are server configuration, not request parameters. No default paid endpoint/model or credential is embedded. Any live commercial service use remains subject to owner approval; this work makes no model calls.

Synthetic mode uses `LLM_PROVIDER=synthetic` and `WATCHDAWG_TEST_MODE=true`, and labels all generated content as synthetic/unverified. The disposable runner sets these only for its temporary test processes/containers. Synthetic output must not be treated as intelligence or publication approval.

## Disposable database and integration testing

```sh
python -m pip install --require-hashes -r backend/requirements-dev.txt
python scripts/test_backend_disposable.py --all-python
```

The runner creates a uniquely named private Docker bridge network, a digest-pinned MongoDB 8.0 image with a temporary RAM-backed data directory, and loopback-only randomly assigned host ports. It launches the real API with synthetic provider configuration and a randomly named `watchdawg_test_*` database. Service tests require explicit synthetic mode, loopback URLs, and the matching per-run identifier. They do not load `.env`, production connection strings or provider keys. The network permits Docker bridge connectivity; it is not an egress firewall. No test provider makes external requests.

The runner removes only its own containers/network in `finally`; test database contents are disposable synthetic data. It never drops an operator database or deletes retained intelligence evidence. Tests exercise the real async driver and MongoDB: request/SSE/persistence round trips, concurrent independent sessions, rejected user inserts, rejected assistant inserts, generic failure persistence, recovery, startup outage, repeated startup/shutdown and retention of a pre-existing synthetic marker. The failure test temporarily changes the validator only in the runner's disposable database and restores it before proceeding.

The nine original live backend tests now run under this harness instead of skipping. Additional deterministic tests exercise the actual provider protocol via mocked HTTP transport: HTTP errors, redirects, malformed and incomplete SSE, numeric content, frame limits, timeouts, timezone/message fields, partial failures, cancellation, oversized and chunked requests, CORS and prompt truncation. They do not certify any particular live model's quality or vendor protocol variation.

MongoDB Community is free to run and source-available under SSPL, **not an OSI-approved open-source license**. The database was explicitly requested; no paid database service was introduced. Application dependencies remain free/open-source. Review SSPL obligations before redistributing or offering a database service. No database image is published by this work.

## Container and trust-store checks

The backend has a digest-pinned Python 3.12 base, non-root UID 10001, a minimal runtime context allowlist and hashed dependency installation. Only the runtime Python files and lock are copied, with ownership set for the non-root user; tests, `.env`, repository memory, evidence and other source trees are excluded.

```sh
docker build -f backend/Dockerfile -t watchdawg-backend:test .
python scripts/test_backend_disposable.py --backend-image watchdawg-backend:test
```

For an inspected build network, the optional BuildKit secret `package_ca` supplies a local CA bundle to pip **only during installation**:

```sh
docker build --secret id=package_ca,src=/etc/ssl/certs/ca-certificates.crt \
  -f backend/Dockerfile -t watchdawg-backend:test .
```

This keeps certificate verification enabled; it does not trust arbitrary hosts or copy the build secret into the image. The earlier local certificate-chain blocker was handled using this verified CA bundle, not by `--trusted-host`, `verify=False` or a disabled certificate check. The container is built locally and tested with the synthetic provider and disposable database, never deployed.

## Dependency audit and vendor investigation

The old 124-advisory-row result concerned the original broad environment, including duplicate rows. Some packages had no listed fixes. The candidate runtime resolves this through a coherent upgrade and removal of unneeded packages/consumers, rather than advisory suppression or unsupported individual version overrides.

The unauditable vendor SDK was unavailable to the registry audit, and the old custom wheel URL/hash did not provide independently verifiable package-version/license provenance. This work does **not** assert that those artifacts were safe or authentic. They are absent from both candidate locks, container installation and source imports. The replacement provider implementation is in this repository and relies on audited HTTPX. Runtime SBOM: `backend/sbom/runtime.cdx.json` (18 components). A clean candidate audit does not fix any already deployed legacy environment; none was modified.

```sh
python -m pip_audit -r backend/requirements.txt
python -m pip_audit -r backend/requirements-dev.txt
```

Both candidate audits report **no known vulnerabilities** as of November 17, 2026. KEY-9 Python and production npm audits also report no known vulnerabilities. This is a registry-advisory result, not proof of exploit absence or a perpetual guarantee. The supply-chain verifier now understands and validates pip hash continuations and audits development locks; it does not silently exempt hash lines. Lock generation uses pip-tools 7.7.0 with upgrades and SHA-256 hashes. Reproduce on Python 3.12/Linux and constrain the development resolution with the runtime lock:

```sh
pip-compile --upgrade --generate-hashes --no-emit-index-url --no-emit-trusted-host \
  backend/requirements.in -o backend/requirements.txt
pip-compile --upgrade --generate-hashes --no-emit-index-url --no-emit-trusted-host \
  backend/requirements-dev.in -o backend/requirements-dev.txt
```

## Validation and remaining gates

- Full Python suite with disposable MongoDB: **180 passed, zero skipped, six subtests passed**.
- Packaged backend suite: **39 passed, zero skipped** against the built container and disposable MongoDB.
- Node deterministic engine plus all 24 Node tests passed; public artifact build, frontend server syntax, KEY-9 ESLint and production build passed.
- Backend/runner flake8, Python compilation, runtime/development/KEY-9 dependency audits and KEY-9 production npm audit passed. Runtime installs with `--require-hashes` and `pip check` passes.
- Supply-chain verifier: zero errors; two inherited warnings for tag-only KEY-9 and Sentinel base images. The new backend and MongoDB test image are digest-pinned.
- One remaining test warning: Starlette deprecates its current HTTPX TestClient transport. It does not affect the production HTTPX client or indicate a known audited vulnerability. Upgrade the test transport in a separate compatibility-tested change.
- CI now installs the hashed development lock, runs real disposable integration tests without skips, performs runtime/development audits and tests the packaged API. Hosted results depend on a subsequent PR run; local results above do not imply hosted CI has already executed this branch.

**Before release:** review the explicit provider configuration transition and request-size limit; approve any real provider endpoint; verify deployment TLS roots, network access/authentication, private CORS policy and database authorization. The API intentionally retains its existing unauthenticated route contract and wildcard non-credentialed CORS behavior; do not expose it directly to untrusted callers. Live provider conformance, authentication/rate limiting, backup/restore, encryption/quotas, historical error-record review and reviewer identities remain operational release gates. No automatic retry/idempotency key was added: repeated requests create distinct sessions, matching existing behavior.

Intelligence adapters, private archaeological coordinates, offline snapshot retention and human-publication approval gates are unchanged. No production data, private coordinate files or evidence permissions were modified. No merge, deployment, image publication or intelligence publication was performed.
