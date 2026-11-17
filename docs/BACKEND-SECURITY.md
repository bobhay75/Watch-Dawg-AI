# Backend production-oriented security

Implemented on `feature/backend-production-security`, branched from intelligence development commit `11521e8` (which already contains PR #29). This adds application controls; it is not approval to deploy, expose the API publicly, or publish intelligence. No production data, secrets, evidence permissions or archaeological coordinate files were accessed or changed.

## Access and trust boundaries

All API calls now require a server-registered bearer token, including health checks. The caller supplies `Authorization: Bearer <token>` over an approved transport. The backend stores only SHA-256 digests of high-entropy service tokens in a private policy file. Tokens have explicit expiry; comparisons use `hmac.compare_digest`. There are exactly two privileges:

| Scope | Permission |
| --- | --- |
| `health:read` | `GET /api/health` |
| `audit:run` | `POST /api/ai/audit` |

There is no admin wildcard, user-selected role, evidence-read/export scope, or intelligence-publication scope. A health-only credential cannot run an audit. Headers such as `X-Role`, `X-Scopes`, caller IDs, query parameters and request-body approval fields cannot change authorization. OpenAPI/docs endpoints are disabled. Preflight OPTIONS is permitted only for an explicitly allowed origin, supported route/method and the `Authorization`/`Content-Type` request headers; the actual call still requires authorization.

Authorized successful requests retain their financial audit JSON, SSE delta/done/session fields and database message shape. Deliberate security changes: missing/invalid/expired credentials return 401, insufficient privilege/network/origin/transport returns 403 (invalid hosts return 400), budgets return 429 with Retry-After, unavailable security storage returns 503, and invalid input responses do not echo private values. Responses are `no-store`, include `nosniff`, and get a server-generated request ID. No browser cookie authentication or credentialed wildcard CORS was introduced.

## Bootstrap and secure configuration

Install the existing hashed runtime lock first. Generate one least-privilege principal offline; these example commands only create local private files and do not contact a provider or database:

```sh
python scripts/create_backend_security.py \
  --output-dir .backend-secrets \
  --principal audit-service --scope audit:run \
  --host api.example.invalid --network 10.20.0.10/32 \
  --origin https://console.example.invalid \
  --transport proxy --proxy-network 10.20.0.10/32
```

The bootstrap directory is mode 0700; `token` and `security.json` are mode 0600, exclusively created without overwriting existing files. The token is never printed. `security.json` contains the token digest, expiry (seven days by default; `--days` permits 1–90), exact allowlists and a random 256-bit rate-limit HMAC key. `.backend-secrets/` is Git-ignored; prefer deployment secret mounts outside the checkout. Never commit or include these files in build artifacts. Keep the raw token with its authorized client, not in the server image, public frontend, URL, shell command arguments, browser localStorage or logs. Use a separate `health:read` principal for monitoring; explicitly grant both scopes only when necessary.

Server variables:

| Variable | Meaning |
| --- | --- |
| `BACKEND_SECURITY_FILE` | Required path to the private policy JSON; no authentication-off fallback |
| `MONGO_URL_FILE` | Recommended private file containing MongoDB URI; legacy `MONGO_URL` remains supported |
| `DB_NAME` | Existing approved application database |
| `LLM_API_KEY_FILE` | Private provider credential file if a real provider is separately approved; `LLM_API_KEY` is also supported |
| `LLM_PROVIDER` | `disabled` by default; real providers still require explicit approved endpoint/model/credential configuration |

For either secret, specifying both its value and `_FILE` fails startup. Files must be regular, non-symlinked, single-link, owned by the running UID, without group/other permissions, and within size limits. Missing or unsafe policy files fail closed. This reader targets POSIX/Linux. Policy errors do not print raw JSON or secrets. Protect the parent directory and host account; this does not defend against root or a malicious process with the same UID.

The container runs as UID/GID 10001. Provision mounted server policy/secret files for that UID, read-only, mode 0400 or 0600 inside a private directory; a host file owned by a different UID with mode 0600 will intentionally fail. Only the policy/hash/HMAC material belongs on the server; the raw client token does not. The test harness injects only ephemeral synthetic policy material into a private tmpfs, through stdin, after container creation; it is not baked into an image layer.

### Policy format and limits

The bootstrap utility writes the canonical shape. To add principals, edit the private file offline with distinct `id`, scopes, `token_sha256` list and timezone-aware `expires_at`. A principal may hold up to four digest entries for overlap during rotation. Duplicate names/digests, unknown privileges, wildcard hosts/origins and `/0` peer networks are rejected. Allowed origins must be exact HTTPS origins; an empty list disables cross-origin browser access. Raw service-to-service requests need no Origin header but still require network, transport and token checks.

Optional `rates` values are positive integers:

```json
{
  "window": 60,
  "global_limit": 600,
  "network_limit": 120,
  "principal_limit": 30,
  "global_streams": 4,
  "principal_streams": 2
}
```

These are fixed-window counts, not a rolling-window algorithm. A caller can consume up to two windows' allowance across a boundary. Global and actual-peer budgets include failed authentication and preflights; principal budgets are shared by all tokens for that principal. A trusted proxy's clients share its peer budget, so size aggregate budgets and monitoring frequency deliberately. The principal budget covers both allowed routes. Stream concurrency is separately bounded by shared, 120-second expiring leases; provider streams are already bounded to 90 seconds and database operations to five seconds, and lease admission itself is bounded to five seconds. Released leases cannot be released again by a stale owner after another worker has claimed the slot.

MongoDB atomic updates enforce budgets/leases across workers and restarts; there is no production in-memory fallback. The policy HMAC key pseudonymizes peer/principal keys before storage. Keep it identical across workers and stable during token rotation, or workers will not share the same budgets. Policy is immutable during a process lifetime: token removal/scope changes require an approved restart of all workers. Expiry is checked on each new request; an already admitted stream may continue until its bounded completion. For immediate revocation, stop/drain existing workers. Rotate the HMAC key only during a coordinated maintenance window with streams drained and old leases expired; do not use the bootstrap utility as an in-place rotation tool.

## Network, TLS and CORS deployment configuration

`allowed_hosts`, `allowed_networks` and `trusted_proxy_networks` use exact hostnames and explicit CIDRs. Limits use the TCP peer address, never `X-Forwarded-For`, `X-Real-IP`, `Forwarded` or User-Agent values. Uvicorn must not rewrite the ASGI peer before these checks. The Docker command and test harness set `--no-proxy-headers`; use it for host launches too, and keep access logs off so raw query paths do not reach server logs.

Transport modes:

- `https`: require the actual ASGI HTTPS scheme. Configure valid TLS certificates on Uvicorn or an equivalent trusted server.
- `proxy`: require the actual peer to be in both the network allowlist and trusted-proxy CIDRs, and require a single `X-Forwarded-Proto: https`. The TLS-terminating proxy must overwrite this header based on its own verified connection, never pass client-supplied values through.
- `loopback`: allow HTTP only on a loopback peer, for private local development. Other peers still need HTTPS and an allowed network. This is not a public deployment mode.
- `test`: restricted at startup to explicit synthetic mode and a disposable `watchdawg_test_*` database (or internally injected unit-test storage). Authentication still applies. Never configure it for a real deployment.

A production host launch, after approving/provisioning secrets and database access, should use a private interface, approved transport, and bounded connection settings, for example:

```sh
# Required secure files and policy must already exist; no secrets in arguments.
export BACKEND_SECURITY_FILE=/run/secrets/backend-security.json
export MONGO_URL_FILE=/run/secrets/backend-mongo-url
export DB_NAME=watchdawg
export LLM_PROVIDER=disabled
python -m uvicorn backend.server:app --host 127.0.0.1 --port 8001 \
  --no-proxy-headers --no-access-log --no-server-header \
  --limit-concurrency 64 --timeout-keep-alive 5
```

Use `proxy` only behind an existing correctly configured TLS ingress, or supply TLS certificate/key options and use `https`. Restrict firewall/security-group ingress to approved peers; do not publish the backend port on all host interfaces. For a TLS ingress, overwrite `Host` with an approved host and `X-Forwarded-Proto` with its own TLS scheme, forward the caller's Authorization header, and configure header/body deadlines, connection limits and edge request limits. Do not log Authorization, request bodies, query strings, tokens or private source metadata.

The repository's legacy Node frontend proxy forwards caller headers; **it is not a trusted TLS attester**. Do not put it in `trusted_proxy_networks` unless a separately reviewed gateway strips/overwrites untrusted headers. No shared service credential was injected into the public frontend. Browser/UI authentication and any identity-provider integration need their own review; authorized API clients can send bearer headers through an appropriately secured gateway.

Outbound provider TLS verification, redirect refusal and MongoDB TLS-bypass rejection remain enabled. Local HTTP in the isolated synthetic harness does not disable certificate verification for any TLS connection. No paid/live provider calls were made.

## MongoDB least privilege and retention

The application still only inserts financial message records; it has no read/export API. Configure a database user scoped to the approved database/collections, without cluster administration or access to archaeological/evidence collections. A custom role should grant:

- `insert` on `ai_audit_messages`;
- `find`, `insert`, `update` and `createIndex` on `security_windows` and `security_leases` only.

Provision the collections during an approved database setup. Startup idempotently creates TTL indexes on the two security-state collections; the role needs that narrowly scoped permission. It never creates TTL indexes on financial messages, source snapshots or offline evidence. MongoDB's TTL monitor may remove expired counters/leases; enforcement itself checks windows/lease expiry and does not depend on prompt TTL cleanup. No production database or role was changed during this work. Integration tests use only newly created, uniquely named disposable databases and preserve a synthetic existing-record marker.

Caution: peer/principal references are keyed pseudonyms, not anonymous data. Protect the policy HMAC key, security collections and logs. Shared MongoDB must be healthy and reachable; quota storage outages fail requests closed with 503. Synchronize worker clocks and monitor clock changes. Existing replica deployments need the same policy/HMAC key, acknowledged primary writes and a reviewed failover/write-concern policy; primary rollback can lose counters. Retained financial/source evidence remains unchanged and is not automatically pruned.

## Audit logging and abuse controls

`watchdawg.security` emits structured JSON to stdout with a server-generated request ID, UTC timestamp, fixed route alias, status and HMAC principal reference. Stream outcomes record completed/failed/cancelled separately; completion is logged only after successful message persistence. Logs never include tokens, token hashes, raw principal names, raw IPs, request paths/queries/bodies, provider exceptions, coordinates, connection strings or model output. Client-supplied request IDs are ignored. Validation and unhandled request errors are sanitized before server error logging.

Use the existing runtime's private log collector with permissions, disk/ingestion quotas, rotation, retention and alerts appropriate to the deployment. Stdout alone is not a durable append-only audit ledger, and this code cannot guarantee collector delivery. Application budgets cannot prevent connection floods, distributed denial of service or log-volume exhaustion at the network edge; the gateway/host controls remain necessary. Limit request headers at ingress, use the existing 256 KiB body cap and ten-second total body-read deadline, and retain provider/output bounds. No Redis, commercial identity service, WAF or new hosted infrastructure was added.

## Verification

- Full Python suite with disposable MongoDB: **217 passed, zero skipped**, six subtests passed.
- Built-container backend suite: **76 passed, zero skipped**. The non-root image contains exactly `server.py`, `providers.py`, and `security.py` under `/app/backend`, with no policy/token/test files baked in.
- Deterministic engine and all **24 Node tests** passed; public artifact build and frontend syntax passed. KEY-9 lint/build and production npm audit passed.
- Backend/utility flake8, Python compilation, `pip check`, runtime/development/KEY-9 Python dependency audits passed; audited sets report no known vulnerabilities. No new runtime dependencies were needed; existing hashed locks and runtime SBOM remain applicable.
- Supply-chain verification: zero errors, two inherited tag-only KEY-9/Sentinel base warnings. One inherited Starlette TestClient transport deprecation warning remains.
- Tests cover missing/invalid/expired credentials, health-only privilege escalation, role/header/body/query spoofing, forbidden publication scopes, rotation sharing a budget, global/peer budgets across clients, forwarded-IP bypass attempts, TLS/proxy trust, restricted CORS/preflight, duplicate credentials, malformed/deep/oversized requests, private log assertions, unsafe secret files, fail-closed storage, lease release after failure, and real atomic MongoDB budgets/leases across clients including stale-owner release. The test harness strips inherited production secret settings, installs private synthetic policy material and uses only synthetic providers/data.

## Remaining release gates

These controls are production-oriented, not production certification. Before deployment: approve service principal assignments and token delivery/rotation/revocation procedures; confirm host/TLS/proxy/firewall/CORS configuration; provision the narrow database role and assess replication/failover; configure durable private audit collection, log quotas and monitoring; validate backups/restore and evidence retention; assess browser/human authentication if needed; and approve any real provider endpoint/live conformance test. Static bearer tokens are replayable if stolen and are not MFA, end-user identity or delegated tenant authorization. Hardening cannot protect a compromised host or malicious process with the same UID.

No API privilege permits intelligence publication. Private coordinates, raw source provenance, offline snapshots, evidence-permission migration and human publication approval paths were preserved. No merge, deployment, paid-provider contact or production-data modification was performed.
