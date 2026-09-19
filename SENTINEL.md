# Watch-Dawg Deep Audit Engine

Watch-Dawg is an authorized deep-audit and preventive-intelligence engine. Set it on a business, campaign, website, system, repository, workflow, document set, or data source and it looks for observable flaws, leaks, contradictions, missing controls, wasted effort, and preventable future failures. Sentinel is its continuous-observation layer, not the identity of the whole product.

The operating rule is **observe, prove, diagnose, improve, verify; human decides**. Every supported finding identifies the deficit, explains why it matters, proposes the smallest preventive correction, names the efficiency or prosperity lever, defines a success measure, and states how to verify the result. It never invents a dollar value: financial impact remains `NOT CALCULATED` until sufficient volume, cost, revenue, time, or conversion evidence exists.

## Swarm Defense device pilot

The optional `swarm_device` watch pack evaluates an authorized device snapshot
for package/process, permission, device-posture, network, and collection-coverage
signals. The Android pilot does not implement a device mesh; its signed schema
reports mesh disabled.
It is disabled unless a target explicitly sets `enabled: true`, requires an
unexpired owner/contract authorization whose device and path match exactly, and
accepts only `shadow` or `advisory` mode.

An owner-installed Android sensor can now collect signals exposed to an
ordinary app, pseudonymize package names on device, sign the canonical snapshot
with an Android Keystore ECDSA P-256 key, and submit it to the optional
`POST /v1/swarm/snapshot` ingest route over HTTPS. Ingest requires an exact
per-device token and enrolled public key, verifies a monotonic sequence, rejects
altered or older replay attempts, treats an exact already-accepted retry as
idempotent, and preserves each accepted signed payload, original device
signature, and server-HMAC-authenticated verification sidecar. The evaluator—not ingest—gates
stale or future telemetry before drawing conclusions. See
[`docs/ANDROID-SENSOR.md`](docs/ANDROID-SENSOR.md) for the
build, enrollment, consent, verification, and threat-model runbook.

Android does not expose reliable cross-app camera/microphone activity to an
ordinary app. Permission-plus-foreground correlation is therefore an
`INFERENCE`, not proof of sensor use. The pilot does not scan a network, record
media, inspect packets, install a VPN, block a process, change an account, patch
software, or execute a response. Any future containment action must pass the
existing human-approval boundary and an optional ProofPass adapter.

Run the harmless local example:

```bash
python -m sentinel.cli --config sentinel/config.swarm-shadow.example.json --state /tmp/watch-dawg-swarm-state.json
```

It does not promise to watch literally everything. It can watch nearly any observable source for which the operator has a public-data basis, ownership, or documented authorization and a safe connector.

## What this MVP watches

### Public website pack

- availability and unexpected HTTP status;
- response-time threshold changes;
- required or known-bad page text;
- landing-page redirects;
- bounded content fingerprints;
- configured response headers;
- JSON-LD event Offer prices, including the Black Oak zero-price defect.

The public fetcher performs one bounded request per configured target. It does not scan ports, submit forms, bypass access controls, or accept private, loopback, link-local, or reserved network targets.

### DNS and TLS pack

- public DNS resolution and address-set changes;
- TLS certificate expiry warning and critical windows;
- negotiated TLS-version policy;
- certificate subject, issuer, and expiry evidence.

The domain pack accepts only plain public hostnames, performs one DNS resolution and one ordinary TLS handshake, rejects non-public addresses, and treats DNS changes as one-time events rather than permanent alarms.

### Sitemap integrity pack

- XML sitemap and one-level sitemap-index parsing;
- bounded same-origin landing-page availability checks;
- broken URL and off-origin redirect detection;
- minimum URL-count checks;
- one-time URL-set change alerts without false recoveries.

The pack has explicit limits of at most 10 child sitemaps and 100 page URLs. It validates each public URL before fetching and never follows cross-origin sitemap entries.

### Owned traffic-log pack

- 5xx error-rate threshold;
- 401/403 volume;
- request-volume spikes between comparable samples;
- paths commonly associated with automated probing;
- parse coverage for Apache/Nginx combined logs.

Client IPs are hashed before entering observations. A probe-pattern match is labeled `INFERENCE`; it is not represented as proof of an attacker or compromise.

### Authorized service-exposure pack

- checks only an explicit list of at most 16 TCP ports on one public hostname;
- requires `owner` or `contract` authority with a record ID, exact host and port
  scope, approved `tcp-connect` method, and unexpired authorization;
- compares reachable ports with an approved open-service baseline;
- collects no banners and sends no exploit or authentication payloads.

This is bounded service discovery, not a general port scanner. Port ranges,
private-address targets, credential attempts, vulnerability exploitation,
evasion, persistence, and lateral movement are not supported.

### Authorized secret-exposure pack

- inspects only explicitly listed local files under a configured root;
- requires `owner` or `contract` authority, an authorization record ID, exact
  path scope, the approved `read-local-files` method, and an expiration time;
- limits each run to 50 files and each file to 1 MB;
- recognizes selected private-key, cloud-key, GitHub-token, and hard-coded
  secret patterns;
- emits only the rule, file, line, and a truncated SHA-256 fingerprint—not the
  credential itself.

This replaces password guessing with a defensible exposure audit. It does not
attempt logins, crack hashes, test passwords against remote services, or collect
the secret value in findings.

### Authorized AI-system risk pack

- reads one explicitly authorized JSON control manifest under a configured
  local root and never calls the AI model or its tools;
- requires an authorization record ID, exact manifest path, approved
  `read-ai-manifest` method, and unexpired `owner` or `contract` authority;
- records only a content hash and minimized control evidence;
- flags mutable model revisions, supplier-provided remote-code execution,
  ungated high-impact tools, unknown-tool or network-default-allow policies,
  missing prompt-injection and output-validation controls, embedded secrets,
  missing kill switch or model-change approval, vendor/provenance gaps,
  untested recovery objectives, and incomplete cryptographic migration
  ownership;
- redacts credential-like values and reports only their manifest path and a
  truncated fingerprint.

Use [`sentinel/config.ai-security.example.json`](sentinel/config.ai-security.example.json)
as the profile example. This is an evidence-based configuration audit, not a
model penetration test, behavior guarantee, certification, or substitute for
red-team and production monitoring.

## Evidence and noise control

Every finding has a stable fingerprint, severity, evidence, and one of two truth labels:

- `VERIFIED`: directly observed by a deterministic check;
- `INFERENCE`: an interpretation supported by observed evidence.

The state store remembers persistent findings. It emits those only when they are new or resolved. One-time changes such as a new page fingerprint, DNS address set, or sitemap URL set are emitted as events and do not create a fake recovery on the next run. The DAWG score is a review-priority signal, not a legal, financial, or security verdict.

## Authorization boundary

Every target must declare one mode:

- `public`: passive observation of public information;
- `owner`: a system or log controlled by the operator;
- `contract`: documented authority from the target owner.

The traffic-log pack rejects `public` mode. Missing or insufficient authority is blocked before the watch pack runs. Production deployments should add authenticated tenant ownership, signed scope records, rate limits, retention rules, and an allowlist. KEY-9 should broker future credentials so monitors can use a capability without receiving or storing the underlying secret.

## Run it

The original watch packs use the standard library. Verified Android ingest
adds the pinned `cryptography` dependency:

```bash
python -m pip install --requirement sentinel/requirements.txt
```

Run Sentinel:

```bash
python -m sentinel.cli \
  --config sentinel/config.example.json \
  --state .sentinel/state.json
```

Run the Black Oak proof pack:

```bash
python -m sentinel.cli \
  --config sentinel/examples/black-oak.json \
  --state .sentinel/black-oak-state.json
```

Run tests:

```bash
python -m unittest discover -s sentinel/tests -v
```

Run the example AI control review:

```bash
python -m sentinel.cli \
  --config sentinel/config.ai-security.example.json \
  --state .sentinel/ai-security-state.json
```

Verify repository supply-chain boundaries:

```bash
python scripts/verify_supply_chain.py
```

The verifier fails on non-SHA-pinned third-party GitHub Actions, unpinned Python
requirements, missing Node lockfiles, and floating `latest` container bases. A
versioned container base without a digest is reported as a warning so the
remaining provenance gap is visible rather than hidden.

## Restricted API

`sentinel.api` exposes the engine to an authenticated server-side caller without
accepting caller-supplied URLs or targets. A request may name only a profile that
the server operator mapped to a reviewed JSON configuration file.

Security controls in the first service boundary:

- a bearer token of at least 32 characters is required for every run;
- profile names and configuration paths are server-owned and fail closed;
- configuration paths cannot escape the configured root;
- `/v1/run` bodies are limited to 2 KiB and may contain only `profile`;
- the optional `/v1/swarm/snapshot` route is absent until at least one device
  enrollment is configured; it has a separate 512 KB limit, per-device token,
  signature, strict-schema, replay, immutable-history, and rate-limit boundary;
- a process-wide request limit and per-profile cooldown bound repeat observation;
- simultaneous runs of one profile are rejected to protect its state file;
- responses are non-cacheable and return defensive browser headers;
- no CORS access is enabled, so the bearer token is not placed in the static demo;
- `/healthz` is public but reports only service health and the profile count.

Example server configuration:

```bash
export SENTINEL_API_TOKEN="replace-with-a-random-secret-of-at-least-32-characters"
export SENTINEL_CONFIG_ROOT="sentinel/examples"
export SENTINEL_PROFILES_JSON='{"black-oak-public":"black-oak.json"}'
export SENTINEL_STATE_ROOT=".sentinel/api-state"
python -m sentinel.api
```

Run an approved profile from a trusted server-side client:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"profile":"black-oak-public"}' \
  http://127.0.0.1:8080/v1/run
```

The container is intentionally unconfigured by default. Build it with
`docker build -f sentinel/Dockerfile -t watch-dawg-sentinel-api .`, then inject
the token and approved profile mapping through the deployment platform. Do not
place the bearer token in GitHub Pages, browser JavaScript, source control, or a
public configuration file.

The built-in limiter and file-backed state are intentionally single-instance.
Before horizontal scaling or Internet exposure, place the service behind a
managed HTTPS proxy with a shared rate limit and request timeout, and move state
to durable storage with cross-instance locking.

## Human-approved financial correction plans

The deterministic JavaScript audit core can prepare corrections for valid
deposit-allocation mismatches. A plan is bound to the exact source ledger and
its proposed changes with SHA-256 digests. Application requires an exact plan
digest, an `APPROVE` decision, and a named human approver. The result is a
corrected in-memory copy plus a receipt; Watch-Dawg never writes to a bank,
accounting system, or external financial record.

Unknown transaction types and invalid financial fields remain in the manual
review queue.

## Government evaluation readiness

The current customer-managed pilot boundary, evidence bundle, candidate NIST
control crosswalk, and remaining authorization gates are documented in
[`docs/GOVERNMENT-READINESS.md`](docs/GOVERNMENT-READINESS.md). These artifacts
support evaluation; they do not claim FedRAMP, FISMA, FIPS, CMMC, Section 508,
or agency authorization.

### Private staging on Cloud Run

The staging deployer keeps Cloud Run IAM enabled, removes `allUsers` and
`allAuthenticatedUsers` invoker bindings, creates a dedicated runtime identity,
stores a generated application token in Secret Manager, pins the deployed
revision to that exact secret version, and limits the service to one concurrent
request on at most one scale-to-zero instance. The smoke test proves anonymous
access is denied and then supplies Cloud Run identity through
`X-Serverless-Authorization` alongside Sentinel's application token.

Run this only from an authenticated Google Cloud Shell attached to the intended
project:

```bash
git clone https://github.com/bobhay75/Watch-Dawg-AI.git
cd Watch-Dawg-AI
export GOOGLE_CLOUD_PROJECT="bobsome1"
export SENTINEL_STAGING_DEPLOY=true
bash sentinel/scripts/deploy-cloud-run-staging.sh
```

The default `black-oak-staging` profile performs only bounded passive checks of
public Black Oak resources: five targets, five-second per-request timeouts, no
more than two child sitemaps, and no more than five sitemap landing pages. The
deployment does not connect the API to GitHub Pages or make it production-ready.
Its `/state` data remains ephemeral and can disappear whenever Cloud Run scales
to zero or replaces the instance.

## Expansion path

The core accepts additional watch packs without changing its alert contract. Next packs should be built in this order:

1. analytics pack for authorized Search Console, GA4, ad-platform, and ticketing data;
2. repository, CI, dependency, and deployment-health pack;
3. owner-installed host agent for process, disk, auth, firewall, and endpoint events;
4. public promotion, review, competitor, event, pricing, and reputation pack;
5. KEY-9-controlled response actions with human approval and redacted receipts.

The safe product promise is: **Watch-Dawg can deeply audit any authorized target its watch packs can observe, prove what changed, expose deficits and blind spots, formulate a measurable improvement plan, suppress repeat noise, and put the decision in human hands.**
