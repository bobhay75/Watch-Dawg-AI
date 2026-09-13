# Watch-Dawg Deep Audit Engine

Watch-Dawg is an authorized deep-audit and preventive-intelligence engine. Set it on a business, campaign, website, system, repository, workflow, document set, or data source and it looks for observable flaws, leaks, contradictions, missing controls, wasted effort, and preventable future failures. Sentinel is its continuous-observation layer, not the identity of the whole product.

The operating rule is **observe, prove, diagnose, improve, verify; human decides**. Every supported finding identifies the deficit, explains why it matters, proposes the smallest preventive correction, names the efficiency or prosperity lever, defines a success measure, and states how to verify the result. It never invents a dollar value: financial impact remains `NOT CALCULATED` until sufficient volume, cost, revenue, time, or conversion evidence exists.

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

No new runtime dependency is required:

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

## Restricted API

`sentinel.api` exposes the engine to an authenticated server-side caller without
accepting caller-supplied URLs or targets. A request may name only a profile that
the server operator mapped to a reviewed JSON configuration file.

Security controls in the first service boundary:

- a bearer token of at least 32 characters is required for every run;
- profile names and configuration paths are server-owned and fail closed;
- configuration paths cannot escape the configured root;
- request bodies are limited to 2 KiB and may contain only `profile`;
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
