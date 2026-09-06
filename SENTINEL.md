# Watch-Dawg Sentinel

Watch-Dawg Sentinel is the authorized cyber stakeout and change-monitoring layer for Watch-Dawg AI. It turns the existing **detect first, explain second, human decides** rule into a reusable monitoring engine.

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

The public fetcher performs one bounded request per configured target. It does not crawl, scan ports, submit forms, bypass access controls, or accept private, loopback, link-local, or reserved network targets.

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

The state store remembers persistent findings. It emits those only when they are new or resolved. One-time changes such as a new page fingerprint are emitted as events and do not create a fake recovery on the next run. The DAWG score is a review-priority signal, not a legal, financial, or security verdict.

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

## Expansion path

The core accepts additional watch packs without changing its alert contract. Next packs should be built in this order:

1. analytics pack for authorized Search Console, GA4, ad-platform, and ticketing data;
2. uptime, DNS, TLS-expiry, broken-link, sitemap, and structured-data pack;
3. repository, CI, dependency, and deployment-health pack;
4. owner-installed host agent for process, disk, auth, firewall, and endpoint events;
5. public promotion, review, competitor, event, pricing, and reputation pack;
6. KEY-9-controlled response actions with human approval and redacted receipts.

The safe product promise is: **Watch-Dawg can watch any authorized signal that a pack can observe, prove what changed, suppress repeat noise, and put the decision in human hands.**
