# Watch-Dawg Website Evidence Audit — MVP Boundary

This slice strengthens the existing Sentinel website-observation path. It does not perform autonomous remediation and it does not treat an AI model as an evidence source.

## Trust model

The website audit path is:

1. declare authority and target scope;
2. collect a bounded public/passive HTTP or browser observation;
3. preserve exact collected artifacts in append-only SHA-256 storage;
4. preserve canonical capture/package manifests with stable `package_ref` values;
5. independently re-hash and verify the evidence package;
6. run deterministic checks or separately content-addressed tool analyses;
7. expose coverage limits, findings, incomplete checks, and untested areas;
8. optionally issue a ProofPass v1 receipt over the already-verified package;
9. allow AI interpretation or remediation proposals only downstream;
10. require separate authorization before any write or remediation action.

## HTTP evidence package v1

`watch-dawg-evidence-package/v1` can contain:

- the SHA-256 reference for the exact bounded response bytes;
- the SHA-256 reference for the canonical HTTP capture manifest;
- one stable top-level `package_ref`;
- source URL, capture time, media type, byte count, artifact type, and explicit coverage.

`require_content_addressed_evidence: true` fails closed before collection if no evidence store is configured. Stored digest paths are never overwritten by Watch-Dawg code; an existing digest path is re-hashed before reuse.

Independent verification:

```bash
python -m sentinel.evidence_verify \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<package-digest>
```

A successful HTTP verifier result is `VERIFIED_INTEGRITY`, not `VERIFIED_TRUTH`.

## Browser evidence package v1

The optional browser capability uses pinned Playwright/Chromium and produces `watch-dawg-browser-evidence-package/v1` with content-addressed:

- rendered DOM after `DOMContentLoaded` plus one bounded settle interval;
- viewport PNG screenshot;
- console/page-error events;
- bounded network response/failure metadata;
- browser egress policy decisions;
- browser capture manifest and top-level package manifest.

The production browser path performs no clicks, form submissions, credential injection, downloads, or remediation. Service workers are blocked and WebSockets are closed locally without an upstream connection.

### Browser egress boundary

Chromium is forced through a loopback Watch-Dawg egress proxy. For HTTP(S) destinations the proxy:

- accepts only the configured web-port allowlist (production default `80/443`);
- permits only `GET` and `HEAD` for plain HTTP requests;
- resolves the requested hostname once;
- rejects the entire hostname if any returned address is non-public;
- connects directly to the already-validated IP rather than resolving the hostname again;
- records allowed/blocked egress decisions into a content-addressed artifact.

The Playwright route layer remains a second independent policy check. Chromium loopback proxy bypass is disabled, QUIC is disabled, and non-proxied WebRTC UDP is constrained. The browser package verifier cross-checks its declared egress coverage against the verified egress artifact and requires the network artifact to reference that same egress artifact.

This closes the hostname-check-then-browser-resolve window inside the implemented browser path. It is still a process-level choke point, not a host firewall or privileged network namespace, so production infrastructure should add defense-in-depth egress controls around the worker.

Collection remains bounded: maximum 1920x1080 viewport, 2 MB rendered DOM, 250 requests, 500 network events, and 200 console events. The default viewport is 1440x900.

Capture and verify:

```bash
python -m sentinel.browser_capture capture \
  --evidence-root .sentinel/evidence \
  --target-id public-homepage-browser \
  --url https://example.com/

python -m sentinel.browser_capture verify \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<browser-package-digest>
```

A successful browser result is `VERIFIED_BROWSER_EVIDENCE`; it does not mean the page is safe, compliant, or truthful.

## Deterministic accessibility analysis with axe-core

The browser capture can optionally run the exactly pinned local axe-core engine on the already-loaded page:

```bash
python -m sentinel.browser_capture capture \
  --evidence-root .sentinel/evidence \
  --target-id public-homepage-browser \
  --url https://example.com/ \
  --axe-script sentinel/audit_tools/node_modules/axe-core/axe.min.js
```

Current review tooling pins `axe-core 4.13.0` with a committed npm lockfile. Raw rendered DOM and screenshot evidence are captured **before** the axe script is injected.

The axe adapter runs with iframe traversal disabled and asset preloading disabled. It requests detailed output only for `violations` and `incomplete`, applies deterministic size/node caps, and stores two additional content-addressed artifacts:

- the exact axe-core JavaScript bytes that executed;
- normalized `watch-dawg-axe-analysis/v1` output referencing the browser package and capture.

The axe result is deliberately **not** inserted into the raw browser evidence package. It is a derived analysis whose engine bytes and subject evidence can be independently verified. A successful verifier result is `VERIFIED_AXE_ANALYSIS`.

`VERIFIED_AXE_ANALYSIS` does not mean legal WCAG compliance. Confirmed axe rule failures remain tool findings; `incomplete` items require human review, and manual accessibility testing remains necessary.

## ProofPass receipt v1

ProofPass v1 adds an Ed25519 signature over an HTTP or browser evidence package that has already passed its independent verifier. The subject type is derived from the hashed package schema rather than caller input.

The receipt binds package type/ref, target, source URL, observation time, coverage, verified artifact references, issuer id/key fingerprint, issuance time, and limitations. The receipt does not appoint its own trust anchor; verification requires a separately supplied trusted public key.

A successful result is `VERIFIED_RECEIPT`. That establishes signature validity plus continued evidence-package integrity, not truth, exploitability, causation, intent, or business impact.

The local keypair helper is review/pilot infrastructure. Production signing should move to KMS/HSM or equivalent protected key custody.

## Current deterministic coverage

The existing HTTP pack can check:

- expected HTTP status and response latency;
- required/forbidden text markers;
- configured response headers;
- selected JSON-LD offer-price conditions;
- response-body and final-URL changes between observations.

The separate static HTML adapter examines exact verified HTML bytes with zero additional requests for:

- active/passive mixed content;
- HTTPS forms resolving to HTTP;
- password forms using GET;
- cross-origin form actions as review signals;
- missing page titles.

Bounded sitemap checks add same-origin page/status checking and off-origin redirect signals. The axe adapter adds deterministic accessibility-engine findings against a rendered page state while remaining a separately identified tool analysis.

## Explicit MVP limits

The current slice still has important boundaries:

- no authenticated scanning;
- no credentials, clicks, form submission, exploit attempts, credential guessing, mutation, port scanning, or automatic remediation;
- HTTP response bodies and browser event sets are bounded;
- normalized client headers are not raw wire bytes;
- browser network evidence is metadata, not a full HAR with every subresource body;
- screenshots are viewport-bounded;
- the process-level egress proxy is not equivalent to a host firewall/network namespace;
- local SHA-256 storage is not privileged-admin-resistant WORM storage;
- local ProofPass private keys are not HSM/KMS-backed;
- axe findings are not a substitute for manual accessibility review;
- Lighthouse and active security-engine adapters are not yet part of this evidence contract;
- no derived tool result is promoted to fact merely because the tool emitted it.

## Next release gates

Before marketing this as a complete Website Evidence Audit, require:

1. CI-green HTTP/browser evidence, egress, axe, ProofPass, verifier, and tamper tests.
2. Controlled production key management and issuer-trust policy.
3. Infrastructure-level egress isolation around the browser worker as defense in depth.
4. A human-reviewable audit package linking every finding/tool result to exact evidence and scope.
5. Before/after verification receipts for authorized remediation workflows.
6. Machine-enforceable authorization profiles before any authenticated/active test mode.
7. Stronger storage controls if the commercial threat model requires privileged-host tamper resistance.
8. Lighthouse/approved-security adapters only after their collection/network behavior is constrained to the same evidence and authorization standard.

Until those gates are met, this branch is review/pilot infrastructure—not a claim of a finished commercial scanner.
