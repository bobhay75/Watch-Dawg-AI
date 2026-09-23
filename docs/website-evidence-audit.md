# Watch-Dawg Website Evidence Audit — MVP Boundary

This slice strengthens the existing Sentinel website-observation path. It does not perform autonomous remediation and it does not treat an AI model as an evidence source.

## Trust model

The website audit path is:

1. declare authority and target scope;
2. collect a bounded public/passive HTTP or browser observation;
3. preserve exact collected artifacts in append-only SHA-256 storage;
4. preserve a canonical capture manifest that references those artifacts;
5. preserve a content-addressed package manifest with one stable `package_ref`;
6. run deterministic checks against the verified evidence;
7. expose coverage limits and deterministic findings;
8. optionally issue a ProofPass v1 receipt over the already-verified `package_ref`;
9. allow interpretation or remediation proposals only downstream;
10. require separate authorization before any write or remediation action.

For the classic HTTP target, `require_content_addressed_evidence: true` fails closed before collection if no evidence store is configured.

## HTTP evidence package v1

Each captured HTTP observation can expose `watch-dawg-evidence-package/v1` metadata containing:

- the SHA-256 reference for the exact bounded response bytes;
- the SHA-256 reference for the canonical HTTP capture manifest;
- a top-level SHA-256 `package_ref` for the package manifest;
- media type, source URL, capture time, byte count, and artifact type;
- explicit coverage metadata.

Stored artifacts are never overwritten. Reuse of an existing digest path requires re-hashing the existing file. A mismatch raises an integrity error.

This establishes integrity and linkage of the collected artifacts. It does **not** prove signer identity, exploitability, intent, or the truth of a business claim.

## Independent HTTP integrity verification

The HTTP evidence verifier uses Python's standard library only and does not invoke the Watch-Dawg AI endpoint. It re-hashes the package, capture, and response-body artifacts and validates the package-to-capture-to-body linkage, target identity, capture time, coverage, body size, and source URL.

Verify in place:

```bash
python -m sentinel.evidence_verify \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<package-digest>
```

Export a small, reviewable packet after verification:

```bash
python -m sentinel.evidence_verify \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<package-digest> \
  --export ./verified-package
```

The export contains `package.json`, `capture.json`, `response-body.bin`, `verification.json`, and a short limitations notice. Export refuses a non-empty destination so it cannot silently replace unrelated material.

A successful HTTP evidence verifier result is `VERIFIED_INTEGRITY`, not `VERIFIED_TRUTH`.

## Browser evidence package v1

The browser path is an explicit optional capability backed by pinned Playwright/Chromium. It produces `watch-dawg-browser-evidence-package/v1` and content-addresses:

- the rendered DOM after `DOMContentLoaded` plus one bounded settle interval;
- one bounded viewport PNG screenshot;
- bounded console/page-error events;
- bounded network response/failure metadata;
- the browser capture manifest;
- the top-level browser package manifest.

The browser path performs no clicks, form submissions, credential injection, downloads, or remediation. Service workers are blocked. Every HTTP(S) browser request is checked before it is allowed to continue; private, loopback, link-local, and reserved destinations are rejected by the normal public-network URL validator. Browser requests using methods outside `GET`, `HEAD`, and `OPTIONS` are blocked.

Collection is capped at a 1920x1080 maximum viewport, a 2 MB rendered DOM, 250 requests, 500 network events, and 200 console events. The default viewport is 1440x900. The screenshot is viewport-bounded rather than full-page.

Capture:

```bash
python -m sentinel.browser_capture capture \
  --evidence-root .sentinel/evidence \
  --target-id public-homepage-browser \
  --url https://example.com/
```

Verify independently from the browser runtime:

```bash
python -m sentinel.browser_capture verify \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<browser-package-digest>
```

A successful browser verifier result is `VERIFIED_BROWSER_EVIDENCE`. That means the stored browser artifacts and manifest linkage verified; it does not mean the page is safe, compliant, or truthful.

The dedicated browser CI lane installs the pinned Playwright dependency and matching Chromium runtime and performs a real Chromium capture against a local fixture. The normal production validator still blocks loopback/private destinations; the fixture allowance exists only through test dependency injection and is not exposed through the CLI.

## ProofPass receipt v1

ProofPass v1 adds an Ed25519 signature over an HTTP **or browser** evidence package that has already passed its independent verifier. The subject type is derived from the hashed package schema rather than supplied by the caller, preventing a receipt from relabeling one evidence type as another.

The receipt binds:

- the exact `package_ref`;
- the package subject type;
- target id, final source URL, and observation timestamp;
- the package coverage statement;
- independently verified artifact references;
- an issuer id and public-key fingerprint;
- issuance time and explicit limitations.

The signature key is **not** embedded as a trust decision in the receipt. A verifier must supply the public key it already trusts. This prevents a receipt from manufacturing its own authority by carrying an arbitrary self-declared key.

Generate a review/test keypair outside source control:

```bash
python -m sentinel.proofpass_receipt generate-key \
  --private-key ./secrets/proofpass-private.pem \
  --public-key ./proofpass-public.pem
```

The private-key loader rejects symlinks, non-regular files, files owned by another local user, and files readable or writable by group/other users.

Issue a receipt only after the referenced package verifies:

```bash
python -m sentinel.proofpass_receipt sign \
  --evidence-root .sentinel/evidence \
  --package-ref sha256:<package-digest> \
  --private-key ./secrets/proofpass-private.pem \
  --issuer watch-dawg-review \
  --out ./proofpass-receipt.json
```

Verify both the signature and the still-present evidence package using an independently supplied public key:

```bash
python -m sentinel.proofpass_receipt verify \
  --evidence-root .sentinel/evidence \
  --receipt ./proofpass-receipt.json \
  --public-key ./proofpass-public.pem
```

A successful result is `VERIFIED_RECEIPT`. That means the supplied trusted public key validates the Ed25519 signature **and** the referenced evidence package still passes its independent verifier. It does not mean the website, a vulnerability claim, or a business allegation is true.

The v1 keypair helper intentionally writes an unencrypted local private key with restrictive permissions for controlled review/pilot use. Production should move signing into KMS/HSM or equivalent protected signing infrastructure rather than treating a shared-host filesystem key as a final trust anchor.

## Current deterministic coverage

The existing HTTP pack can deterministically check:

- HTTP status against configured allowed statuses;
- response latency against a configured threshold;
- required and forbidden text markers;
- configured required response headers;
- selected JSON-LD offer-price conditions;
- response-body hash changes between observations;
- final landing URL changes between observations.

The separate deterministic HTML-analysis adapter can inspect the exact verified HTML bytes with **zero additional network requests** for:

- active and passive mixed-content references;
- HTTPS forms that resolve to HTTP actions;
- password fields submitted with GET;
- cross-origin form actions as an informational review signal;
- missing page titles.

Existing bounded sitemap checks provide same-origin page/status checking and off-origin redirect signals.

These findings remain observations of collected material. Higher-level explanations must remain separate inference.

## Explicit MVP coverage limits

The current slice still has important boundaries:

- HTTP observation is one configured URL per HTTP target;
- browser capture is one navigation target per invocation;
- authenticated areas are not tested;
- no credentials, clicks, form submissions, exploit attempts, credential guessing, mutation, port scanning, or automatic remediation occur;
- HTTP response bodies are bounded and may be marked truncated;
- HTTP response headers are captured as the client's normalized header map, not raw wire bytes;
- browser network evidence stores bounded event metadata, not complete HAR archives or every subresource response body;
- browser screenshot evidence is viewport-bounded, not a full-page archival image;
- application-level DNS/public-address validation reduces SSRF risk but is not equivalent to production network-namespace or firewall egress isolation; a hardened browser worker should add infrastructure-level egress controls to close DNS-rebinding/TOCTOU exposure;
- the local content-addressed store provides write-once-by-digest behavior in Watch-Dawg code, not filesystem WORM guarantees against a privileged host administrator;
- local ProofPass private-key files are not equivalent to HSM/KMS-backed signing keys;
- current deterministic checks do not replace a specialized accessibility, CVE, penetration-testing, or browser-performance engine.

Existing DNS/TLS, sitemap, service exposure, secret exposure, access-log, and AI-system watch packs remain separate sources of deterministic observations.

## Next release gates

Before this can be marketed as a complete Website Evidence Audit, require all of the following:

1. CI-green HTTP evidence, browser evidence, verifier, ProofPass, and tamper tests.
2. Controlled key-management and issuer-trust policy for real customer receipts.
3. Infrastructure-level browser egress isolation in addition to application-level URL validation.
4. Deterministic adapters for established tools such as axe-core/Lighthouse and specifically authorized security scanners rather than asking an LLM to reproduce their checks.
5. Machine-enforceable authorization profiles for any active or authenticated test mode.
6. A before/after verification receipt for authorized remediation workflows.
7. Stronger deployment storage controls if the commercial threat model requires resistance to privileged-host tampering.
8. A human-reviewable pilot audit format that links every finding to its exact evidence artifact and coverage statement.

Until those gates are met, this branch is an evidence, browser-capture, and receipt-authenticity hardening slice—not a claim of a finished commercial scanner.
