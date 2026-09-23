# Watch-Dawg Website Evidence Audit — MVP Boundary

This slice strengthens the existing Sentinel HTTP observer. It does not introduce a second scanner and does not perform autonomous remediation.

## Trust model

The website audit path is:

1. declare authority and target scope;
2. collect a bounded HTTP observation;
3. preserve exact collected response-body bytes in append-only SHA-256 storage;
4. preserve a canonical capture manifest that references the response artifact;
5. preserve a content-addressed package manifest with one stable `package_ref`;
6. run deterministic checks against the observation;
7. expose coverage limits and deterministic findings;
8. allow interpretation or remediation proposals only downstream;
9. require separate authorization before any write or remediation action.

A target can set `require_content_addressed_evidence: true`. If no evidence store is configured, collection fails before the network request. This is the fail-closed mode for audit-grade targets.

## Evidence package v1

Each captured HTTP observation can expose `watch-dawg-evidence-package/v1` metadata containing:

- the SHA-256 reference for the exact bounded response bytes;
- the SHA-256 reference for the canonical HTTP capture manifest;
- a top-level SHA-256 `package_ref` for the package manifest;
- media type, source URL, capture time, byte count, and artifact type;
- explicit coverage metadata.

Stored artifacts are never overwritten. Reuse of an existing digest path requires re-hashing the existing file. A mismatch raises an integrity error.

This establishes integrity and linkage of the collected artifacts. It does **not** prove signer identity, exploitability, intent, or the truth of a business claim.

## Independent integrity verification

The verifier uses Python's standard library only and does not invoke the Watch-Dawg AI endpoint. It re-hashes the package, capture, and response-body artifacts and validates the package-to-capture-to-body linkage, target identity, capture time, coverage, body size, and source URL.

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

A successful verifier result is `VERIFIED_INTEGRITY`, not `VERIFIED_TRUTH`. Signature/authenticity verification remains a separate release gate.

## Current deterministic coverage

The existing HTTP pack can deterministically check:

- HTTP status against configured allowed statuses;
- response latency against a configured threshold;
- required and forbidden text markers;
- configured required response headers;
- selected JSON-LD offer-price conditions;
- response-body hash changes between observations;
- final landing URL changes between observations.

These findings remain `VERIFIED` observations of the collected material. Higher-level explanations must remain separate inference.

## Explicit MVP coverage limits

The first slice is intentionally narrow. A capture reports these limits instead of implying broader coverage:

- scope is one configured URL per HTTP target;
- authenticated areas are not tested by the HTTP pack;
- JavaScript execution/rendering is not performed;
- subresources are not collected by the HTTP pack;
- response bodies are bounded and may be marked truncated;
- screenshots are not captured in this slice;
- response headers are captured as the HTTP client's normalized header map, not as raw wire bytes;
- the local content-addressed store provides write-once-by-digest behavior in Watch-Dawg code, not filesystem WORM guarantees against a privileged host administrator;
- no exploit attempts, credential guessing, mutation, port scanning, or automatic remediation occurs;
- no claim is made that the current deterministic checks replace a specialized accessibility, CVE, penetration-testing, or browser-performance engine.

Existing DNS/TLS, sitemap, service exposure, secret exposure, access-log, and AI-system watch packs remain separate sources of deterministic observations.

## CLI usage

Use `sentinel/config.website-evidence.example.json` as the starting profile and run the normal Sentinel CLI with a state path. The CLI creates a content-addressed evidence store at `evidence_root` (default `.sentinel/evidence`) and passes it to the HTTP observer. Approved Sentinel API profiles use the same evidence-store path logic.

For audit-grade website targets, keep `require_content_addressed_evidence` enabled.

## Next release gates

Before this can be marketed as a complete Website Evidence Audit, require all of the following:

1. CI-green evidence-store, verifier, and HTTP integration tests.
2. A versioned receipt that signs or otherwise independently authenticates the package manifest; hashes alone establish integrity, not signer identity.
3. Browser-based collection for JavaScript-rendered DOM, network waterfall, console failures, and screenshots, with the same content-addressed storage rules.
4. Deterministic adapters for established tools such as axe-core/Lighthouse and approved security scanners rather than asking an LLM to reproduce their checks.
5. Machine-enforceable authorization profiles for any active or authenticated test mode.
6. A before/after verification receipt for authorized remediation workflows.
7. Stronger deployment storage controls if the commercial threat model requires resistance to privileged-host tampering.

Until those gates are met, this branch is an evidence-substrate hardening slice, not a claim of a finished commercial scanner.
