# PR #29 development integration review

Reviewed against `feature/intelligence-brief-plan-2026-11-15` at `ada276cd445b0bed8d39d059fd245934453cce45`. The PR head before review was `35ce28cc607debcb7d7055e4d806273edf2a3a72`; fixes remain on `feature/legacy-backend-remediation`. No merge, deployment, production data access or paid-provider calls were performed.

## Finding fixed

**Medium — small SSE deltas were buffered until 8 KiB or EOF.** The provider requested `aiter_bytes(chunk_size=8192)`, which made HTTPX accumulate response bytes before yielding them. A syntactically complete small delta from an otherwise paused stream could not reach the client promptly, potentially causing an avoidable timeout. Existing complete-response mock tests did not exercise this behavior.

A new regression supplies one complete delta, then pauses indefinitely; the original code failed the bounded first-delta assertion. The provider now consumes network chunks as they arrive and internally slices them into bounded parser segments. Complete small deltas are yielded immediately. Partial lines and complete lines retain the 64 KiB cap; the overall response cap, event cap, output cap and provider timeouts remain in force. TLS verification, redirect refusal, generic error responses, exception redaction and explicit provider configuration are unchanged.

## GitHub and CI evidence

GitHub reported the initial head mergeable, and the development base is an ancestor of the feature head. Local merge-tree checks also found no conflicts. At the initial head all four applicable workflows completed successfully:

- Validate Watch-Dawg AI: run `44083878048`. Its backend-integration job passed hashed-lock installation, lint, all Python suites with real disposable MongoDB, both backend dependency audits, container build, exact image-file allowlist assertion and packaged API/database tests. Node and Python jobs also passed.
- Test Watch-Dawg: run `44083878049`, success.
- Build government evaluation evidence: run `44083878094`, success.
- Validate Watch-Dawg Sentinel: run `44083878265`, success.

The KEY-9 path-filtered workflow is not applicable to this PR's changed paths; its code/dependencies are unchanged. Backend/container CI is directly exercised by the applicable validation workflow. The review fix triggers new CI on a new head: do not substitute the initial head's green checks for the final head's status. The final integration decision must verify all applicable runs on the exact final SHA, as well as GitHub mergeability and any protected-branch requirements. No branch protection or review requirement was bypassed.

## Local validation

- Full Python suite with disposable MongoDB: **181 passed, zero skipped**, six subtests passed.
- Built-container backend tests: **40 passed, zero skipped** against synthetic provider and disposable MongoDB.
- Node deterministic suite and all **24 Node tests** passed; public asset build passed.
- Backend and disposable runner lint passed; supply-chain verification reports zero errors and the two inherited tag-only image warnings.
- Backend runtime and development lock audits report no known vulnerabilities. Packages and hashes did not change during this review. See the runtime SBOM and remediation report for audit scope and vendor dependency removal.
- One inherited Starlette TestClient transport deprecation warning remains; it is not a failed test or an advisory finding.

## Boundary review

- **Provider:** disabled by default; real adapter needs explicit server-side HTTPS endpoint, model and credential configuration. Tests use mock HTTP transport or the deterministic synthetic adapter, never a commercial endpoint. TLS verification is enabled, redirects/ambient proxies are refused, response buffers are bounded, and incomplete streams cannot claim successful completion. Provider exceptions are not retained in HTTP output or new system-error messages. Provider streams close on cancellation and early response closure.
- **Database:** real PyMongo async driver connects and closes in application lifespan with bounded timeouts. Disposable tests cover concurrent sessions, failed user/assistant inserts and recovery, startup failure, lifecycle restarts and retention of an existing synthetic record. The runner uses random names, loopback-only published ports and synthetic-mode/per-run guards. Only its own disposable resources are removed. No production URI, `.env`, persisted evidence or archaeological coordinates are loaded by the runner.
- **Container:** non-root user, digest-pinned backend base, hashed install, explicit runtime-file copies and exact `/app/backend` file allowlist assertion. The optional build-only CA secret preserves TLS verification and is not copied into the image. The image is built/tested locally, not published or deployed.
- **Evidence/publication:** this review changes only provider parsing, its regression test and review documentation. Intelligence ingestion, raw provenance, snapshot retention, private-coordinate handling, permission migration and human-publication approval paths remain unchanged. No success status or generated model text constitutes independent corroboration or publication approval.
- **Audits:** no dependency advisory waivers or TLS bypasses were introduced. The removed vendor SDK/custom wheel are not silently reintroduced. A clean candidate audit does not certify an untouched deployed legacy environment.

## Readiness decision

**Development:** suitable for integration into the intelligence development branch after all applicable checks pass on the final head and normal owner/reviewer approval is granted. This is a development-code review, not permission to perform the merge. No unaddressed development-blocking defect was found beyond the streaming issue fixed here.

**Production:** not approved. The API still has its inherited unauthenticated route contract and wildcard non-credentialed CORS policy. Production release requires authentication/authorization, rate limiting and network isolation; an approved provider endpoint and live conformance testing; deployment/database TLS and authorization checks; backup/restore, encryption and quotas; historical error-record review; and reviewer identity/publication controls. Explicit provider configuration migration and the intentional 256 KiB request limit also require operational handoff. MongoDB Community's SSPL obligations need review for database service distribution. Inherited image-pinning and test-transport follow-ups remain documented in `LEGACY-BACKEND-REMEDIATION.md`.
