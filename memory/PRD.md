# Watch-Dawg AI PRD

## Original problem statement
https://github.com/bobhay75/Watch-Dawg-AI

User direction: import/run the existing app, fix anything preventing it from working, build the repo concept into a working product, review the repo, and choose the best MVP path. Priority was making it run, fixing bugs, and using reasonable defaults.

## Architecture decisions
- Kept the repository as a lightweight static web app because the source project is a standalone deterministic JavaScript audit engine and browser demo.
- Used `watchdawg.js` as the reusable core audit module for allocation checks, ledger reconciliation, DAW scoring, sample scenarios, and report generation.
- Used `index.html` as the polished browser dashboard with no external backend/API requirement.
- Added a small FastAPI backend for secure ChatGPT integration so the LLM key never appears in browser code.
- Added a minimal frontend service wrapper that serves the static dashboard and proxies local `/api` calls to the backend using environment variables.
- Preserved simple Node regression testing through `test.mjs`.

## Implemented
- Polished Watch-Dawg dashboard with terminal-style audit console, scenario loading, DAW score, verdict metrics, balance snapshot, anomaly queue, ledger table, and audit report output.
- Expanded deterministic engine with `runWatchDawg`, `explainAudit`, richer ledger entries, sample scenarios, strict invalid payload handling, and preserved Grow Vault transaction compatibility.
- Integrated ChatGPT GPT 5.4 Mini using the Emergent universal LLM key for automatic explanations, next actions, and polished audit summaries after each user-run audit.
- Stored AI request/response messages in MongoDB under `ai_audit_messages`.
- Added regression tests for verified transactions, mismatches, Grow Vault contracts, ledger runs, anomaly runs, invalid payloads, and score/report behavior.
- Verified with Node tests, backend health/API checks, and browser automation at `http://localhost:3000`.

## Prioritized backlog
### P0
- Add persistent saved audit sessions if users need to revisit prior reviews.
- Add CSV import/export for real ledger files.
- Add an AI analysis history viewer that lets users reopen previous ChatGPT explanations.

### P1
- Add signed audit report downloads as PDF.
- Add configurable vault allocation rules per account/team.
- Add role-based review workflow for flagged transactions.

### P2
- Add trend charts for review rate, balance drift, and DAW score over time.
- Add integration adapters for Grow Vault or other transaction systems.
- Add optional AI-generated review summaries after deterministic checks complete.
