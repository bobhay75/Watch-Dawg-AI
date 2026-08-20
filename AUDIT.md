# Watch-Dawg AI audit — 2026-08-19

Verified defects addressed in this branch:

- Transaction type matching was case-sensitive, while Grow Vault emits `Deposit` and `Purchase`.
- Grow Vault purchase records use `gross`/`amount`; Watch-Dawg expected only `amount`.
- Invalid numeric values, negative amounts, and out-of-range allocation rates were insufficiently validated.
- Unknown transaction types could pass through without a clear review finding.
- No CI workflow ran the regression tests automatically.

The engine now normalizes the Grow Vault contract, validates transaction fields, audits purchase-side vaulting, and runs its regression suite in GitHub Actions.

## MVP expansion

- Added a polished Watch-Dawg dashboard for JSON audits, scenario loading, DAW scoring, anomaly review, balance snapshots, and audit report copying.
- Extended the deterministic engine with reusable `runWatchDawg`, `explainAudit`, ledger entries, sample scenarios, and richer review metadata.
- Expanded regression coverage for dashboard-facing ledger runs, anomaly reports, and invalid payload handling.

## ChatGPT integration

- Added a FastAPI backend endpoint at `/api/ai/audit` that streams ChatGPT analysis with GPT 5.4 Mini through the Emergent universal LLM key.
- The dashboard now automatically generates AI explanations, recommended next actions, and review-ready summaries after each user-run audit.
- AI audit messages are stored in MongoDB for session history while the deterministic Watch-Dawg result remains the source of truth.