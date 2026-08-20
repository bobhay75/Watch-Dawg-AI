# Watch-Dawg AI

Watch-Dawg AI is the audit and intelligence layer for transaction systems. It verifies allocation rules, reconciles balances, flags anomalies, and explains money movement.

The initial build is a deterministic audit engine and browser demo designed to integrate with Grow Vault.

## MVP features

- Transaction allocation audit for gross, vault rate, vaulted amount, and spendable amount.
- Ledger reconciliation for deposits, purchases, and vault withdrawals.
- DAW health score, anomaly review queue, audit trail table, and plain-English report.
- Automatic ChatGPT AI insights after each user-run audit, including explanations, next actions, and a review-ready summary.
- Built-in verified, ledger, and anomaly scenarios for fast testing.

## Run locally

Start the backend and frontend services:

```bash
cd backend && uvicorn server:app --host 0.0.0.0 --port 8001
cd frontend && yarn start
```

Then visit `http://localhost:3000`. The frontend proxies `/api` requests to the backend.

Required backend environment variables:

- `MONGO_URL`
- `DB_NAME`
- `EMERGENT_LLM_KEY`

Required frontend environment variables:

- `REACT_APP_BACKEND_URL`

## Test

```bash
node test.mjs
```
