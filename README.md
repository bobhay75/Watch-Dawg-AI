# Watch-Dawg AI

Watch-Dawg AI is the audit and intelligence layer for transaction systems. It verifies allocation rules, reconciles balances, flags anomalies, and explains money movement.

The initial build is a deterministic audit engine and browser demo designed to integrate with Grow Vault.

## MVP features

- Transaction allocation audit for gross, vault rate, vaulted amount, and spendable amount.
- Ledger reconciliation for deposits, purchases, and vault withdrawals.
- DAW health score, anomaly review queue, audit trail table, and plain-English report.
- Automatic ChatGPT AI insights after each user-run audit, including explanations, next actions, and a review-ready summary.
- Built-in verified, ledger, and anomaly scenarios for fast testing.

## Reproducible Testing

The deterministic Watch-Dawg audit core can be reproduced without MongoDB, an LLM key, or any external service.

### Prerequisite

Use a current Node.js release with ES module support.

### 1. Clone the repository

```bash
git clone https://github.com/bobhay75/Watch-Dawg-AI.git
cd Watch-Dawg-AI
```

### 2. Run the automated audit-core tests

```bash
npm test
```

Equivalent direct command:

```bash
node test.mjs
```

Expected final output:

```text
Watch-Dawg tests passed
```

The test suite verifies:

- A correct 10% allocation is `VERIFIED`.
- Incorrect vault and spendable allocations are sent to `REVIEW`.
- Invalid numeric values and out-of-range allocation rates are rejected for review.
- Deposits, purchases, and vault withdrawals reconcile against opening balances.
- Unknown transaction types are flagged instead of silently accepted.
- A clean ledger produces a DAW score of `100`.
- The built-in anomaly scenario produces a `REVIEW` verdict, multiple human-review findings, and a DAW score below `100`.
- The plain-English audit report includes the review queue when anomalies exist.

### 3. Reproduce the browser demo

For the full browser demo, install the backend dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Set the backend environment variables:

```bash
export MONGO_URL='YOUR_MONGODB_URL'
export DB_NAME='watchdawg'
export EMERGENT_LLM_KEY='YOUR_KEY'
```

Set the frontend backend URL:

```bash
export REACT_APP_BACKEND_URL='http://localhost:8001'
```

Start the backend in one terminal:

```bash
cd backend
uvicorn server:app --host 0.0.0.0 --port 8001
```

Start the frontend in a second terminal from the repository root:

```bash
cd frontend
npm start
```

Open:

```text
http://localhost:3000
```

### 4. Reproduce the anomaly shown in the demo video

In the Watch-Dawg interface:

1. Click **Load Anomaly**.
2. Click **Run Watch-Dawg**.
3. Confirm the verdict changes to **REVIEW**.
4. Confirm the DAW score drops below 100 (the current built-in scenario produces **72**).
5. Confirm the human-review queue flags `GV-2001` for allocation mismatches and `GV-2003` as an unknown transaction type.
6. Confirm the audit explanation lists the review findings instead of silently correcting the records.

The built-in anomaly data is defined in `watchdawg.js`, and the same behavior is asserted in `test.mjs`, so judges can reproduce the result from both the UI and the automated test path.

## Run locally

Start the backend and frontend services:

```bash
cd backend && uvicorn server:app --host 0.0.0.0 --port 8001
cd frontend && npm start
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
npm test
```
