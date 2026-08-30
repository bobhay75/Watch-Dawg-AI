# Watch-Dawg AI

**Watch-Dawg AI is a financial-loss prevention and audit layer for small contractors and field-service businesses.** Its job is to catch money, documentation, and transaction problems before they become lost revenue, missed deductions, disputes, or bad records.

The product direction is simple: **work happens in the field, Watch-Dawg watches the records, and the DAWG flags what needs attention.** That includes transaction anomalies today and expands naturally into contractor workflows such as receipts, job-cost allocation, undocumented labor, and unapproved extra work.

The current repository contains the deterministic audit core and browser demo that power that mission. The earliest test scenarios were developed against Grow Vault-style transaction records, but the audit engine is intentionally reusable and is not limited to Grow Vault.

## Current MVP features

- Deterministic transaction-allocation audit for gross amount, allocation rate, protected/vaulted amount, and spendable amount.
- Ledger reconciliation for deposits, purchases, withdrawals, and unknown transaction types.
- DAW health score, anomaly review queue, audit trail table, and plain-English report.
- Automatic AI insights after each user-run audit, including explanations, recommended next actions, and a review-ready summary.
- Built-in verified, ledger, and anomaly scenarios for fast testing.

## Contractor product direction

Watch-Dawg is being developed around a specific operating problem: small contractors often lose money because the work gets done faster than the paperwork gets captured.

The intended contractor workflow connects the audit core to jobsite records so Watch-Dawg can help identify issues such as:

- purchases that are not assigned to the correct job;
- missing or unmatched receipts;
- labor that lacks supporting daily documentation;
- customer-requested extra work without an approved change order;
- transaction or job-cost records that do not reconcile;
- exceptions that require an owner or administrator to review them.

The principle is **detect first, explain why, and give the human a clear next action** rather than silently changing financial records.

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
- Incorrect protected/vaulted and spendable allocations are sent to `REVIEW`.
- Invalid numeric values and out-of-range allocation rates are rejected for review.
- Deposits, purchases, and withdrawals reconcile against opening balances.
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
