# Watch-Dawg AI

**Watch-Dawg AI is a financial-loss prevention, audit, and secure-agent control layer for small contractors and field-service businesses.** It is built to catch money, documentation, transaction, and credential-use problems before they become lost revenue, missed deductions, disputes, bad records, or unsafe automation.

The product principle is simple: **work happens in the field, Watch-Dawg watches the records, and the DAWG flags what needs human attention.** The repository combines a deterministic audit core, an optional AI explanation layer, and the KEY-9 secure agentic credential broker.

## Current MVP

- Deterministic transaction-allocation audit for gross amount, allocation rate, protected/vaulted amount, and spendable amount.
- Ledger reconciliation for deposits, purchases, withdrawals, and unknown transaction types.
- DAW health score, anomaly review queue, audit trail, and plain-English report.
- Optional AI analysis with recommended next actions and a review-ready summary.
- MongoDB persistence for AI audit messages in the full-stack runtime.
- Built-in verified, ledger, and anomaly scenarios for reproducible testing.
- KEY-9 agentic credential broker with explicit policy gates, sandboxing, human approval, and redacted audit proof.

## Contractor direction

Watch-Dawg is being developed around a specific operating problem: small contractors often lose money because the work gets done faster than the paperwork gets captured.

The intended contractor workflow connects the audit core to jobsite records so Watch-Dawg can identify issues such as:

- purchases not assigned to the correct job;
- missing or unmatched receipts;
- labor lacking supporting daily documentation;
- customer-requested extra work without an approved change order;
- transaction or job-cost records that do not reconcile;
- exceptions that require owner or administrator review.

The operating rule is **detect first, explain why, and give the human a clear next action** rather than silently changing financial records.

## KEY-9 secure agentic credential broker

KEY-9 extends Watch-Dawg into secure agent execution. It is designed so an agent can request access to a protected capability without receiving the underlying secret directly.

The contest implementation includes:

- isolated broker and policy boundary;
- allow/deny policy evaluation;
- explicit human approval gates for sensitive actions;
- sandboxed execution path;
- redacted audit evidence that proves what happened without exposing credentials;
- executable trust-boundary security gates;
- Cloud Run deployment helpers and smoke tests.

The design goal is **use the credential without revealing the credential**.

## Reproducible testing

The deterministic Watch-Dawg audit core can be reproduced without MongoDB, an LLM key, or any external service.

### Prerequisite

Use a current Node.js release with ES module support.

### 1. Clone

```bash
git clone https://github.com/bobhay75/Watch-Dawg-AI.git
cd Watch-Dawg-AI
```

### 2. Run the audit-core tests

```bash
npm test
```

Expected final output:

```text
Watch-Dawg tests passed
```

The suite verifies that:

- a correct 10% allocation is `VERIFIED`;
- incorrect protected/vaulted and spendable allocations are sent to `REVIEW`;
- invalid numeric values and out-of-range allocation rates are rejected for review;
- deposits, purchases, and withdrawals reconcile against opening balances;
- unknown transaction types are flagged instead of silently accepted;
- a clean ledger produces a DAW score of `100`;
- the built-in anomaly scenario produces a `REVIEW` verdict, multiple human-review findings, and a DAW score below `100`;
- the plain-English audit report includes the review queue when anomalies exist.

### 3. Reproduce the browser demo

Install backend dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Set backend variables:

```bash
export MONGO_URL='YOUR_MONGODB_URL'
export DB_NAME='watchdawg'
export EMERGENT_LLM_KEY='YOUR_KEY'
```

Set frontend variables:

```bash
export HOST='0.0.0.0'
export PORT='3000'
export REACT_APP_BACKEND_URL='http://localhost:8001'
```

Never commit `.env` files, API keys, credentials, or service-account secrets.

Start the backend:

```bash
cd backend
uvicorn server:app --host 0.0.0.0 --port 8001
```

Start the frontend in another terminal from the repository root:

```bash
cd frontend
npm start
```

Open `http://localhost:3000`.

### 4. Reproduce the anomaly shown in the demo

1. Click **Load Anomaly**.
2. Click **Run Watch-Dawg**.
3. Confirm the verdict changes to **REVIEW**.
4. Confirm the DAW score drops below 100.
5. Confirm the human-review queue flags allocation mismatches and the unknown transaction type.
6. Confirm the explanation reports the findings instead of silently correcting records.

## Deployment model

The full Watch-Dawg AI application requires a runtime that can run the Node frontend proxy and FastAPI backend, plus MongoDB and the required environment variables. The Emergent-hosted runtime is the original full-stack MVP path.

GitHub Pages intentionally publishes **only** the deterministic browser demo (`index.html` and `watchdawg.js`). Backend code, tests, deployment helpers, and security internals are not included in the Pages artifact.

KEY-9 has a separate Cloud Run deployment path documented in the repository. The public Cloud Run contest service is intended to demonstrate the broker boundary and policy-controlled agent execution without exposing actual secrets.

## Validation

GitHub Actions now validates both runtime surfaces on pull requests and main-branch pushes:

```bash
npm test
node --check frontend/server.mjs
python -m compileall -q backend
python -m flake8 backend/server.py backend/tests/test_ai_audit_api.py
```

## Competition story

Watch-Dawg is strongest when presented as one system with two defensible layers:

1. **Operational audit:** detect financial and documentation loss before it compounds.
2. **Agent trust boundary:** let AI systems perform authorized work without handing them unrestricted secrets or silent authority.

That combination turns Watch-Dawg from a single-purpose demo into a broader **trust and control layer for AI-assisted small-business operations**.
