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
- Authorized, explicit-port service exposure checks without banners, exploits,
  or credential attempts.
- Redacted local secret-exposure checks that never return matched credential
  values.
- SHA-256-bound financial correction proposals that recompute allowed changes,
  require a trusted approval verifier, and produce no external write.
- A government evaluator evidence bundle with source hashes, SPDX SBOM, test
  commands, and a candid control-gap crosswalk.
- Authorized, manifest-only AI-system risk review for immutable model revisions,
  remote-code trust, high-impact tool approval, prompt-injection defenses,
  output validation, brokered secrets, recovery objectives, and cryptographic
  migration ownership. It never invokes the reviewed model.
- A CI supply-chain gate that requires full commit-SHA pins for GitHub Actions,
  exact Python dependency versions, Node lockfiles, and reviewed OCI-index
  digests for both Python container bases.

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

Government-readiness evidence and the limits on all compliance claims are in
[`docs/GOVERNMENT-READINESS.md`](docs/GOVERNMENT-READINESS.md).
The draft customer-facing pilot scope is in
[`docs/CAPABILITY-STATEMENT.md`](docs/CAPABILITY-STATEMENT.md).

The AI control manifest is a review aid, not an assurance that a model is safe.
It records evidence for human review and deliberately excludes autonomous
exploitation, credential guessing, unrestricted tool use, and automatic
financial correction.

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
export WATCH_DAWG_AI_API_TOKEN='GENERATE_A_RANDOM_32_PLUS_CHARACTER_SECRET'
```

Set frontend variables:

```bash
export HOST='0.0.0.0'
export PORT='3000'
export REACT_APP_BACKEND_URL='http://localhost:8001'
export WATCH_DAWG_AI_API_TOKEN='THE_SAME_SERVER_SIDE_SECRET'
```

The frontend requires an individual operator session before it sends a paid audit
to the backend. The shared bearer credential is now only a service-to-service
secret: browser bearer headers are not accepted as operator authentication.
The deterministic demo remains usable without signing in.

Create an operator account outside the repository (the command prompts privately
for a unique passphrase and writes a 0600 file; it will not overwrite a file):

```bash
mkdir -p ~/.config/watch-dawg
python frontend/create_operator.py --username robert --output ~/.config/watch-dawg/operators.json
export WATCH_DAWG_USERS_FILE=~/.config/watch-dawg/operators.json
export WATCH_DAWG_PUBLIC_ORIGIN='http://localhost:3000'
export HOST='127.0.0.1'
```

For a private HTTPS deployment, set `WATCH_DAWG_PUBLIC_ORIGIN` to the exact HTTPS
origin without a trailing slash. Serve through a managed TLS reverse proxy; HTTP
is allowed only with a loopback origin and loopback bind address for development.
Backend traffic must use HTTPS or loopback HTTP. Open `/login.html`, sign in, then
return to the audit. The Operator account link also provides sign-out.

Accounts use unique salts and scrypt (N=131072, r=8, p=1). Session cookies are
HttpOnly, SameSite=Strict, Secure over HTTPS, and expire after 15 minutes. A new
login revokes the previous session for that account; logout revokes it immediately.
Login and paid audit writes require the configured Origin. Each operator is
limited to five paid requests per minute, within the backend's shared ceiling.
Password verification concurrency is bounded to limit memory use.

This is a private **single-process operator pilot**, with up to 20 configured
accounts. It provides no public registration, password-reset email, MFA or SSO.
Sessions and throttles are process-local: restart signs everyone out. To revoke
an operator or rotate a password, replace the protected configuration and restart
all frontend instances. Do not use multiple instances without shared session and
rate-limit storage. Before a government/public deployment, integrate the required
identity provider and MFA; this pilot does not establish certification.

Keep operator files, passwords, and service credentials out of git, browser
storage, logs, and the public web root. Never give a browser the backend token.
Both servers reject API bodies above 64,000 bytes before forwarding or parsing;
sign-in bodies are limited to 4,096 bytes, including chunked bodies.

Security references: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

Run the offline security checks (no account, database or paid model required):

```bash
node --test frontend/tests/*.test.mjs
python -m unittest backend.tests.test_request_boundary -v
```

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
