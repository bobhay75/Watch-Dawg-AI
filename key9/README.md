# Watch-Dawg KEY-9

**Give the goal. Never give the secret.**

Watch-Dawg KEY-9 is a secure action broker for contractors and solo operators.
It lets an AI agent complete authenticated, multi-step work without exposing a
password, API key, session token, or service identity to the model, browser,
screen, or application logs.

- Track: **The Taskmaster**
- Built for: **All Things Agentic Hackathon 2026**
- Contest build began: **August 28, 2026**
- Primary stack: **Gemini 3.5 Flash, Google ADK, Cloud Run, Secret Manager**
- Web console: **https://watch-dawg-key9.thebobsomest1.chatgpt.site**

> Contest disclosure: Watch-Dawg AI existed before the contest and is used as
> an integration target and source of seeded contractor workflow data. The
> KEY-9 console, credential broker, fail-closed policy engine, Google ADK agent,
> tests, deployment configuration, and submission materials were created during
> the August 3–31, 2026 submission period.

## The friction

Passwords and API credentials interrupt real work. A contractor may bounce
among field records, receipt folders, vendor portals, accounting tools, and
cloud services just to close one job. Traditional password managers can fill a
login, but they do not understand the operational goal or complete the
workflow. Giving an AI agent unrestricted credentials creates a worse problem.

KEY-9 separates **reasoning** from **identity**:

1. The user states a goal.
2. Gemini plans the work and chooses allowlisted tools.
3. The policy engine validates the credential alias, exact target, requested
   scopes, time-to-live, and approval state.
4. Consequential writes stop at an approval boundary the model cannot call.
5. The broker atomically consumes a one-use lease before retrieving a secret.
6. The connector performs one scoped action and returns a recursively redacted result.
7. A unique, evidence-labeled audit receipt records what the connector reported.

The model sees the outcome. It never sees the secret.

## Proof-of-action mission

The reproducible contest mission is:

> Close out the Johnson remodel. Gather the missing receipts, reconcile labor
> and materials, and prepare the accounting export.

KEY-9 then:

- plans a bounded six-step mission;
- reads 18 time entries and 27 progress photos from seeded Watch-Dawg data;
- collects three receipt records through the `drive.receipts` alias;
- reconciles the receipt total against the material ledger;
- surfaces an $86.42 mismatch instead of hiding it;
- prepares an accounting-export preview; and
- holds the consequential external write while the public approval control records
  only a local sandbox simulation.

The public demonstration never stores or accepts real credentials and cannot
relay an owner-approval call to the agent service.

## Architecture

```mermaid
flowchart TD
    U["Contractor goal"] --> UI["KEY-9 console"]
    UI --> A["Gemini 3.5 + Google ADK"]
    A --> P["Fail-closed policy engine"]
    P -->|"alias + exact target + scope"| B["Credential broker"]
    B --> SM["Google Secret Manager"]
    B --> C["Scoped connector"]
    C --> W["Watch-Dawg / Drive / accounting sandbox"]
    C --> R["Redacted proof + audit trail"]
    R --> UI
```

The critical trust boundary is between the ADK tools and the credential broker.
Tool inputs contain only aliases such as `drive.receipts`; the Secret Manager
resource mapping is controlled by server configuration and cannot be selected
by the model.

## Security invariants

- **No model secret access:** prompts and tool results contain aliases only.
- **Exact target binding:** `api.watch-dawg.ai.attacker.example` is denied.
- **HTTPS only:** non-TLS targets are denied.
- **Scope allowlists:** unregistered capabilities are denied.
- **No disclosure scopes:** `secret:reveal`, `password:show`, and similar
  requests are always denied, even if a broader policy is added accidentally.
- **Short leases:** every credential use receives a capped expiry.
- **Single use:** invocation atomically and irreversibly consumes the lease before
  target validation, provider access, or connector execution—even on failure.
- **Invocation target binding:** the connector target is rechecked against the
  canonical host captured in the lease.
- **Owner approval:** the model-facing tool has no approval parameter; the public
  demo can only simulate approval, and production writes remain disabled until an
  authenticated owner-only flow exists.
- **Fail closed:** unknown alias, target, scope, lease, or state means no action.
- **Redacted output:** nested values, keys, bytes, escaped strings, known secrets,
  and common credential shapes are scrubbed before serialization or model access.
- **Production state guard:** process-local ADK sessions are rejected when sandbox
  mode is disabled.
- **Explicit context and hook policy:** accepted context sources are inventoried;
  implicit repository instructions and application-defined lifecycle hooks are denied.
- **Sandbox first:** the hosted contest UI uses non-sensitive seeded records.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for the threat model.

## Repository layout

```text
app/
  page.tsx                    Interactive KEY-9 mission console
  api/agent/route.ts          Server-side bridge to ADK with safe fallback
agent-service/
  agents/key9_agent/agent.py  Gemini 3.5 Google ADK agent and tools
  key9_core/policy.py         Exact-target, scope, approval, and TTL checks
  key9_core/broker.py         Consume-before-use secret injection
  key9_core/redaction.py      Recursive pre-serialization redaction
  key9_core/audit.py          Dynamic, evidence-labeled audit receipts
  key9_core/evidence.py       Authorized scan/patch evidence gate
  key9_core/workflow.py       Reproducible Watch-Dawg closeout tools
  tests/                      Security regression tests
  Dockerfile                 Cloud Run image
docs/
  ARCHITECTURE.md             Trust boundaries and event flow
  DEMO_SCRIPT.md              Four-minute unedited demo plan
  DEVPOST_SUBMISSION.md       Submission-ready project copy
  SECURITY_MODEL.md           Assets, threats, controls, limitations
security/
  context-manifest.json       Context origin, trust, role, and lifetime policy
  lifecycle-hook-policy.json  Default-deny executable hook policy
scripts/
  bootstrap-contest-cloud.sh One-command contest Cloud setup
  deploy-cloud-run.sh         Reproducible Google Cloud deployment
  smoke-cloud-run.sh          Health and ADK discovery checks
```

## Run the web console

Requirements:

- Node.js 22.13 or newer
- npm

```bash
npm ci --ignore-scripts
npm run dev
```

The console uses its deterministic sandbox until `KEY9_AGENT_URL` is set on the
server. Never put a Google API key or connector credential in a
`NEXT_PUBLIC_*` variable.

## Run and test the agent service

Requirements:

- Python 3.10 or newer

```bash
cd agent-service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. python -m unittest discover -s tests -v
export KEY9_BRIDGE_TOKEN="replace-with-a-long-random-server-only-value"
uvicorn main:app --host 127.0.0.1 --port 8080
```

Verify the local service:

```bash
curl http://127.0.0.1:8080/v1/health
curl -H "x-key9-bridge-token: $KEY9_BRIDGE_TOKEN" \
  http://127.0.0.1:8080/list-apps
```

Expected app list:

```json
["key9_agent"]
```

## Deploy to Google Cloud Run

Use a dedicated Google Cloud project or a dedicated service account with only
the permissions the demo needs. The agent can run against Vertex AI using the
Cloud Run service identity, so no Gemini API key is committed to the project.

```bash
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_RUN_REGION="us-central1"
export GOOGLE_CLOUD_LOCATION="global"
export KEY9_GEMINI_MODEL="gemini-3.5-flash"
export KEY9_BRIDGE_SECRET="key9-bridge-token"
export KEY9_SANDBOX_DEPLOY=true
./scripts/deploy-cloud-run.sh
```

The script enables the required APIs and deploys `agent-service/` as a
**publicly reachable, token-gated synthetic sandbox**. It refuses to run unless
that sandbox-only choice is explicit. It is not the production deployment path.
Before running it, create the named Secret Manager secret and grant the Cloud
Run service account access to that one secret. After deployment, set the
server-only `KEY9_AGENT_URL` and `KEY9_AGENT_TOKEN` values for the web console.
The token value must match the Secret Manager value; neither setting may use a
`NEXT_PUBLIC_*` name.

For the contest deployment, Google Cloud Shell can perform the complete API,
IAM, secret, and Cloud Run setup in one command sequence:

```bash
git clone --branch key9-contest https://github.com/bobhay75/Watch-Dawg-AI.git
cd Watch-Dawg-AI/key9
bash ./scripts/bootstrap-contest-cloud.sh
```

Cloud Run stays in `us-central1`, while Gemini 3.5 Flash uses Vertex AI's
`global` location. The bootstrap writes the Site bridge URL and server-only token
to `key9-sites-env.txt`; add those two values directly to the Site production
environment and never commit or share that file.

For production secrets, configure a server-only alias map whose values are
exact Secret Manager version resource names:

```json
{
  "watchdawg.production": "projects/PROJECT/secrets/watchdawg-api/versions/1",
  "drive.receipts": "projects/PROJECT/secrets/drive-receipts/versions/1",
  "accounting.export": "projects/PROJECT/secrets/accounting-export/versions/1"
}
```

Do not use `latest` for consequential production actions; pin and rotate an
explicit version so an audit record identifies the exact credential revision.

## Call the deployed ADK agent

The ADK API server exposes its standard session and run endpoints:

```bash
export KEY9_AGENT_URL="https://SERVICE-URL.run.app"
export KEY9_AGENT_TOKEN="the-private-bridge-token"

curl -X POST \
  "$KEY9_AGENT_URL/apps/key9_agent/users/demo/sessions/mission-1" \
  -H "content-type: application/json" \
  -H "x-key9-bridge-token: $KEY9_AGENT_TOKEN" \
  -d '{"sandbox": true}'

curl -X POST "$KEY9_AGENT_URL/run" \
  -H "content-type: application/json" \
  -H "x-key9-bridge-token: $KEY9_AGENT_TOKEN" \
  -d '{
    "app_name": "key9_agent",
    "user_id": "demo",
    "session_id": "mission-1",
    "new_message": {
      "role": "user",
      "parts": [{
        "text": "Close out the Johnson remodel. Gather the missing receipts, reconcile labor and materials, and prepare the accounting export."
      }]
    },
    "streaming": false
  }'
```

## Tests and current verification

- Web lint: passing
- Web production build: passing
- Policy, broker, workflow, evidence-gate, and trust-boundary tests: **30/30 passing**
- ADK server import: passing with `google-adk 2.8.0`
- ADK discovery: returns only `key9_agent`
- `/v1/health`: passing
- `/v1/security-posture`: passing

The Gemini-backed Cloud Run execution remains environment-dependent. The UI
identifies sandbox mode until that deployment is connected, and its approval
button never calls the Cloud Run approval endpoint.

## Honest limitations

- The contest demo uses seeded Watch-Dawg, receipt, and accounting records.
- The accounting connector prepares a sandbox preview; it does not modify a
  real QuickBooks account. The public approval control is simulation-only.
- Private Cloud Run IAM, workload identity for the server bridge, and
  authenticated owner approval are not implemented. The supplied deployment
  script is deliberately restricted to an explicitly selected public sandbox.
- Sandbox runs may use in-memory ADK sessions. Non-sandbox startup rejects
  `memory://`; a supported persistent session service must be configured and
  operationally tested before personal use.
- Audit receipts are dynamic and digest-bound, but remain process-local events;
  durable append-only storage, signing, and independent verification are absent.
- The Agent Control Standard mapping is preview-shaped metadata only. It is not
  conformance-tested.
- The context manifest and lifecycle-hook policy are checked repository
  contracts, not a complete runtime context-taint or hook-enforcement engine.
- The scan/patch evidence gate evaluates supplied lab evidence; it does not
  scan targets, execute exploits, generate patches, or approve releases.
- Stopping the web animation does not prove cancellation of an in-flight remote
  ADK run; server-side cancellation and status reconciliation remain future work.
- KEY-9 is not yet an Android Credential Provider, VPN, or general browser
  autofill replacement.
- This is a security architecture prototype, not an audited password manager.
  Do not place real personal passwords in the public contest demonstration.

## License

Copyright © 2026 Robert J. Hayes. All rights reserved during the hackathon.
