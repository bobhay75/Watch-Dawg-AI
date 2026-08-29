# Devpost submission copy

## Project name

Watch-Dawg KEY-9

## Tagline

Give the goal. Never give the secret.

## Category

The Taskmaster

## Inspiration

As a contractor and solo builder, I repeatedly interrupt real work to hunt
through phone settings for the right login or API key. Existing password
managers help fill one form, while AI agents can plan and execute whole
workflows. Connecting the two carelessly would expose every key to the model.
KEY-9 was built around a stricter idea: the agent should be able to use an
identity without ever possessing or revealing the credential.

## What it does

KEY-9 converts a contractor's goal into a bounded multi-step mission. Gemini
selects allowlisted tools, while a separate policy engine validates the secret
alias, exact destination, requested scopes, lease duration, and approval state.
The credential broker resolves and injects the secret only at the connector
boundary, redacts the result, revokes the lease, and returns proof.

The reproducible demo closes a seeded Watch-Dawg remodeling job: it gathers
field records, collects three receipts, reconciles labor and materials, flags an
$86.42 mismatch, prepares an accounting export, and stops for owner approval
before the external financial write.

## How we built it

- Gemini 3.5 Flash for planning and tool selection
- Google Agent Development Kit for the agent, sessions, and tool execution
- Google Cloud Run for the agent runtime
- Google Secret Manager adapter for versioned credentials
- A model-independent Python policy and credential-broker boundary
- Next.js/React for the responsive mission console
- Fourteen regression tests covering denial, exact-host checks, scope isolation,
  approvals, TTL limits, revocation, and redaction

## Challenges

The hardest design decision was refusing to make secret retrieval an agent tool.
If a model can retrieve the value, prompt instructions are not a sufficient
security boundary. KEY-9 instead lets the model name an approved capability and
keeps secret resolution in deterministic server code outside model context.

We also kept the demo honest: it uses seeded Watch-Dawg and accounting records,
labels sandbox execution visibly, and does not invite judges to submit real
credentials.

## Accomplishments

- A working end-to-end mission and server-isolated approval experience
- Google ADK agent with bounded contractor tools
- Exact-target, least-scope, short-lease authorization
- Single-use credential injection with redacted results
- Fail-closed degradation and a visible audit trail
- Reproducible tests and Cloud Run deployment configuration

## What we learned

For agent credentials, hiding the screen value is not enough. The model context,
tool schema, logs, error paths, destination validation, lease lifetime, and
approval boundary all matter. The safest useful abstraction is not “get my
password”; it is “perform this approved action against this exact target and
return sanitized proof.”

## What's next

- Android Credential Provider and quick-action integration
- User-owned Vaultwarden/Bitwarden-compatible storage option
- OAuth and short-lived workload identity instead of standing passwords
- Real Watch-Dawg receipt intake and accounting sandbox connectors
- Firestore-backed signed audit receipts and durable mission state
- Independent security review before storing personal secrets

## Links

- App: https://watch-dawg-key9.thebobsomest1.chatgpt.site
- Repository: https://github.com/bobhay75/Watch-Dawg-AI/tree/key9-contest/key9
- Demo: add public YouTube/Vimeo URL before submission
