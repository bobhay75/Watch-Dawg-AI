# Four-minute demo script

Target length: **3:40**. Record as one continuous, unedited take.

## 0:00–0:28 — The friction

“I am a contractor and solo builder. I lose time every day hunting through my
phone for the right password or API key before I can finish the work I was
already doing. Giving those credentials directly to an AI agent would be fast,
but dangerously wrong. KEY-9 lets the agent do the job while the secret stays
buried.”

Show the console headline and `0 secrets exposed` status.

## 0:28–0:55 — The boundary

Open **Vault aliases**.

“Gemini can see these names and permitted scopes. It cannot see the values.
Aliases are tied to an exact target, a short lease, and an approval policy. A
separate broker injects the credential only into the approved connector call.”

## 0:55–2:15 — Live proof of action

Return to **Mission** and click **Release KEY-9**.

Use the seeded goal: close out the Johnson remodel. Narrate the live steps:

- Gemini creates the bounded plan.
- KEY-9 reads Watch-Dawg field records.
- It collects three receipt records.
- It reconciles labor and materials.
- It surfaces the $86.42 mismatch.
- It prepares the accounting export.

At **Waiting for you**, emphasize that the agent stopped before the external
financial write.

## 2:15–2:40 — Human approval

Click **Approve final write**.

“The owner makes the consequential decision. KEY-9 completes the sandbox export
and returns a signed proof: three receipts, 18 time entries, one discrepancy,
and zero secrets exposed.”

## 2:40–3:05 — Blocked attack

Open **Audit trail** and point to the blocked secret-reveal request.

“A prompt cannot convince KEY-9 to disclose a password. The tool does not
exist, the policy forbids disclosure scopes, lookalike domains fail exact-host
checks, and unknown state means no action.”

## 3:05–3:32 — Architecture and Google Cloud proof

Show the architecture diagram, then the Cloud Run service and logs in Google
Cloud Console.

“The agent runs on Cloud Run with Google ADK and Gemini 3.5. Secret Manager is
behind the broker boundary. The public contest flow uses only seeded data, and
the repository contains ten security regression tests and reproducible setup.”

## 3:32–3:40 — Close

“Watch-Dawg KEY-9: secrets stay buried; work gets done.”
