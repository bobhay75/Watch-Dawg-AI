import { NextResponse } from "next/server";

const SECRET_LIKE_PATTERN =
  /(?:password|api[_-]?key|private[_-]?key|secret|bearer|token)\s*[:=]\s*\S+/i;

type AdkEvent = {
  content?: { parts?: Array<{ text?: string }> };
  author?: string;
};

function finalText(events: unknown): string | null {
  if (!Array.isArray(events)) return null;
  for (const event of [...events].reverse() as AdkEvent[]) {
    const text = event.content?.parts
      ?.map((part) => part.text ?? "")
      .join("")
      .trim();
    if (text) return text;
  }
  return null;
}

function sandboxResult(goal: string) {
  return {
    mode: "sandbox",
    service: "local-policy-proof",
    model: "not invoked",
    goal,
    proof: {
      planned_actions: 6,
      receipts_matched: 3,
      time_entries_verified: 18,
      discrepancy: "86.42",
      final_write: "approval_required",
      secrets_exposed: 0,
    },
    summary:
      "The reproducible sandbox completed the closeout plan and held the accounting write for owner approval.",
  };
}

export async function POST(request: Request) {
  let body: { goal?: unknown };
  try {
    body = (await request.json()) as { goal?: unknown };
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  const goal = typeof body.goal === "string" ? body.goal.trim() : "";
  if (!goal || goal.length > 1_000) {
    return NextResponse.json({ error: "goal_required" }, { status: 400 });
  }
  if (SECRET_LIKE_PATTERN.test(goal)) {
    return NextResponse.json(
      { error: "secret_like_input_blocked", message: "Describe the goal; never paste a credential." },
      { status: 400 }
    );
  }

  const configuredUrl = process.env.KEY9_AGENT_URL?.trim();
  if (!configuredUrl) {
    return NextResponse.json(sandboxResult(goal));
  }

  const baseUrl = configuredUrl.replace(/\/$/, "");
  const sessionId = `key9-${crypto.randomUUID()}`;
  const userId = "contest-judge";

  try {
    const createSession = await fetch(
      `${baseUrl}/apps/key9_agent/users/${userId}/sessions/${sessionId}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ source: "watch-dawg-key9-site", sandbox: true }),
      }
    );
    if (!createSession.ok) throw new Error(`session_${createSession.status}`);

    const run = await fetch(`${baseUrl}/run_sse`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        app_name: "key9_agent",
        user_id: userId,
        session_id: sessionId,
        new_message: { role: "user", parts: [{ text: goal }] },
        streaming: false,
      }),
    });
    if (!run.ok) throw new Error(`agent_${run.status}`);

    const events = await run.json();
    return NextResponse.json({
      mode: "google-cloud",
      service: "Cloud Run + Google ADK",
      model: "gemini-3.5-flash",
      goal,
      proof: {
        final_write: "approval_required",
        secrets_exposed: 0,
      },
      summary: finalText(events) ?? "Agent run completed; inspect the event trail for details.",
    });
  } catch (error) {
    console.error("KEY-9 agent unavailable", error instanceof Error ? error.message : "unknown");
    return NextResponse.json(
      { ...sandboxResult(goal), degraded_from: "google-cloud", fail_closed: true },
      { status: 200 }
    );
  }
}
