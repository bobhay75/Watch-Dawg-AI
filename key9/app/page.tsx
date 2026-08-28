"use client";

import { useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  EyeOff,
  FileCheck2,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  ReceiptText,
  Route,
  ShieldCheck,
  Square,
  Terminal,
  UserCheck,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

type RunState = "idle" | "running" | "approval" | "complete" | "stopped";
type StepState = "waiting" | "active" | "done" | "approval";
type AgentMode = "unverified" | "sandbox" | "google-cloud";

type MissionStep = {
  title: string;
  detail: string;
  service: string;
  icon: typeof Route;
  protected?: boolean;
};

const STEPS: MissionStep[] = [
  {
    title: "Plan the closeout",
    detail: "Gemini converts the goal into six scoped, reversible actions.",
    service: "Gemini 3.5",
    icon: Route,
  },
  {
    title: "Read Watch-Dawg records",
    detail: "Collect timecards, materials, progress photos, and field notes.",
    service: "Watch-Dawg API",
    icon: Database,
    protected: true,
  },
  {
    title: "Collect missing receipts",
    detail: "Find three vendor receipts and attach them to the Johnson remodel.",
    service: "Google Drive",
    icon: ReceiptText,
    protected: true,
  },
  {
    title: "Reconcile the job",
    detail: "Match labor and materials; flag one $86.42 mismatch for review.",
    service: "D.A.W.G. Audit",
    icon: FileCheck2,
  },
  {
    title: "Prepare accounting export",
    detail: "Create a QuickBooks-ready package without posting financial data.",
    service: "Accounting bridge",
    icon: Terminal,
    protected: true,
  },
  {
    title: "Owner approval",
    detail: "Require a deliberate approval before any external write occurs.",
    service: "KEY-9 Policy",
    icon: Fingerprint,
  },
];

const VAULT_ITEMS = [
  {
    alias: "watchdawg.production",
    target: "api.watch-dawg.ai",
    scope: "jobs:read · audit:write",
    lease: "60 seconds",
    status: "Ready",
  },
  {
    alias: "drive.receipts",
    target: "Google Drive",
    scope: "receipts-folder:read",
    lease: "15 minutes",
    status: "Ready",
  },
  {
    alias: "accounting.export",
    target: "Accounting bridge",
    scope: "exports:create",
    lease: "Approval only",
    status: "Guarded",
  },
];

const AUDIT_ROWS = [
  ["14:07:13", "drive.receipts", "Read 3 files", "Allowed"],
  ["14:07:11", "watchdawg.production", "Read job #WD-1042", "Allowed"],
  ["14:07:09", "gemini-planner", "Created scoped plan", "Recorded"],
  ["Yesterday", "unknown-domain", "Requested secret reveal", "Blocked"],
];

function stateForStep(index: number, cursor: number, runState: RunState): StepState {
  if (runState === "complete") return "done";
  if (runState === "approval") {
    if (index < STEPS.length - 1) return "done";
    return "approval";
  }
  if (index < cursor) return "done";
  if (runState === "running" && index === cursor) return "active";
  return "waiting";
}

export default function Home() {
  const [goal, setGoal] = useState(
    "Close out the Johnson remodel. Gather the missing receipts, reconcile labor and materials, and prepare the accounting export."
  );
  const [runState, setRunState] = useState<RunState>("idle");
  const [cursor, setCursor] = useState(-1);
  const [requireApproval, setRequireApproval] = useState(true);
  const [sandbox, setSandbox] = useState(true);
  const [agentMode, setAgentMode] = useState<AgentMode>("unverified");
  const [agentSummary, setAgentSummary] = useState("");
  const runToken = useRef(0);

  const completed = useMemo(() => {
    if (runState === "complete") return STEPS.length;
    if (runState === "approval") return STEPS.length - 1;
    return Math.max(0, cursor);
  }, [cursor, runState]);

  const progress = Math.round((completed / STEPS.length) * 100);

  async function startMission() {
    const token = ++runToken.current;
    setRunState("running");
    setCursor(0);

    const agentRun = fetch("/api/agent", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ goal }),
    })
      .then(async (response) => {
        const data = (await response.json()) as { mode?: AgentMode; summary?: string; message?: string };
        if (!response.ok) throw new Error(data.message ?? "Agent request failed");
        setAgentMode(data.mode ?? "sandbox");
        setAgentSummary(data.summary ?? "");
      })
      .catch((error: unknown) => {
        setAgentMode("sandbox");
        setAgentSummary(error instanceof Error ? error.message : "Fail-closed sandbox used.");
      });

    for (let index = 0; index < STEPS.length - 1; index += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 620));
      if (runToken.current !== token) return;
      setCursor(index + 1);
    }

    await agentRun;

    if (requireApproval) {
      setRunState("approval");
      return;
    }

    await new Promise((resolve) => window.setTimeout(resolve, 620));
    if (runToken.current !== token) return;
    setRunState("complete");
    setCursor(STEPS.length);
  }

  function stopMission() {
    runToken.current += 1;
    setRunState("stopped");
  }

  function approveMission() {
    setRunState("complete");
    setCursor(STEPS.length);
  }

  function resetMission() {
    runToken.current += 1;
    setRunState("idle");
    setCursor(-1);
    setAgentSummary("");
  }

  const running = runState === "running";

  return (
    <main className="key9-shell">
      <header className="topbar">
        <a className="brand" href="#console" aria-label="Watch-Dawg KEY-9 home">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck />
          </span>
          <span>
            <strong>WATCH-DAWG</strong>
            <small>KEY-9</small>
          </span>
        </a>

        <div className="system-status" aria-label="System status">
          <span className="pulse-dot" />
          Policy engine armed
          <Badge className="hidden-secret-badge" variant="outline">
            <EyeOff /> 0 secrets exposed
          </Badge>
        </div>
      </header>

      <div className="workspace" id="console">
        <aside className="rail" aria-label="Security posture">
          <div className="rail-heading">
            <span>SECURITY POSTURE</span>
            <strong>LOCKED</strong>
          </div>

          <div className="posture-ring" aria-label="Protection score 100 percent">
            <span>100</span>
            <small>PROTECTED</small>
          </div>

          <div className="posture-list">
            <div><LockKeyhole /><span>Model isolation<small>Secrets never enter Gemini</small></span><CheckCircle2 /></div>
            <div><Clock3 /><span>Short leases<small>Automatic expiry enabled</small></span><CheckCircle2 /></div>
            <div><UserCheck /><span>Owner control<small>High-risk writes require you</small></span><CheckCircle2 /></div>
          </div>

          <div className="guardrail-card">
            <AlertTriangle />
            <div>
              <strong>Fail closed</strong>
              <p>If identity, scope, or target cannot be verified, KEY-9 does nothing.</p>
            </div>
          </div>

          <div className="rail-foot">
            <span>Runtime</span><strong>{agentMode === "google-cloud" ? "Google Cloud" : "Contest sandbox"}</strong>
            <span>Planner</span><strong>Gemini + ADK</strong>
          </div>
        </aside>

        <section className="console-panel">
          <div className="console-heading">
            <div>
              <p className="eyebrow"><Zap /> SECURE ACTION CONSOLE</p>
              <h1>Give the goal. <span>Never give the secret.</span></h1>
              <p>KEY-9 plans the work, borrows only the identity it needs, performs the approved action, and returns proof.</p>
            </div>
            <div className="mission-chip">
              <KeyRound />
              <span>MISSION ID<strong>KEY9-0828-1042</strong></span>
            </div>
          </div>

          <Tabs defaultValue="mission" className="product-tabs">
            <TabsList variant="line" className="product-tabs-list" aria-label="KEY-9 views">
              <TabsTrigger value="mission">Mission</TabsTrigger>
              <TabsTrigger value="vault">Vault aliases</TabsTrigger>
              <TabsTrigger value="audit">Audit trail</TabsTrigger>
            </TabsList>

            <TabsContent value="mission" className="tab-content">
              <div className="goal-box">
                <label htmlFor="mission-goal">What should Watch-Dawg finish?</label>
                <textarea
                  id="mission-goal"
                  value={goal}
                  onChange={(event) => setGoal(event.target.value)}
                  disabled={running}
                  rows={3}
                />

                <div className="goal-controls">
                  <label className="switch-label">
                    <Switch checked={requireApproval} onCheckedChange={setRequireApproval} disabled={running} />
                    Require owner approval
                  </label>
                  <label className="switch-label">
                    <Switch checked={sandbox} onCheckedChange={setSandbox} disabled={running} />
                    Sandbox connectors
                  </label>

                  <div className="action-buttons">
                    {runState === "approval" ? (
                      <Button className="bite-button" onClick={approveMission}>
                        <Fingerprint /> Approve final write
                      </Button>
                    ) : runState === "complete" || runState === "stopped" ? (
                      <Button className="bite-button" onClick={resetMission}>Reset mission</Button>
                    ) : (
                      <Button className="bite-button" onClick={startMission} disabled={running || !goal.trim()}>
                        <Zap /> {running ? "KEY-9 is working" : "Release KEY-9"}
                      </Button>
                    )}
                    {running && (
                      <Button className="stop-button" variant="outline" onClick={stopMission} aria-label="Stop mission">
                        <Square /> Stop
                      </Button>
                    )}
                  </div>
                </div>
              </div>

              <div className="mission-summary" aria-live="polite">
                <div>
                  <span>{runState === "idle" ? "READY" : runState === "approval" ? "WAITING FOR YOU" : runState.toUpperCase()}</span>
                  <strong>{runState === "complete" ? "Closeout package ready" : runState === "approval" ? "Final write held safely" : runState === "stopped" ? "Mission stopped; leases revoked" : running ? STEPS[cursor]?.title : "No credentials loaded"}</strong>
                </div>
                <div className="progress-wrap"><span>{progress}%</span><Progress value={progress} /></div>
              </div>

              <ol className="mission-steps">
                {STEPS.map((step, index) => {
                  const status = stateForStep(index, cursor, runState);
                  const Icon = step.icon;
                  return (
                    <li key={step.title} className={`mission-step ${status}`}>
                      <div className="step-icon">
                        {status === "done" ? <CheckCircle2 /> : status === "approval" ? <Fingerprint /> : <Icon />}
                      </div>
                      <div className="step-copy">
                        <div>
                          <strong>{step.title}</strong>
                          {step.protected && <Badge variant="outline"><EyeOff /> secret hidden</Badge>}
                        </div>
                        <p>{step.detail}</p>
                      </div>
                      <span className="service-tag">{step.service}</span>
                    </li>
                  );
                })}
              </ol>

              {runState === "complete" && (
                <div className="result-card">
                  <div className="result-icon"><FileCheck2 /></div>
                  <div>
                    <span>MISSION COMPLETE</span>
                    <h2>Johnson remodel closeout is ready.</h2>
                    <p>3 receipts matched · 18 time entries verified · 1 discrepancy flagged · 0 secrets exposed</p>
                    {agentSummary && <p className="agent-summary">{agentSummary}</p>}
                  </div>
                  <Badge className="proof-badge"><ShieldCheck /> Signed proof</Badge>
                </div>
              )}
            </TabsContent>

            <TabsContent value="vault" className="tab-content">
              <div className="section-intro">
                <div><p className="eyebrow"><KeyRound /> SECRET HANDLES ONLY</p><h2>The planner knows aliases—not credentials.</h2></div>
                <Badge className="hidden-secret-badge" variant="outline"><EyeOff /> Contents hidden</Badge>
              </div>
              <div className="vault-grid">
                {VAULT_ITEMS.map((item) => (
                  <article className="vault-card" key={item.alias}>
                    <div><LockKeyhole /><Badge variant={item.status === "Guarded" ? "secondary" : "outline"}>{item.status}</Badge></div>
                    <h3>{item.alias}</h3>
                    <dl>
                      <div><dt>Target</dt><dd>{item.target}</dd></div>
                      <div><dt>Scope</dt><dd>{item.scope}</dd></div>
                      <div><dt>Lease</dt><dd>{item.lease}</dd></div>
                    </dl>
                  </article>
                ))}
              </div>
              <div className="vault-rule"><ShieldCheck /><div><strong>Credential boundary</strong><p>Real values are injected after policy approval at the connector boundary. They never enter prompts, browser storage, or application logs.</p></div></div>
            </TabsContent>

            <TabsContent value="audit" className="tab-content">
              <div className="section-intro">
                <div><p className="eyebrow"><FileCheck2 /> TAMPER-EVIDENT PROOF</p><h2>Every bite leaves a receipt.</h2></div>
                <Badge variant="outline"><Clock3 /> Live trail</Badge>
              </div>
              <div className="audit-table-wrap">
                <table className="audit-table">
                  <thead><tr><th>Time</th><th>Identity</th><th>Action</th><th>Decision</th></tr></thead>
                  <tbody>
                    {AUDIT_ROWS.map((row) => (
                      <tr key={`${row[0]}-${row[1]}`}>
                        <td>{row[0]}</td><td><code>{row[1]}</code></td><td>{row[2]}</td>
                        <td><Badge variant={row[3] === "Blocked" ? "destructive" : "outline"}>{row[3]}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="audit-stats">
                <div><span>Secrets exposed</span><strong>0</strong></div>
                <div><span>Scoped actions</span><strong>12</strong></div>
                <div><span>Blocked requests</span><strong>1</strong></div>
                <div><span>Active leases</span><strong>0</strong></div>
              </div>
            </TabsContent>
          </Tabs>
        </section>
      </div>

      <footer className="app-footer">
        <span><ShieldCheck /> Secrets stay buried. Work gets done.</span>
        <span>Contest sandbox · No real credentials stored</span>
      </footer>
    </main>
  );
}
