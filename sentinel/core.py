from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


SEVERITY_WEIGHTS = {
    "critical": 35,
    "high": 22,
    "medium": 12,
    "low": 5,
    "info": 0,
}
TRUTH_LABELS = {"VERIFIED", "INFERENCE"}
AUTHORIZATION_MODES = {"public", "owner", "contract"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    target_id: str
    code: str
    severity: str
    title: str
    detail: str
    truth: str = "VERIFIED"
    evidence: dict[str, Any] = field(default_factory=dict)
    stateful: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"unsupported severity: {self.severity}")
        if self.truth not in TRUTH_LABELS:
            raise ValueError(f"unsupported truth label: {self.truth}")

    @property
    def fingerprint(self) -> str:
        return stable_hash(f"{self.target_id}\0{self.code}")[:24]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        clean = dict(value)
        clean.pop("fingerprint", None)
        return cls(**clean)


@dataclass(frozen=True)
class Observation:
    target_id: str
    kind: str
    ok: bool
    facts: dict[str, Any]
    observed_at: str = field(default_factory=utc_now_iso)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Observation":
        return cls(**value)


class WatchPack(Protocol):
    kind: str
    allowed_authorization_modes: set[str]

    def observe(self, target: dict[str, Any]) -> Observation: ...

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]: ...


class StateStore:
    """Small atomic JSON state store for baselines and active findings."""

    VERSION = 1

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": self.VERSION, "targets": {}}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("version") != self.VERSION:
            raise ValueError("unsupported Sentinel state version")
        if not isinstance(payload.get("targets"), dict):
            raise ValueError("invalid Sentinel state")
        return payload

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)


class SentinelEngine:
    """Runs watch packs, diffs state, and emits only new or resolved findings."""

    def __init__(self, state_store: StateStore, packs: list[WatchPack]):
        self.state_store = state_store
        self.packs = {pack.kind: pack for pack in packs}

    def run(self, targets: list[dict[str, Any]]) -> dict[str, Any]:
        state = self.state_store.load()
        results = [self._run_target(target, state) for target in targets]
        self.state_store.save(state)
        return {
            "generated_at": utc_now_iso(),
            "notify": any(result["new_alerts"] or result["resolved"] for result in results),
            "targets_checked": len(results),
            "new_alert_count": sum(len(result["new_alerts"]) for result in results),
            "resolved_count": sum(len(result["resolved"]) for result in results),
            "results": results,
        }

    def _run_target(
        self,
        target: dict[str, Any],
        state: dict[str, Any],
    ) -> dict[str, Any]:
        target_id = str(target.get("id", "")).strip()
        kind = str(target.get("kind", "")).strip()
        if not target_id or not kind:
            raise ValueError("each target requires non-empty id and kind")
        pack = self.packs.get(kind)
        if pack is None:
            raise ValueError(f"no watch pack registered for kind: {kind}")

        target_state = state["targets"].get(target_id, {})
        previous_data = target_state.get("observation")
        previous = Observation.from_dict(previous_data) if previous_data else None
        prior_active = {
            key: Finding.from_dict(value)
            for key, value in target_state.get("active_findings", {}).items()
        }

        denial = self._authorization_denial(target, pack)
        if denial:
            current = Observation(
                target_id=target_id,
                kind=kind,
                ok=False,
                facts={"blocked": True, "reason": denial.detail},
            )
            findings = [denial]
        else:
            try:
                current = pack.observe(target)
                findings = pack.evaluate(target, current, previous)
            except Exception as exc:  # A pack failure becomes review evidence.
                current = Observation(
                    target_id=target_id,
                    kind=kind,
                    ok=False,
                    facts={
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:300],
                    },
                )
                findings = [
                    Finding(
                        target_id=target_id,
                        code="PACK_EXECUTION_FAILED",
                        severity="high",
                        title="Watch pack could not complete",
                        detail="The target was not fully observed; human review is required.",
                        evidence=current.facts,
                    )
                ]

        active = {
            finding.fingerprint: finding
            for finding in findings
            if finding.stateful
        }
        events = [finding for finding in findings if not finding.stateful]
        new_alerts = [
            finding.to_dict()
            for fingerprint, finding in active.items()
            if fingerprint not in prior_active
        ] + [finding.to_dict() for finding in events]
        resolved = [
            {
                **finding.to_dict(),
                "resolved_at": current.observed_at,
            }
            for fingerprint, finding in prior_active.items()
            if fingerprint not in active
        ]
        score = max(
            0,
            100 - sum(SEVERITY_WEIGHTS[item.severity] for item in findings),
        )
        verdict = self._verdict(findings)

        state["targets"][target_id] = {
            "observation": current.to_dict(),
            "active_findings": {
                fingerprint: finding.to_dict()
                for fingerprint, finding in active.items()
            },
        }
        return {
            "target_id": target_id,
            "kind": kind,
            "observed_at": current.observed_at,
            "verdict": verdict,
            "dawg_score": score,
            "current_findings": [item.to_dict() for item in findings],
            "new_alerts": new_alerts,
            "resolved": resolved,
        }

    @staticmethod
    def _authorization_denial(
        target: dict[str, Any],
        pack: WatchPack,
    ) -> Finding | None:
        authorization = target.get("authorization")
        mode = authorization.get("mode") if isinstance(authorization, dict) else None
        target_id = str(target.get("id", "unknown"))
        if mode not in AUTHORIZATION_MODES:
            return Finding(
                target_id=target_id,
                code="AUTHORIZATION_REQUIRED",
                severity="critical",
                title="Target blocked: authorization missing",
                detail="Declare public, owner, or contract authority before observation.",
            )
        if mode not in pack.allowed_authorization_modes:
            return Finding(
                target_id=target_id,
                code="AUTHORIZATION_SCOPE_DENIED",
                severity="critical",
                title="Target blocked: authority is insufficient",
                detail=f"The {pack.kind} pack does not permit authorization mode {mode}.",
            )
        return None

    @staticmethod
    def _verdict(findings: Any) -> str:
        severities = {finding.severity for finding in findings}
        if severities & {"critical", "high", "medium"}:
            return "REVIEW"
        if severities:
            return "WATCH"
        return "VERIFIED"
