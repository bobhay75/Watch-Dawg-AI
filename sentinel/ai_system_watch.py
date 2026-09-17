from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import Finding, Observation, stable_hash


MAX_MANIFEST_BYTES = 256_000
IMMUTABLE_REVISION = re.compile(r"^(?:sha256:[0-9a-f]{64}|[0-9a-f]{40})$")
SENSITIVE_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|credential)")
ALLOWED_SECRET_REFERENCES = ("secret://", "env://", "sm://")
HIGH_IMPACT_OPERATIONS = {
    "delete",
    "deploy",
    "execute",
    "financial-write",
    "identity-change",
    "message-external",
    "permission-change",
    "write",
}


def _parse_expiry(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} requires an expiration time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} expiration must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed <= datetime.now(timezone.utc):
        raise ValueError(f"{label} authorization is expired or lacks a timezone")
    return parsed


def _secret_value_paths(value: Any, prefix: str = "$") -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if SENSITIVE_KEY.search(str(key)) and isinstance(child, str):
                if child and not child.startswith(ALLOWED_SECRET_REFERENCES):
                    matches.append({
                        "path": path,
                        "value_sha256": stable_hash(child)[:16],
                    })
            matches.extend(_secret_value_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(_secret_value_paths(child, f"{prefix}[{index}]"))
    return matches


class AiSystemRiskWatchPack:
    """Evaluates an operator-owned AI control manifest without invoking a model."""

    kind = "ai_system"
    allowed_authorization_modes = {"owner", "contract"}

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def observe(self, target: dict[str, Any]) -> Observation:
        raw_path = str(target.get("manifest_path", "")).strip()
        if not raw_path:
            raise ValueError("AI system target requires manifest_path")
        authorization = target.get("authorization")
        if not isinstance(authorization, dict) or not str(authorization.get("id", "")).strip():
            raise ValueError("AI system target requires an authorization record id")
        methods = authorization.get("approved_methods", [])
        if not isinstance(methods, list) or "read-ai-manifest" not in methods:
            raise ValueError("AI system authorization must approve read-ai-manifest")
        scope = authorization.get("scope")
        if not isinstance(scope, dict) or scope.get("manifest_path") != raw_path:
            raise ValueError("AI system authorization path must exactly match the target")
        _parse_expiry(authorization.get("expires_at"), "AI system")

        candidate = (self.root / raw_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("AI system manifest path escapes the configured root")
        if not candidate.is_file():
            raise ValueError("AI system manifest does not exist")
        if candidate.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError(f"AI system manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        raw = candidate.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("AI system manifest must contain a JSON object")

        models = manifest.get("models", [])
        tools = manifest.get("tools", [])
        controls = manifest.get("controls", {})
        if not isinstance(models, list) or not isinstance(tools, list) or not isinstance(controls, dict):
            raise ValueError("AI system manifest models, tools, or controls have invalid types")
        resilience = controls.get("resilience", {})
        if not isinstance(resilience, dict):
            resilience = {}
        crypto_inventory = controls.get("crypto_inventory", [])
        if not isinstance(crypto_inventory, list):
            crypto_inventory = []
        safe_controls = {
            key: controls.get(key)
            for key in (
                "deny_unknown_tools",
                "network_egress",
                "prompt_injection_defense",
                "output_validation",
                "secrets_via_broker",
                "logging_redaction",
                "kill_switch",
                "model_change_approval",
                "vendor_inventory",
                "training_data_provenance",
            )
        }
        safe_controls["resilience"] = {
            "incident_runbook_present": bool(resilience.get("incident_runbook")),
            "rto_minutes": resilience.get("rto_minutes"),
            "rpo_minutes": resilience.get("rpo_minutes"),
            "restore_tested_at": resilience.get("restore_tested_at"),
        }
        safe_controls["crypto_inventory"] = [
            {
                "use": str(item.get("use", ""))[:80],
                "algorithm": str(item.get("algorithm", ""))[:80],
                "owner_present": bool(item.get("owner")),
                "migration_trigger_present": bool(item.get("migration_trigger")),
            }
            for item in crypto_inventory
            if isinstance(item, dict)
        ]
        facts = {
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "system_id": str(manifest.get("system_id", ""))[:100],
            "version": str(manifest.get("version", ""))[:40],
            "owner_present": bool(manifest.get("owner")),
            "purpose_present": bool(manifest.get("purpose")),
            "data_classification": str(manifest.get("data_classification", "unspecified"))[:40],
            "models": [
                {
                    "id": str(model.get("id", "unnamed"))[:100],
                    "provider": str(model.get("provider", "unspecified"))[:100],
                    "immutable_revision": str(model.get("revision", ""))[:80],
                    "remote_code": bool(model.get("trust_remote_code", False)),
                }
                for model in models
                if isinstance(model, dict)
            ],
            "tools": [
                {
                    "id": str(tool.get("id", "unnamed"))[:100],
                    "operations": sorted({str(item) for item in tool.get("operations", [])}),
                    "human_approval": bool(tool.get("human_approval", False)),
                }
                for tool in tools
                if isinstance(tool, dict)
            ],
            "controls": safe_controls,
            "embedded_secret_candidates": _secret_value_paths(manifest),
        }
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts=facts,
            evidence=[f"manifest://{candidate.relative_to(self.root).as_posix()}#{facts['manifest_sha256']}"],
        )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        facts = current.facts
        controls = facts["controls"]
        findings: list[Finding] = []

        if not facts["system_id"] or not facts["version"] or not facts["owner_present"] or not facts["purpose_present"]:
            findings.append(self._finding(current, "AI_ACCOUNTABILITY_METADATA_MISSING", "high", "AI system accountability metadata is incomplete", "The manifest requires system ID, version, owner, and purpose.", {"required": ["system_id", "version", "owner", "purpose"]}))
        if facts["data_classification"] == "unspecified":
            findings.append(self._finding(current, "AI_DATA_CLASSIFICATION_MISSING", "high", "AI data classification is not recorded", "The manifest must name the data classification before model or tool use.", {"control": "data_classification"}))
        if not facts["models"]:
            findings.append(self._finding(current, "AI_MODEL_INVENTORY_EMPTY", "high", "AI model inventory is empty", "At least one reviewed model dependency must be recorded.", {"control": "models"}))

        for model in facts["models"]:
            model_id = model["id"]
            if not IMMUTABLE_REVISION.fullmatch(model["immutable_revision"]):
                findings.append(self._finding(
                    current,
                    f"AI_MODEL_UNPINNED_{stable_hash(model_id)[:10]}",
                    "high",
                    "AI model revision is not immutable",
                    f"Model {model_id} lacks a full commit or SHA-256 revision.",
                    {"model_id": model_id, "provider": model["provider"]},
                ))
            if model["remote_code"]:
                findings.append(self._finding(
                    current,
                    f"AI_REMOTE_CODE_ENABLED_{stable_hash(model_id)[:10]}",
                    "critical",
                    "AI model may execute supplier-provided remote code",
                    f"Model {model_id} enables remote code trust.",
                    {"model_id": model_id, "provider": model["provider"]},
                ))

        for tool in facts["tools"]:
            high_impact = sorted(set(tool["operations"]) & HIGH_IMPACT_OPERATIONS)
            if high_impact and not tool["human_approval"]:
                findings.append(self._finding(
                    current,
                    f"AI_HIGH_IMPACT_TOOL_UNGATED_{stable_hash(tool['id'])[:10]}",
                    "critical",
                    "High-impact AI tool lacks a human approval gate",
                    f"Tool {tool['id']} declares high-impact operations without human approval.",
                    {"tool_id": tool["id"], "operations": high_impact},
                ))

        required = {
            "deny_unknown_tools": (True, "AI_UNKNOWN_TOOLS_NOT_DENIED", "high", "Unknown AI tools are not denied by default"),
            "network_egress": ("deny-by-default", "AI_EGRESS_NOT_DEFAULT_DENY", "high", "AI network egress is not deny-by-default"),
            "prompt_injection_defense": (True, "AI_PROMPT_INJECTION_CONTROL_MISSING", "high", "Prompt-injection controls are not recorded"),
            "output_validation": (True, "AI_OUTPUT_VALIDATION_MISSING", "high", "AI output validation is not recorded"),
            "secrets_via_broker": (True, "AI_SECRET_BOUNDARY_MISSING", "critical", "AI credentials are not confined to a broker"),
            "logging_redaction": (True, "AI_LOG_REDACTION_MISSING", "high", "AI log redaction is not recorded"),
            "kill_switch": (True, "AI_KILL_SWITCH_MISSING", "high", "AI kill switch is not recorded"),
            "model_change_approval": (True, "AI_MODEL_CHANGE_GATE_MISSING", "high", "Model changes lack an approval gate"),
            "vendor_inventory": (True, "AI_VENDOR_INVENTORY_MISSING", "medium", "AI vendor inventory is not recorded"),
            "training_data_provenance": (True, "AI_DATA_PROVENANCE_MISSING", "medium", "AI data provenance is not recorded"),
        }
        for key, (expected, code, severity, title) in required.items():
            if controls.get(key) != expected:
                findings.append(self._finding(
                    current,
                    code,
                    severity,
                    title,
                    f"The manifest must set controls.{key} to {expected!r}.",
                    {"control": key, "expected": expected},
                ))

        resilience = controls.get("resilience")
        if not isinstance(resilience, dict) or not resilience.get("incident_runbook_present"):
            findings.append(self._finding(current, "AI_INCIDENT_RUNBOOK_MISSING", "medium", "AI incident runbook is not recorded", "The manifest does not identify an incident runbook.", {"control": "resilience.incident_runbook"}))
        if not isinstance(resilience, dict) or not all(
            isinstance(resilience.get(key), int) and resilience[key] > 0
            for key in ("rto_minutes", "rpo_minutes")
        ):
            findings.append(self._finding(current, "AI_RECOVERY_OBJECTIVES_MISSING", "medium", "AI recovery objectives are not measurable", "Positive recovery-time and recovery-point targets are required.", {"controls": ["resilience.rto_minutes", "resilience.rpo_minutes"]}))
        tested_at = resilience.get("restore_tested_at") if isinstance(resilience, dict) else None
        try:
            restore_test = datetime.fromisoformat(str(tested_at).replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            restore_fresh = (
                restore_test.tzinfo is not None
                and now - timedelta(days=180) <= restore_test <= now
            )
        except ValueError:
            restore_fresh = False
        if not restore_fresh:
            findings.append(self._finding(current, "AI_RESTORE_TEST_STALE", "high", "AI recovery has not been tested recently", "The last recorded restore test is missing, invalid, or older than 180 days.", {"control": "resilience.restore_tested_at"}))

        crypto_inventory = controls.get("crypto_inventory")
        if not isinstance(crypto_inventory, list) or not crypto_inventory or any(
            not isinstance(item, dict)
            or not item.get("use")
            or not item.get("algorithm")
            or not item.get("owner_present")
            or not item.get("migration_trigger_present")
            for item in crypto_inventory
        ):
            findings.append(self._finding(current, "AI_CRYPTO_AGILITY_MISSING", "medium", "Cryptographic migration ownership is incomplete", "Inventory each cryptographic use, algorithm, accountable owner, and migration trigger.", {"control": "crypto_inventory"}))

        for candidate in facts["embedded_secret_candidates"]:
            findings.append(self._finding(
                current,
                f"AI_SECRET_EMBEDDED_{stable_hash(candidate['path'])[:10]}",
                "critical",
                "AI manifest may contain embedded credential material",
                "A credential-like field contains a value instead of an approved secret reference.",
                candidate,
            ))
        return findings

    @staticmethod
    def _finding(
        current: Observation,
        code: str,
        severity: str,
        title: str,
        detail: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return Finding(
            target_id=current.target_id,
            code=code,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
        )
