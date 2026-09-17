from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import Finding, Observation, stable_hash


MAX_MANIFEST_BYTES = 256_000
MAX_MODELS = 32
MAX_TOOLS = 64
MAX_CRYPTO_ENTRIES = 64
MAX_OPERATIONS_PER_TOOL = 16
MAX_MANIFEST_DEPTH = 32
MAX_MANIFEST_NODES = 4_096
MAX_SECRET_CANDIDATES = 32
MAX_FINDINGS = 192
MAX_EVIDENCE_PATH_CHARS = 256
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
KNOWN_TOOL_OPERATIONS = HIGH_IMPACT_OPERATIONS | {
    "analyze",
    "draft",
    "read",
    "retrieve",
    "search",
    "summarize",
}
BOOLEAN_CONTROLS = (
    "deny_unknown_tools",
    "prompt_injection_defense",
    "output_validation",
    "secrets_via_broker",
    "logging_redaction",
    "kill_switch",
    "model_change_approval",
    "vendor_inventory",
    "training_data_provenance",
)
MODEL_KEYS = {"id", "provider", "revision", "trust_remote_code"}
TOOL_KEYS = {"id", "operations", "human_approval"}


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


def _read_manifest_beneath(root: Path, raw_path: str) -> tuple[str, bytes]:
    path = Path(raw_path)
    parts = path.parts
    if path.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("AI system manifest path escapes the configured root")

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    opened: list[int] = []
    directory_fd = root_fd
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        for part in parts[:-1]:
            directory_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | nofollow,
                dir_fd=directory_fd,
            )
            opened.append(directory_fd)
        file_fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=directory_fd)
        opened.append(file_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("AI system manifest must be a regular file")

        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError(f"AI system manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        return Path(*parts).as_posix(), raw
    except OSError as exc:
        raise ValueError("AI system manifest cannot be safely opened") from exc
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(root_fd)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("AI system manifest contains a duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"AI system manifest contains non-standard JSON constant {value}")


def _bounded_string(
    value: Any,
    label: str,
    *,
    maximum: int,
    required: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    clean = value.strip()
    if required and not clean:
        raise ValueError(f"{label} must be a non-empty string")
    if len(clean) > maximum:
        raise ValueError(f"{label} exceeds {maximum} characters")
    return clean


def _optional_manifest_string(
    container: dict[str, Any],
    key: str,
    *,
    maximum: int,
    default: str = "",
) -> str:
    if key not in container:
        return default
    return _bounded_string(container[key], key, maximum=maximum, required=False)


def _bounded_path(prefix: str, key: str) -> str:
    segment = re.sub(r"[^A-Za-z0-9_-]", "_", key)[:64] or "field"
    path = f"{prefix}.{segment}"
    if len(path) <= MAX_EVIDENCE_PATH_CHARS:
        return path
    suffix = stable_hash(path)[:12]
    return f"{path[:MAX_EVIDENCE_PATH_CHARS - 16]}...#{suffix}"


def _secret_value_paths(value: Any) -> tuple[list[dict[str, str]], int]:
    """Return bounded, path-only evidence for inline secret-like string fields."""

    matches: list[dict[str, str]] = []
    overflow = 0
    nodes = 0
    stack: list[tuple[Any, str, int]] = [(value, "$", 0)]
    while stack:
        current, prefix, depth = stack.pop()
        nodes += 1
        if nodes > MAX_MANIFEST_NODES:
            raise ValueError(f"AI system manifest exceeds {MAX_MANIFEST_NODES} JSON nodes")
        if depth > MAX_MANIFEST_DEPTH:
            raise ValueError(f"AI system manifest exceeds nesting depth {MAX_MANIFEST_DEPTH}")
        if isinstance(current, dict):
            if nodes + len(stack) + len(current) > MAX_MANIFEST_NODES:
                raise ValueError(f"AI system manifest exceeds {MAX_MANIFEST_NODES} JSON nodes")
            if current and depth == MAX_MANIFEST_DEPTH:
                raise ValueError(f"AI system manifest exceeds nesting depth {MAX_MANIFEST_DEPTH}")
            for key, child in reversed(list(current.items())):
                path = _bounded_path(prefix, key)
                if SENSITIVE_KEY.search(key) and isinstance(child, str):
                    if child and not child.startswith(ALLOWED_SECRET_REFERENCES):
                        candidate = {
                            "path": path,
                            "rule": "sensitive-key-with-inline-string",
                        }
                        if len(matches) < MAX_SECRET_CANDIDATES:
                            matches.append(candidate)
                        else:
                            overflow += 1
                stack.append((child, path, depth + 1))
        elif isinstance(current, list):
            if nodes + len(stack) + len(current) > MAX_MANIFEST_NODES:
                raise ValueError(f"AI system manifest exceeds {MAX_MANIFEST_NODES} JSON nodes")
            if current and depth == MAX_MANIFEST_DEPTH:
                raise ValueError(f"AI system manifest exceeds nesting depth {MAX_MANIFEST_DEPTH}")
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{prefix}[{index}]", depth + 1))
    return matches, overflow


def _validate_model(model: Any, index: int) -> dict[str, Any]:
    label = f"models[{index}]"
    if not isinstance(model, dict):
        raise ValueError(f"{label} must be an object")
    missing = MODEL_KEYS - model.keys()
    unexpected = model.keys() - MODEL_KEYS
    if missing:
        raise ValueError(f"{label} is missing required fields")
    if unexpected:
        raise ValueError(f"{label} contains unsupported fields")
    if type(model["trust_remote_code"]) is not bool:
        raise ValueError(f"{label}.trust_remote_code must be a boolean")
    return {
        "id": _bounded_string(model["id"], f"{label}.id", maximum=100),
        "provider": _bounded_string(model["provider"], f"{label}.provider", maximum=100),
        "immutable_revision": _bounded_string(
            model["revision"], f"{label}.revision", maximum=80
        ),
        "remote_code": model["trust_remote_code"],
    }


def _validate_tool(tool: Any, index: int) -> dict[str, Any]:
    label = f"tools[{index}]"
    if not isinstance(tool, dict):
        raise ValueError(f"{label} must be an object")
    missing = TOOL_KEYS - tool.keys()
    unexpected = tool.keys() - TOOL_KEYS
    if missing:
        raise ValueError(f"{label} is missing required fields")
    if unexpected:
        raise ValueError(f"{label} contains unsupported fields")
    if type(tool["human_approval"]) is not bool:
        raise ValueError(f"{label}.human_approval must be a boolean")
    operations = tool["operations"]
    if not isinstance(operations, list):
        raise ValueError(f"{label}.operations must be a list of strings")
    if not operations:
        raise ValueError(f"{label}.operations must not be empty")
    if len(operations) > MAX_OPERATIONS_PER_TOOL:
        raise ValueError(
            f"{label}.operations permits at most {MAX_OPERATIONS_PER_TOOL} entries"
        )
    normalized: set[str] = set()
    for operation_index, operation in enumerate(operations):
        operation_label = f"{label}.operations[{operation_index}]"
        canonical = _bounded_string(operation, operation_label, maximum=40).casefold()
        if canonical not in KNOWN_TOOL_OPERATIONS:
            raise ValueError(f"{operation_label} is not a recognized operation")
        normalized.add(canonical)
    return {
        "id": _bounded_string(tool["id"], f"{label}.id", maximum=100),
        "operations": sorted(normalized),
        "human_approval": tool["human_approval"],
    }


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

        relative_path, raw = _read_manifest_beneath(self.root, raw_path)
        try:
            manifest = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("AI system manifest is not valid bounded JSON") from exc
        if not isinstance(manifest, dict):
            raise ValueError("AI system manifest must contain a JSON object")

        embedded_secrets, secret_candidate_overflow = _secret_value_paths(manifest)

        models = manifest.get("models", [])
        tools = manifest.get("tools", [])
        controls = manifest.get("controls", {})
        if not isinstance(models, list) or not isinstance(tools, list) or not isinstance(controls, dict):
            raise ValueError("AI system manifest models, tools, or controls have invalid types")
        if len(models) > MAX_MODELS:
            raise ValueError(f"AI system manifest permits at most {MAX_MODELS} models")
        if len(tools) > MAX_TOOLS:
            raise ValueError(f"AI system manifest permits at most {MAX_TOOLS} tools")

        safe_models = [_validate_model(model, index) for index, model in enumerate(models)]
        safe_tools = [_validate_tool(tool, index) for index, tool in enumerate(tools)]
        model_ids = [model["id"].casefold() for model in safe_models]
        tool_ids = [tool["id"].casefold() for tool in safe_tools]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("AI system manifest model ids must be unique")
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("AI system manifest tool ids must be unique")

        for key in BOOLEAN_CONTROLS:
            if key in controls and type(controls[key]) is not bool:
                raise ValueError(f"controls.{key} must be a boolean")
        network_egress = controls.get("network_egress")
        if network_egress is not None:
            network_egress = _bounded_string(
                network_egress,
                "controls.network_egress",
                maximum=40,
                required=False,
            )

        resilience = controls.get("resilience", {})
        if not isinstance(resilience, dict):
            raise ValueError("controls.resilience must be an object")
        incident_runbook = _optional_manifest_string(
            resilience,
            "incident_runbook",
            maximum=160,
        )
        for objective in ("rto_minutes", "rpo_minutes"):
            if objective in resilience and type(resilience[objective]) is not int:
                raise ValueError(f"controls.resilience.{objective} must be an integer")
        restore_tested_at = _optional_manifest_string(
            resilience,
            "restore_tested_at",
            maximum=64,
        )

        crypto_inventory = controls.get("crypto_inventory", [])
        if not isinstance(crypto_inventory, list):
            raise ValueError("controls.crypto_inventory must be a list")
        if len(crypto_inventory) > MAX_CRYPTO_ENTRIES:
            raise ValueError(
                f"AI system manifest permits at most {MAX_CRYPTO_ENTRIES} crypto entries"
            )
        safe_crypto_inventory: list[dict[str, Any]] = []
        for index, item in enumerate(crypto_inventory):
            if not isinstance(item, dict):
                raise ValueError(f"controls.crypto_inventory[{index}] must be an object")
            use = _optional_manifest_string(item, "use", maximum=80)
            algorithm = _optional_manifest_string(item, "algorithm", maximum=80)
            owner = _optional_manifest_string(item, "owner", maximum=160)
            migration_trigger = _optional_manifest_string(
                item,
                "migration_trigger",
                maximum=240,
            )
            safe_crypto_inventory.append({
                "use": use,
                "algorithm": algorithm,
                "owner_present": bool(owner),
                "migration_trigger_present": bool(migration_trigger),
            })

        safe_controls = {key: controls.get(key) for key in BOOLEAN_CONTROLS}
        safe_controls["network_egress"] = network_egress
        safe_controls["resilience"] = {
            "incident_runbook_present": bool(incident_runbook),
            "rto_minutes": resilience.get("rto_minutes"),
            "rpo_minutes": resilience.get("rpo_minutes"),
            "restore_tested_at": restore_tested_at,
        }
        safe_controls["crypto_inventory"] = safe_crypto_inventory
        facts = {
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "system_id": _optional_manifest_string(manifest, "system_id", maximum=100),
            "version": _optional_manifest_string(manifest, "version", maximum=40),
            "owner_present": bool(_optional_manifest_string(manifest, "owner", maximum=160)),
            "purpose_present": bool(_optional_manifest_string(manifest, "purpose", maximum=500)),
            "data_classification": _optional_manifest_string(
                manifest,
                "data_classification",
                maximum=40,
                default="unspecified",
            ),
            "models": safe_models,
            "tools": safe_tools,
            "controls": safe_controls,
            "embedded_secret_candidates": embedded_secrets,
            "embedded_secret_candidate_overflow": secret_candidate_overflow,
        }
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts=facts,
            evidence=[f"manifest://{relative_path}#{facts['manifest_sha256']}"],
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
            type(resilience.get(key)) is int and resilience[key] > 0
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
        secret_overflow = facts.get("embedded_secret_candidate_overflow", 0)
        if type(secret_overflow) is int and secret_overflow > 0:
            findings.append(self._finding(
                current,
                "AI_SECRET_CANDIDATES_TRUNCATED",
                "critical",
                "Additional embedded-credential candidates were summarized",
                "The bounded evidence limit was reached; remove all inline secret-like values and review the source manifest.",
                {
                    "rule": "sensitive-key-with-inline-string",
                    "omitted_candidate_count": secret_overflow,
                    "reported_candidate_limit": MAX_SECRET_CANDIDATES,
                },
            ))

        if len(findings) > MAX_FINDINGS:
            omitted = len(findings) - (MAX_FINDINGS - 1)
            findings = findings[:MAX_FINDINGS - 1] + [self._finding(
                current,
                "AI_FINDINGS_TRUNCATED",
                "critical",
                "AI risk findings exceeded the bounded output limit",
                "Additional findings were summarized; the manifest requires human review.",
                {
                    "omitted_finding_count": omitted,
                    "reported_finding_limit": MAX_FINDINGS,
                },
            )]
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
