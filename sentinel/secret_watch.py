from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import Finding, Observation, stable_hash


MAX_FILES = 50
MAX_FILE_BYTES = 1_000_000
RULES = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "critical"),
    (
        "HARDCODED_SECRET",
        re.compile(
            r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
        ),
        "high",
    ),
)


class SecretExposureWatchPack:
    """Finds likely committed secrets while emitting only redacted evidence."""

    kind = "secret_exposure"
    allowed_authorization_modes = {"owner", "contract"}

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def observe(self, target: dict[str, Any]) -> Observation:
        paths = target.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ValueError("secret exposure target requires explicit file paths")
        if len(paths) > MAX_FILES:
            raise ValueError(f"secret exposure target may inspect at most {MAX_FILES} files")
        authorization = target.get("authorization", {})
        if not str(authorization.get("id", "")).strip():
            raise ValueError("secret exposure authorization requires a record id")
        approved_methods = authorization.get("approved_methods", [])
        if not isinstance(approved_methods, list) or "read-local-files" not in approved_methods:
            raise ValueError("secret exposure authorization must approve read-local-files")
        scope = authorization.get("scope")
        if not isinstance(scope, dict) or scope.get("paths") != paths:
            raise ValueError("secret exposure authorization paths must exactly match the target")
        expires_at = authorization.get("expires_at")
        if not isinstance(expires_at, str):
            raise ValueError("secret exposure authorization requires an expiration time")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("secret exposure authorization expiration must be ISO-8601") from exc
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("secret exposure authorization is expired or lacks a timezone")

        matches: list[dict[str, Any]] = []
        inspected: list[str] = []
        for raw_path in paths:
            candidate = (self.root / str(raw_path)).resolve()
            if candidate != self.root and self.root not in candidate.parents:
                raise ValueError("secret exposure path escapes the configured root")
            if not candidate.is_file():
                raise ValueError(f"secret exposure file does not exist: {raw_path}")
            if candidate.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"secret exposure file exceeds {MAX_FILE_BYTES} bytes: {raw_path}")
            relative = candidate.relative_to(self.root).as_posix()
            inspected.append(relative)
            text = candidate.read_text(encoding="utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), start=1):
                for rule_name, pattern, severity in RULES:
                    for match in pattern.finditer(line):
                        secret_value = match.group(1) if match.lastindex else match.group(0)
                        matches.append({
                            "path": relative,
                            "line": line_number,
                            "rule": rule_name,
                            "severity": severity,
                            "match_sha256": stable_hash(secret_value)[:16],
                        })
        return Observation(
            target_id=str(target["id"]),
            kind=self.kind,
            ok=True,
            facts={"files_inspected": inspected, "redacted_matches": matches},
            evidence=[f"file://redacted/{path}" for path in inspected],
        )

    def evaluate(
        self,
        target: dict[str, Any],
        current: Observation,
        previous: Observation | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in current.facts["redacted_matches"]:
            location = f"{match['path']}:{match['line']}:{match['match_sha256']}"
            findings.append(Finding(
                target_id=current.target_id,
                code=f"SECRET_EXPOSURE_{match['rule']}_{stable_hash(location)[:12]}",
                severity=match["severity"],
                title="Potential credential material is stored in an inspected file",
                detail="A secret-pattern rule matched. The value was hashed and omitted from all output.",
                evidence=match,
            ))
        return findings
