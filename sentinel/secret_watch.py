from __future__ import annotations

import re
import os
import stat
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


def _read_bounded_regular_file(root_fd: int, raw_path: str) -> tuple[str, bytes]:
    path = Path(raw_path)
    parts = path.parts
    if path.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("secret exposure path escapes the configured root")

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
            raise ValueError(f"secret exposure path is not a regular file: {raw_path}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise ValueError(f"secret exposure file exceeds {MAX_FILE_BYTES} bytes: {raw_path}")

        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError(f"secret exposure file exceeds {MAX_FILE_BYTES} bytes: {raw_path}")
        return Path(*parts).as_posix(), content
    except OSError as exc:
        raise ValueError(f"secret exposure file cannot be safely opened: {raw_path}") from exc
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


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
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for raw_path in paths:
                if not isinstance(raw_path, str) or not raw_path:
                    raise ValueError("secret exposure paths must be non-empty strings")
                relative, content = _read_bounded_regular_file(root_fd, raw_path)
                inspected.append(relative)
                text = content.decode("utf-8", errors="replace")
                for line_number, line in enumerate(text.splitlines(), start=1):
                    for rule_name, pattern, severity in RULES:
                        for _match in pattern.finditer(line):
                            occurrence_id = stable_hash(
                                f"{relative}\0{line_number}\0{rule_name}"
                            )[:16]
                            matches.append({
                                "path": relative,
                                "line": line_number,
                                "rule": rule_name,
                                "severity": severity,
                                "occurrence_id": occurrence_id,
                            })
        finally:
            os.close(root_fd)
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
            location = f"{match['path']}:{match['line']}:{match['occurrence_id']}"
            findings.append(Finding(
                target_id=current.target_id,
                code=f"SECRET_EXPOSURE_{match['rule']}_{stable_hash(location)[:12]}",
                severity=match["severity"],
                title="Potential credential material is stored in an inspected file",
                detail="A secret-pattern rule matched. The value was omitted from all output.",
                evidence=match,
            ))
        return findings
