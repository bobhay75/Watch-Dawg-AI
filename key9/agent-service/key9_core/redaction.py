"""Output redaction utilities applied before logs or model-visible results."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable


SENSITIVE_PATTERN = re.compile(
    r"(?i)(bearer\s+)[a-z0-9._~+\-/]+=*|"
    r"((?:api[_-]?key|password|secret|token)\s*[:=]\s*)[^\s,;]+"
)


def redact_text(value: str, known_secrets: Iterable[str] = ()) -> str:
    redacted = value
    for secret in known_secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return SENSITIVE_PATTERN.sub(lambda match: f"{match.group(1) or match.group(2)}[REDACTED]", redacted)


def redact_payload(payload: Any, known_secrets: Iterable[str] = ()) -> Any:
    """Round-trip JSON-compatible data through the same redaction boundary."""
    serialized = json.dumps(payload, separators=(",", ":"), default=str)
    return json.loads(redact_text(serialized, known_secrets))
