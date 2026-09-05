"""Output redaction utilities applied before logs or model-visible results."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any, Iterable


SENSITIVE_PATTERN = re.compile(
    r"(?i)(bearer\s+)[a-z0-9._~+\-/]+=*|"
    r"((?:api[_-]?key|password|secret|token)\s*[:=]\s*)[^\s,;]+"
)


def redact_text(value: str, known_secrets: Iterable[str] = ()) -> str:
    redacted = value
    variants: set[str] = set()
    for secret in (item for item in known_secrets if item):
        variants.add(secret)
        # A connector may return an already serialized JSON fragment. Cover
        # both UTF-8-preserving and ASCII-escaped forms before pattern matching.
        variants.add(json.dumps(secret, ensure_ascii=False)[1:-1])
        variants.add(json.dumps(secret, ensure_ascii=True)[1:-1])
    for variant in sorted((item for item in variants if item), key=len, reverse=True):
        redacted = redacted.replace(variant, "[REDACTED]")
    return SENSITIVE_PATTERN.sub(lambda match: f"{match.group(1) or match.group(2)}[REDACTED]", redacted)


def redact_payload(payload: Any, known_secrets: Iterable[str] = ()) -> Any:
    """Recursively redact values before serialization can transform secrets.

    Redacting a JSON string is insufficient because quotes, newlines, and
    backslashes are escaped during serialization. Walking the payload first
    preserves the exact secret bytes for matching and also covers dictionary
    keys, tuples, sets, bytes, and non-JSON objects.
    """
    secrets_tuple = tuple(str(item) for item in known_secrets if item)
    active: set[int] = set()

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value, secrets_tuple)
        if isinstance(value, bytes):
            return redact_text(value.decode("utf-8", errors="replace"), secrets_tuple)
        if value is None or isinstance(value, (bool, int, float)):
            return value

        identity = id(value)
        if identity in active:
            return "[REDACTED:CYCLE]"

        if isinstance(value, Mapping):
            active.add(identity)
            try:
                return {
                    redact_text(str(key), secrets_tuple): walk(item)
                    for key, item in value.items()
                }
            finally:
                active.remove(identity)

        if isinstance(value, (list, tuple, set, frozenset)):
            active.add(identity)
            try:
                return [walk(item) for item in value]
            finally:
                active.remove(identity)

        return redact_text(str(value), secrets_tuple)

    return walk(payload)
