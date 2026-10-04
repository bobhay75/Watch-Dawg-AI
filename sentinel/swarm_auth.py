from __future__ import annotations

import re
from typing import Any, Final


MIN_DEVICE_TOKEN_LENGTH: Final[int] = 32
MAX_DEVICE_TOKEN_LENGTH: Final[int] = 256
DEVICE_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    rf"^[A-Za-z0-9_-]{{{MIN_DEVICE_TOKEN_LENGTH},{MAX_DEVICE_TOKEN_LENGTH}}}$"
)


def is_valid_device_token(token: Any) -> bool:
    """Accept one bounded, unambiguous Authorization-header representation."""

    return isinstance(token, str) and DEVICE_TOKEN_PATTERN.fullmatch(token) is not None
