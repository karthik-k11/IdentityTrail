"""Redaction and masking helpers for reports and investigation views."""

from __future__ import annotations

import re
from typing import Any


_SECRET_KEY_PATTERN = re.compile(
    r"(secret|password|passwd|token|credential|private[_-]?key|"
    r"session[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

_ACCESS_KEY_PATTERN = re.compile(r"access[_-]?key[_-]?id", re.IGNORECASE)

REDACTED = "[REDACTED]"


def mask_access_key(value: Any) -> str:
    """Mask an access-key identifier while keeping it comparable.

    Access-key IDs are identifiers rather than secrets, but masking them in
    reports and list views avoids unnecessary disclosure.
    """
    if not isinstance(value, str) or not value.strip():
        return "Not recorded"
    text = value.strip()
    if len(text) <= 8:
        return "****"
    return f"{text[:4]}...{text[-4:]}"


def redact_sensitive(value: Any) -> Any:
    """Return a recursively redacted copy of JSON-compatible data.

    Values under secret-like keys are replaced. Access-key identifiers are
    masked rather than removed so evidence remains comparable.
    """
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_PATTERN.search(key_text):
                result[key] = REDACTED
            elif _ACCESS_KEY_PATTERN.search(key_text):
                result[key] = mask_access_key(item)
            else:
                result[key] = redact_sensitive(item)
        return result

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]

    return value


def redact_json_text(value: Any) -> Any:
    """Return redacted data, wrapping non-dict/list values unchanged."""
    return redact_sensitive(value)
