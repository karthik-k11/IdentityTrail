"""Stable identity key helpers shared by ingestion and analysis."""

from __future__ import annotations

import base64
import binascii


def build_identity_key(
    principal_arn: str | None,
    principal_id: str | None,
    username: str | None,
) -> str | None:
    """Return a deterministic key for an event identity.

    The ARN is preferred because it is the most specific CloudTrail identity
    attribute. A principal ID is used next, then a username. Events with none of
    these attributes deliberately receive no identity key; they are never
    classified as an anonymous identity.
    """
    for prefix, value in (
        ("arn", principal_arn),
        ("pid", principal_id),
        ("user", username),
    ):
        if isinstance(value, str) and value.strip():
            return f"{prefix}|{value.strip()}"
    return None


def identity_display_name(
    username: str | None,
    principal_arn: str | None,
    principal_id: str | None,
) -> str:
    """Return a human-readable identity label without inventing a value."""
    if isinstance(username, str) and username.strip():
        return username.strip()
    if isinstance(principal_arn, str) and principal_arn.strip():
        return principal_arn.strip()
    if isinstance(principal_id, str) and principal_id.strip():
        return principal_id.strip()
    return "Not recorded"


def encode_identity_key(identity_key: str) -> str:
    """Encode a database identity key for use in a URL path."""
    return base64.urlsafe_b64encode(identity_key.encode("utf-8")).decode(
        "ascii"
    ).rstrip("=")


def decode_identity_key(token: str) -> str | None:
    """Decode a URL identity key, returning ``None`` when it is malformed."""
    if not token:
        return None
    padding = "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(token + padding)
        return decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
