"""Normalization of individual CloudTrail events."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


def normalize_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a predictable normalized representation of a CloudTrail event.

    Missing or null optional fields are represented as ``None`` for scalar
    values, ``[]`` for resources, and ``{}`` for request/response parameters.
    The complete original event is preserved under ``raw_event``.

    The function does not infer that missing identity information is anonymous
    or unauthenticated; unknown values simply remain ``None``.
    """
    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping representing a CloudTrail event")

    user_identity = _as_mapping(event.get("userIdentity"))

    account_id = _string_or_none(event.get("recipientAccountId"))
    if account_id is None:
        account_id = _string_or_none(user_identity.get("accountId"))

    return {
        "event_id": _first_string(event, "eventID", "eventId"),
        "event_name": _string_or_none(event.get("eventName")),
        "event_source": _string_or_none(event.get("eventSource")),
        "event_time": _normalize_event_time(event.get("eventTime")),
        "aws_region": _string_or_none(event.get("awsRegion")),
        "account_id": account_id,
        "username": _extract_username(user_identity),
        "principal_arn": _string_or_none(user_identity.get("arn")),
        "principal_id": _string_or_none(user_identity.get("principalId")),
        "identity_type": _string_or_none(user_identity.get("type")),
        "access_key_id": _string_or_none(user_identity.get("accessKeyId")),
        "source_ip": _string_or_none(event.get("sourceIPAddress")),
        "user_agent": _string_or_none(event.get("userAgent")),
        "resources": _list_copy(event.get("resources")),
        "request_parameters": _mapping_copy(event.get("requestParameters")),
        "response_elements": _mapping_copy(event.get("responseElements")),
        "error_code": _string_or_none(event.get("errorCode")),
        "error_message": _string_or_none(event.get("errorMessage")),
        "read_only": _bool_or_none(event.get("readOnly")),
        "management_event": _bool_or_none(event.get("managementEvent")),
        "raw_event": copy.deepcopy(dict(event)),
    }


def _first_string(event: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _string_or_none(event.get(key))
        if value is not None:
            return value
    return None


def _normalize_event_time(value: Any) -> str | None:
    text = _string_or_none(value)
    if text is None:
        return None

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return text

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_username(user_identity: Mapping[str, Any]) -> str | None:
    return _string_or_none(user_identity.get("userName"))


def _string_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value != "":
        return value
    return None


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _mapping_copy(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return {}


def _list_copy(value: Any) -> list[Any]:
    if isinstance(value, list):
        return copy.deepcopy(value)
    return []
