"""Shared data structures and safe helpers for detection rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from services.identity_keys import identity_display_name
from services.redaction import redact_sensitive


@dataclass(frozen=True)
class Finding:
    """A rule evaluation result before it is persisted."""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    trigger_reason: str
    event_ids: tuple[int, ...]
    recommended_steps: tuple[str, ...]
    dedupe_key: str
    identity: str | None = None
    identity_key: str | None = None
    principal_arn: str | None = None
    source_ip: str | None = None
    event_time: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleContext:
    """Inputs shared by all rules for one dataset."""

    events: list[dict[str, Any]]
    thresholds: dict[str, int]

    @property
    def window_seconds(self) -> int:
        return self.thresholds.get("console_failure_window_minutes", 15) * 60

    @property
    def success_window_seconds(self) -> int:
        return (
            self.thresholds.get("failure_success_window_minutes", 30) * 60
        )


def normalized(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("_norm")
    return value if isinstance(value, dict) else {}


def raw(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("_raw")
    return value if isinstance(value, dict) else {}


def internal_id(event: dict[str, Any]) -> int | None:
    value = event.get("id")
    return value if isinstance(value, int) else None


def cloudtrail_event_id(event: dict[str, Any]) -> str | None:
    value = event.get("event_id") or normalized(event).get("event_id")
    return value if isinstance(value, str) and value else None


def identity_label(event: dict[str, Any]) -> str:
    return identity_display_name(
        event.get("username") or normalized(event).get("username"),
        event.get("principal_arn") or normalized(event).get("principal_arn"),
        event.get("principal_id") or normalized(event).get("principal_id"),
    )


def identity_group_key(event: dict[str, Any]) -> str:
    """Group by identity when known, otherwise by source IP or event."""
    key = event.get("identity_key")
    if isinstance(key, str) and key:
        return key
    source_ip = event.get("source_ip")
    if isinstance(source_ip, str) and source_ip:
        return f"ip|{source_ip}"
    event_id = internal_id(event)
    return f"event|{event_id}"


def event_time(event: dict[str, Any]) -> str | None:
    value = event.get("event_time") or normalized(event).get("event_time")
    return value if isinstance(value, str) and value else None


def parse_time(value: Any) -> datetime | None:
    """Parse an ISO-8601 CloudTrail timestamp, returning ``None`` on failure."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def error_text(event: dict[str, Any]) -> str | None:
    """Return a safe error description when the event records a failure."""
    value = event.get("error_code") or normalized(event).get("error_code")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = event.get("error_message") or normalized(event).get("error_message")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def event_succeeded(event: dict[str, Any]) -> bool:
    """Return whether CloudTrail records an API call without an error."""
    return error_text(event) is None


def request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    value = raw(event).get("requestParameters")
    if isinstance(value, dict):
        return redact_sensitive(value)
    return {}


def response_elements(event: dict[str, Any]) -> dict[str, Any]:
    value = raw(event).get("responseElements")
    if isinstance(value, dict):
        return redact_sensitive(value)
    return {}


def event_summary(event: dict[str, Any]) -> dict[str, Any]:
    """Return compact, redacted evidence for one event."""
    return {
        "event_db_id": internal_id(event),
        "event_id": cloudtrail_event_id(event),
        "event_time": event_time(event),
        "event_name": event.get("event_name"),
        "event_source": event.get("event_source"),
        "aws_region": event.get("aws_region"),
        "identity": identity_label(event),
        "identity_key": event.get("identity_key"),
        "source_ip": event.get("source_ip"),
        "access_key_id": event.get("access_key_id"),
        "error": error_text(event),
        "request_parameters": request_parameters(event),
        "response_elements": response_elements(event),
    }


def finding_for_event(
    event: dict[str, Any],
    *,
    rule_id: str,
    rule_name: str,
    category: str,
    severity: str,
    description: str,
    trigger_reason: str,
    recommended_steps: tuple[str, ...],
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Build a single-event finding with consistent identity fields."""
    event_id = internal_id(event)
    dedupe = f"{rule_id}:{event_id}"
    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        severity=severity,
        description=description,
        trigger_reason=trigger_reason,
        identity=identity_label(event),
        identity_key=event.get("identity_key"),
        principal_arn=event.get("principal_arn"),
        source_ip=event.get("source_ip"),
        event_time=event_time(event),
        event_ids=(event_id,) if event_id is not None else (),
        evidence=evidence or {"events": [event_summary(event)]},
        recommended_steps=recommended_steps,
        dedupe_key=dedupe,
    )


def supporting_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return redacted summaries for a list of events."""
    return [event_summary(event) for event in events]


def safe_json(value: Any) -> Any:
    """JSON-compatible wrapper used by evidence builders."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)
