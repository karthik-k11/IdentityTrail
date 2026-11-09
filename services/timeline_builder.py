"""Chronological investigation timeline construction."""

from __future__ import annotations

import json
from datetime import timedelta

import database
from rules.base import parse_time
from services.identity_analyzer import categorize_event
from services.identity_keys import identity_display_name
from services.redaction import mask_access_key


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _resource_labels(event):
    """Return redacted, human-readable resource labels for an event."""
    try:
        normalized = json.loads(event.get("normalized_event_json") or "{}")
    except (TypeError, ValueError):
        normalized = {}
    resources = normalized.get("resources")
    if not isinstance(resources, list):
        return []
    labels = set()
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        for key in ("ARN", "arn", "type", "resourceType", "name"):
            value = resource.get(key)
            if isinstance(value, str) and value.strip():
                labels.add(value.strip())
                break
    return sorted(labels)


def _max_severity(findings):
    severities = [
        str(finding.get("severity") or "").lower()
        for finding in findings
    ]
    if not severities:
        return None
    return max(severities, key=lambda value: SEVERITY_RANK.get(value, 0))


def _decorate_event(row, findings):
    event = dict(row)
    decorated = []
    for finding in findings:
        item = dict(finding)
        decorated.append(item)

    event["findings"] = decorated
    event["finding_count"] = len(decorated)
    event["primary_severity"] = _max_severity(decorated)
    event["categories"] = sorted({
        finding.get("category")
        for finding in decorated
        if finding.get("category")
    })
    event["trigger_explanations"] = sorted({
        finding.get("trigger_reason")
        for finding in decorated
        if finding.get("trigger_reason")
    })
    event["rule_names"] = sorted({
        finding.get("rule_name")
        for finding in decorated
        if finding.get("rule_name")
    })
    event["category"] = categorize_event(
        event.get("event_name"), event.get("event_source")
    )
    event["access_key_masked"] = mask_access_key(
        event.get("access_key_id")
    )
    event["resource_labels"] = _resource_labels(event)
    return event


def _group_events(events, gap_minutes):
    groups = []
    current = None

    for event in events:
        parsed = parse_time(event.get("event_time"))
        identity = event.get("identity_key") or "unidentified"

        def start_group():
            group = {
                "identity_key": event.get("identity_key"),
                "identity": identity_display_name(
                    event.get("username"),
                    event.get("principal_arn"),
                    event.get("principal_id"),
                ),
                "events": [],
                "first_time": event.get("event_time"),
                "last_time": event.get("event_time"),
                "last_parsed": parsed,
                "has_timed_events": parsed is not None,
                "max_severity": None,
                "has_findings": False,
                "categories": set(),
            }
            groups.append(group)
            return group

        new_group = (
            current is None
            or event.get("identity_key") is None
            or current["identity_key"] != event.get("identity_key")
        )
        if not new_group and parsed is None and current["has_timed_events"]:
            new_group = True
        if (
            not new_group
            and parsed is not None
            and current["last_parsed"] is not None
            and parsed - current["last_parsed"]
            > timedelta(minutes=gap_minutes)
        ):
            new_group = True

        if new_group:
            current = start_group()

        current["events"].append(event)
        severity = event.get("primary_severity")
        if severity and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(
            current["max_severity"], 0
        ):
            current["max_severity"] = severity
        if event.get("finding_count"):
            current["has_findings"] = True
        current["categories"].update(event.get("categories") or [])

        if parsed is not None:
            current["last_parsed"] = parsed
            current["last_time"] = event.get("event_time")
            current["has_timed_events"] = True
        elif current["first_time"] is None:
            current["first_time"] = event.get("event_time")

    for group in groups:
        group["categories"] = sorted(group["categories"])
        if group["has_timed_events"]:
            group["title"] = (
                f"Activity sequence — {group['identity']}"
            )
            group["time_label"] = (
                f"{group['first_time'] or 'Not recorded'} to "
                f"{group['last_time'] or 'Not recorded'}"
            )
        else:
            group["title"] = f"Undated events — {group['identity']}"
            group["time_label"] = "Event time not recorded"
        group["note"] = (
            f"Grouped by matching identity and a gap of no more than "
            f"{gap_minutes} minutes. Sequence grouping is a review aid, not "
            "proof of an attack."
        )

    return groups


def build_timeline(
    connection,
    filters,
    *,
    page=1,
    per_page=100,
    gap_minutes=60,
):
    """Return a filtered, chronological timeline with investigation groups."""
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 500))
    offset = (page - 1) * per_page

    total = database.count_timeline_events(connection, **filters)
    rows = database.list_timeline_events(
        connection,
        limit=per_page,
        offset=offset,
        **filters,
    )
    event_ids = [row["id"] for row in rows]
    findings_map = database.get_findings_for_events(connection, event_ids)

    events = [
        _decorate_event(row, findings_map.get(row["id"], []))
        for row in rows
    ]
    groups = _group_events(events, max(1, int(gap_minutes)))

    return {
        "events": events,
        "groups": groups,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }
