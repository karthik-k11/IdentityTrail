"""Access-key activity detection rules."""

from __future__ import annotations

from rules.base import (
    Finding,
    RuleContext,
    event_summary,
    event_time,
    event_succeeded,
    finding_for_event,
    parse_time,
    raw,
    supporting_events,
)
from rules.constants import (
    ACCESS_KEY_EVENT_SEVERITY,
    SENSITIVE_FOLLOW_ON_EVENTS,
)

CATEGORY = "Access Key Activity"

_DESCRIPTIONS = {
    "CreateAccessKey": (
        "An IAM access key was created. Key creation is sensitive because a "
        "new credential can be used outside the console."
    ),
    "DeleteAccessKey": (
        "An IAM access key was deleted. Deletion can be legitimate cleanup or "
        "an attempt to remove evidence or disrupt access."
    ),
    "UpdateAccessKey": (
        "An IAM access key was updated. Confirm whether the status change was "
        "approved and expected."
    ),
}


def _target_user(event):
    request = raw(event).get("requestParameters")
    if isinstance(request, dict):
        value = request.get("userName") or request.get("accessKeyId")
        if isinstance(value, str) and value:
            return value
    response = raw(event).get("responseElements")
    if isinstance(response, dict):
        access_key = response.get("accessKey")
        if isinstance(access_key, dict):
            value = access_key.get("userName")
            if isinstance(value, str) and value:
                return value
    return None


def _extract_new_access_key_id(event):
    """Read the created key ID from the unredacted raw response."""
    response = raw(event).get("responseElements")
    if not isinstance(response, dict):
        return None
    access_key = response.get("accessKey")
    if not isinstance(access_key, dict):
        return None
    value = access_key.get("accessKeyId")
    return value if isinstance(value, str) and value else None


def evaluate(ctx: RuleContext) -> list[Finding]:
    findings = []

    for event in ctx.events:
        event_name = event.get("event_name")
        severity = ACCESS_KEY_EVENT_SEVERITY.get(event_name)
        if severity is None or not event_succeeded(event):
            continue
        target = _target_user(event)
        findings.append(
            finding_for_event(
                event,
                rule_id=f"access_key.{event_name.lower()}",
                rule_name=event_name,
                category=CATEGORY,
                severity=severity,
                description=_DESCRIPTIONS[event_name],
                trigger_reason=(
                    f"{event_name} was recorded"
                    + (f" for target {target}." if target else ".")
                ),
                recommended_steps=(
                    "Confirm that the access-key change was authorized and tied to a change request.",
                    "Identify the actor, source IP, and user agent associated with the change.",
                    "Review subsequent activity performed with the affected access key.",
                    "If the change was not authorized, disable the key and follow incident-response procedures.",
                ),
                evidence={
                    "target": target,
                    "events": [event_summary(event)],
                },
            )
        )

    window_hours = max(
        1, int(ctx.thresholds.get("access_key_activity_window_hours", 24))
    )
    window_seconds = window_hours * 3600

    creations = [
        event
        for event in ctx.events
        if (
            event.get("event_name") == "CreateAccessKey"
            and event_succeeded(event)
        )
    ]
    for creation in creations:
        key_id = _extract_new_access_key_id(creation)
        creation_time = parse_time(event_time(creation))
        if not key_id or creation_time is None:
            continue

        later_activity = []
        for event in ctx.events:
            if event.get("id") == creation.get("id"):
                continue
            if event.get("access_key_id") != key_id:
                continue
            if not event_succeeded(event):
                continue
            activity_time = parse_time(event_time(event))
            if activity_time is None:
                continue
            delta = (activity_time - creation_time).total_seconds()
            if 0 <= delta <= window_seconds:
                later_activity.append(event)

        if not later_activity:
            continue

        later_activity.sort(key=lambda event: parse_time(event_time(event)))
        sensitive_activity = [
            event
            for event in later_activity
            if event.get("event_name") in SENSITIVE_FOLLOW_ON_EVENTS
        ]
        severity = "high" if sensitive_activity else "medium"
        masked_key = f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"
        event_ids = tuple(
            sorted(
                event["id"]
                for event in [creation, *later_activity]
                if isinstance(event.get("id"), int)
            )
        )

        findings.append(
            Finding(
                rule_id="access_key.use_after_creation",
                rule_name="Activity using a newly created access key",
                category=CATEGORY,
                severity=severity,
                description=(
                    "CloudTrail events show API activity using an access key "
                    "created earlier in the same dataset. This is contextual "
                    "evidence only; the activity may be legitimate automation."
                ),
                trigger_reason=(
                    f"New access key {masked_key} was used in "
                    f"{len(later_activity)} event(s) within {window_hours} "
                    "hour(s) of creation."
                    + (
                        f" {len(sensitive_activity)} follow-on event(s) were "
                        "sensitive administrative operations."
                        if sensitive_activity
                        else ""
                    )
                ),
                identity=creation.get("username")
                or creation.get("principal_arn")
                or "Not recorded",
                identity_key=creation.get("identity_key"),
                principal_arn=creation.get("principal_arn"),
                source_ip=creation.get("source_ip"),
                event_time=event_time(creation),
                event_ids=event_ids,
                evidence={
                    "created_access_key": masked_key,
                    "window_hours": window_hours,
                    "follow_on_event_count": len(later_activity),
                    "sensitive_event_names": sorted({
                        event.get("event_name")
                        for event in sensitive_activity
                    }),
                    "events": supporting_events([creation, *later_activity]),
                },
                recommended_steps=(
                    "Confirm that the new access key was expected and approved.",
                    "Review every action performed with the key and the source IPs used.",
                    "Check whether the created key belongs to a user or workload that should have API credentials.",
                    "If the creation or use was unauthorized, disable the key and investigate the creating identity.",
                ),
                dedupe_key=f"access_key.use_after_creation:{creation.get('id')}",
            )
        )

    return findings
