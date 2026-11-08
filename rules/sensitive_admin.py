"""Sensitive administrative and resource operation rules."""

from __future__ import annotations

from collections import defaultdict

from rules.base import (
    Finding,
    RuleContext,
    event_summary,
    event_succeeded,
    event_time,
    finding_for_event,
    identity_group_key,
    identity_label,
    parse_time,
    supporting_events,
)
from rules.constants import (
    HIGH_IMPACT_ADMIN_EVENTS,
    SECRETS_ACCESS_EVENTS,
    SENSITIVE_DELETION_EVENTS,
)

CATEGORY = "Sensitive Administrative Activity"


def _event_findings(
    ctx,
    *,
    event_names,
    rule_id,
    rule_name,
    severity,
    description,
    reason,
    recommended_steps,
):
    findings = []
    for event in ctx.events:
        if (
            event.get("event_name") not in event_names
            or not event_succeeded(event)
        ):
            continue
        findings.append(
            finding_for_event(
                event,
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                severity=severity,
                description=description,
                trigger_reason=reason(event),
                recommended_steps=recommended_steps,
                evidence={"events": [event_summary(event)]},
            )
        )
    return findings


def evaluate(ctx: RuleContext) -> list[Finding]:
    findings = []

    findings.extend(
        _event_findings(
            ctx,
            event_names=SENSITIVE_DELETION_EVENTS,
            rule_id="sensitive.resource_deletion",
            rule_name="Sensitive resource deletion",
            severity="high",
            description=(
                "A deletion API was recorded for a sensitive AWS resource. "
                "Deletion can be routine lifecycle management or an attempt "
                "to disrupt access or remove evidence."
            ),
            reason=lambda event: (
                f"{event.get('event_name')} deleted or requested deletion of "
                "a sensitive resource. Review the target and authorization."
            ),
            recommended_steps=(
                "Identify the deleted resource and its owner.",
                "Confirm whether the deletion was planned and authorized.",
                "Check for recent permission or logging changes by the same actor.",
                "Review backup, recovery, and recreation activity.",
            ),
        )
    )

    findings.extend(
        _event_findings(
            ctx,
            event_names=HIGH_IMPACT_ADMIN_EVENTS,
            rule_id="sensitive.high_impact_admin",
            rule_name="High-impact administrative operation",
            severity="high",
            description=(
                "A high-impact administrative API was recorded. These actions "
                "are not inherently malicious, but they can create identities, "
                "change trust, or expose protected resources."
            ),
            reason=lambda event: (
                f"{event.get('event_name')} is a high-impact administrative "
                "operation. Review the target and business justification."
            ),
            recommended_steps=(
                "Confirm the change against an approved request or change ticket.",
                "Review the actor, source IP, session, and target resource.",
                "Check whether the operation created or expanded access.",
                "Review subsequent activity by the affected principals.",
            ),
        )
    )

    secrets_events = [
        event
        for event in ctx.events
        if (
            event.get("event_name") in SECRETS_ACCESS_EVENTS
            and event_succeeded(event)
        )
    ]
    grouped = defaultdict(list)
    for event in secrets_events:
        grouped[
            (identity_group_key(event), event.get("event_name"))
        ].append(event)

    for (_, event_name), events in grouped.items():
        events.sort(
            key=lambda event: (
                parse_time(event_time(event)) is None,
                parse_time(event_time(event)) or 0,
            )
        )
        first = events[0]
        event_ids = tuple(
            sorted(
                event["id"]
                for event in events
                if isinstance(event.get("id"), int)
            )
        )
        findings.append(
            Finding(
                rule_id="sensitive.secrets_access",
                rule_name="Access to secrets or decryption operations",
                category=CATEGORY,
                severity="medium",
                description=(
                    f"{event_name} accesses secret material or performs a "
                    "decryption operation. This is context for investigating "
                    "credential exposure, not proof of misuse."
                ),
                trigger_reason=(
                    f"{len(events)} {event_name} event(s) were recorded. "
                    "Review which secrets or keys were accessed and why."
                ),
                identity=identity_label(first),
                identity_key=first.get("identity_key"),
                principal_arn=first.get("principal_arn"),
                source_ip=first.get("source_ip"),
                event_time=event_time(first),
                event_ids=event_ids,
                evidence={
                    "event_name": event_name,
                    "access_count": len(events),
                    "events": supporting_events(events),
                },
                recommended_steps=(
                    "Identify the secret, parameter, or key that was accessed.",
                    "Confirm that the calling identity and workload require access.",
                    "Check for unusual source IPs, user agents, or access volume.",
                    "Rotate exposed secrets if the access was not authorized.",
                ),
                dedupe_key=(
                    f"sensitive.secrets_access:"
                    f"{identity_group_key(first)}:{event_name}"
                ),
            )
        )

    return findings
