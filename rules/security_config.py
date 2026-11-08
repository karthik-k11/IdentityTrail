"""Security and logging configuration detection rules."""

from __future__ import annotations

from rules.base import (
    Finding,
    RuleContext,
    event_summary,
    event_succeeded,
    finding_for_event,
)
from rules.constants import LOGGING_CONFIG_EVENTS, LOGGING_CRITICAL_EVENTS

CATEGORY = "Security & Logging Configuration"


def evaluate(ctx: RuleContext) -> list[Finding]:
    findings = []

    for event in ctx.events:
        event_name = event.get("event_name")
        if not event_succeeded(event):
            continue
        if event_name in LOGGING_CRITICAL_EVENTS:
            findings.append(
                finding_for_event(
                    event,
                    rule_id="logging.trail_disabled_or_deleted",
                    rule_name="CloudTrail trail disabled or deleted",
                    category=CATEGORY,
                    severity="critical",
                    description=(
                        "A CloudTrail trail was stopped or deleted. Logging "
                        "tampering is high-impact because it can reduce audit "
                        "visibility, but confirm whether a planned change "
                        "explains it."
                    ),
                    trigger_reason=(
                        f"{event_name} was recorded. This can stop or remove "
                        "audit logging for a trail."
                    ),
                    recommended_steps=(
                        "Determine whether the change was approved maintenance.",
                        "Identify the actor, source IP, and session used for the change.",
                        "Check whether logging was restored and whether a gap exists.",
                        "Review activity around the change for other defense-evasion actions.",
                    ),
                    evidence={"events": [event_summary(event)]},
                )
            )
        elif event_name in LOGGING_CONFIG_EVENTS:
            findings.append(
                finding_for_event(
                    event,
                    rule_id="logging.trail_configuration_change",
                    rule_name="CloudTrail logging configuration change",
                    category=CATEGORY,
                    severity="high",
                    description=(
                        "A CloudTrail or event data store configuration was "
                        "modified. Configuration changes can reduce audit "
                        "coverage without deleting the trail."
                    ),
                    trigger_reason=(
                        f"{event_name} modified logging configuration. "
                        "Review the before/after settings."
                    ),
                    recommended_steps=(
                        "Review the trail or event data store configuration change.",
                        "Confirm that event selectors and destinations still cover required activity.",
                        "Identify the actor and verify the change against an approved request.",
                        "Check for a corresponding gap in recorded events.",
                    ),
                    evidence={"events": [event_summary(event)]},
                )
            )

    return findings
