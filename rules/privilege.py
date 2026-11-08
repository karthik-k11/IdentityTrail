"""Privilege and permission-change detection rules."""

from __future__ import annotations

from rules.base import (
    Finding,
    RuleContext,
    event_summary,
    event_succeeded,
    finding_for_event,
)
from rules.constants import (
    GROUP_MEMBERSHIP_EVENTS,
    POLICY_VERSION_EVENTS,
    PRIVILEGE_POLICY_EVENTS,
    TRUST_POLICY_EVENTS,
)

CATEGORY = "Privilege & Permission Changes"


def _event_findings(
    ctx,
    *,
    event_names,
    rule_id,
    rule_name,
    severity,
    description,
    recommended_steps,
):
    findings = []
    for event in ctx.events:
        event_name = event.get("event_name")
        if event_name not in event_names or not event_succeeded(event):
            continue
        findings.append(
            finding_for_event(
                event,
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                severity=severity,
                description=description,
                trigger_reason=(
                    f"{event_name} changed an IAM permission or trust "
                    "relationship. Review the actor, target, and policy."
                ),
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
            event_names=PRIVILEGE_POLICY_EVENTS,
            rule_id="privilege.policy_change",
            rule_name="IAM policy attachment or inline policy change",
            severity="high",
            description=(
                "An IAM policy attachment, inline policy, or policy deletion "
                "was recorded. Permission changes can be legitimate "
                "administration or privilege-escalation activity."
            ),
            recommended_steps=(
                "Identify the actor and the target user, role, or group.",
                "Review the policy ARN or inline policy document and compare it with the approved change.",
                "Check whether the change expanded permissions, including administrative access.",
                "Review subsequent activity by the target identity.",
            ),
        )
    )

    findings.extend(
        _event_findings(
            ctx,
            event_names=POLICY_VERSION_EVENTS,
            rule_id="privilege.policy_version_change",
            rule_name="IAM policy version change",
            severity="high",
            description=(
                "An IAM policy version was created, made default, or deleted. "
                "Policy versions can change the effective permissions of every "
                "principal attached to the policy."
            ),
            recommended_steps=(
                "Review the policy version content and who made it the default.",
                "Determine which users, roles, or groups are attached to the policy.",
                "Compare the new permissions with the previous approved version.",
                "Check for activity from newly empowered principals.",
            ),
        )
    )

    findings.extend(
        _event_findings(
            ctx,
            event_names=TRUST_POLICY_EVENTS,
            rule_id="privilege.trust_policy_change",
            rule_name="Role trust policy change",
            severity="high",
            description=(
                "A role trust policy was updated. Trust changes can allow new "
                "principals to assume a role and should be reviewed carefully."
            ),
            recommended_steps=(
                "Review the trusted principals in the updated assume-role policy.",
                "Confirm that the new trust relationship is expected and least-privilege.",
                "Check for role assumption activity from the newly trusted principals.",
                "Revert the change if it was not authorized.",
            ),
        )
    )

    findings.extend(
        _event_findings(
            ctx,
            event_names=GROUP_MEMBERSHIP_EVENTS,
            rule_id="privilege.group_membership_change",
            rule_name="User group membership change",
            severity="high",
            description=(
                "A user was added to or removed from an IAM group. Group "
                "membership changes can grant or remove inherited permissions."
            ),
            recommended_steps=(
                "Review the group's attached policies and the target user.",
                "Confirm that the membership change matches an approved request.",
                "Check for subsequent activity by the target user.",
            ),
        )
    )

    return findings
