"""Authentication-related detection rules."""

from __future__ import annotations

from collections import defaultdict

from rules.base import (
    Finding,
    RuleContext,
    error_text,
    event_summary,
    event_time,
    identity_group_key,
    identity_label,
    normalized,
    parse_time,
    supporting_events,
)
from rules.constants import AUTH_ERROR_EVENTS


CATEGORY = "Authentication Activity"


def _console_login_outcome(event):
    response = normalized(event).get("response_elements")
    value = None
    if isinstance(response, dict):
        value = response.get("ConsoleLogin")
    error = error_text(event)

    if isinstance(value, str):
        if value.lower() == "success" and not error:
            return "success"
        if value.lower() == "failure":
            return "failure"
    if error:
        return "failure"
    return None


def _finding_for_attempt_group(
    events,
    *,
    rule_id,
    rule_name,
    description,
    trigger_reason,
    severity,
    evidence,
):
    first = events[0]
    timestamps = [event_time(event) for event in events if event_time(event)]
    event_ids = tuple(
        sorted(
            event["id"]
            for event in events
            if isinstance(event.get("id"), int)
        )
    )
    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        category=CATEGORY,
        severity=severity,
        description=description,
        trigger_reason=trigger_reason,
        identity=identity_label(first),
        identity_key=first.get("identity_key"),
        principal_arn=first.get("principal_arn"),
        source_ip=first.get("source_ip"),
        event_time=timestamps[0] if timestamps else None,
        event_ids=event_ids,
        evidence=evidence,
        recommended_steps=(
            "Contact the affected identity owner and confirm whether the login attempts were expected.",
            "Review the source IP addresses and user agents for known or suspicious infrastructure.",
            "Check MFA status and whether any subsequent activity occurred from the same source.",
            "Review adjacent CloudTrail events for the identity and correlated access keys.",
        ),
        dedupe_key=(
            f"{rule_id}:{identity_group_key(first)}:"
            f"{timestamps[0] if timestamps else first.get('id')}"
        ),
    )


def evaluate(ctx: RuleContext) -> list[Finding]:
    findings = []

    logins = [
        event
        for event in ctx.events
        if event.get("event_name") == "ConsoleLogin"
    ]
    grouped = defaultdict(list)
    for event in logins:
        grouped[identity_group_key(event)].append(event)

    threshold = max(1, int(ctx.thresholds.get("console_failure_threshold", 3)))
    window_minutes = max(
        1, int(ctx.thresholds.get("console_failure_window_minutes", 15))
    )
    window_seconds = window_minutes * 60

    for group_events in grouped.values():
        timed = [
            event
            for event in group_events
            if parse_time(event_time(event)) is not None
        ]
        timed.sort(key=lambda event: parse_time(event_time(event)))

        failures = [
            event for event in timed
            if _console_login_outcome(event) == "failure"
        ]
        successes = [
            event for event in timed
            if _console_login_outcome(event) == "success"
        ]

        bucket = []
        buckets = []
        for event in failures:
            if not bucket:
                bucket = [event]
                continue
            start = parse_time(event_time(bucket[0]))
            current = parse_time(event_time(event))
            if (current - start).total_seconds() <= window_seconds:
                bucket.append(event)
            else:
                buckets.append(bucket)
                bucket = [event]
        if bucket:
            buckets.append(bucket)

        for attempts in buckets:
            if len(attempts) < threshold:
                continue
            errors = sorted({
                error_text(event) for event in attempts if error_text(event)
            })
            findings.append(
                _finding_for_attempt_group(
                    attempts,
                    rule_id="auth.repeated_console_login_failures",
                    rule_name="Repeated ConsoleLogin failures",
                    description=(
                        "Multiple failed AWS console login attempts were "
                        "observed for the same identity or source within a "
                        "short window. Failed logins are an investigation "
                        "indicator, not proof of malicious activity."
                    ),
                    trigger_reason=(
                        f"{len(attempts)} failed ConsoleLogin attempts were "
                        f"observed within {window_minutes} minutes "
                        f"(threshold: {threshold})."
                    ),
                    severity="high",
                    evidence={
                        "attempt_count": len(attempts),
                        "threshold": threshold,
                        "window_minutes": window_minutes,
                        "errors": errors,
                        "events": supporting_events(attempts),
                    },
                )
            )

        success_window = max(
            1,
            int(
                ctx.thresholds.get(
                    "failure_success_window_minutes", 30
                )
            ),
        )
        success_window_seconds = success_window * 60

        for success in successes:
            success_time = parse_time(event_time(success))
            preceding = []
            for failure in failures:
                failure_time = parse_time(event_time(failure))
                if failure_time is None:
                    continue
                delta = (success_time - failure_time).total_seconds()
                if 0 <= delta <= success_window_seconds:
                    preceding.append(failure)
            if not preceding:
                continue

            failure_ips = sorted({
                event.get("source_ip")
                for event in preceding
                if event.get("source_ip")
            })
            success_ip = success.get("source_ip")
            different_network = bool(
                success_ip and failure_ips and success_ip not in failure_ips
            )
            severity = (
                "critical"
                if different_network and len(preceding) >= threshold
                else "high"
            )
            network_note = (
                " The successful login came from a different source IP than "
                "the failed attempts."
                if different_network
                else ""
            )
            findings.append(
                _finding_for_attempt_group(
                    [*preceding, success],
                    rule_id="auth.console_login_failure_then_success",
                    rule_name="ConsoleLogin failure followed by success",
                    description=(
                        "A successful console login occurred shortly after "
                        "one or more failed login attempts for the same "
                        "identity. Confirm whether this was a legitimate "
                        "user recovering access."
                    ),
                    trigger_reason=(
                        f"{len(preceding)} failed ConsoleLogin attempt(s) "
                        f"preceded a successful login within "
                        f"{success_window} minutes.{network_note}"
                    ),
                    severity=severity,
                    evidence={
                        "failure_count": len(preceding),
                        "window_minutes": success_window,
                        "failure_source_ips": failure_ips,
                        "success_source_ip": success_ip,
                        "different_network": different_network,
                        "events": supporting_events([*preceding, success]),
                    },
                )
            )

    authentication_errors = [
        event
        for event in ctx.events
        if event.get("event_name") in AUTH_ERROR_EVENTS and error_text(event)
    ]
    error_groups = defaultdict(list)
    for event in authentication_errors:
        error_groups[
            (identity_group_key(event), event.get("event_name"))
        ].append(event)

    for (_, event_name), events in error_groups.items():
        errors = sorted({
            error_text(event) for event in events if error_text(event)
        })
        first = events[0]
        findings.append(
            Finding(
                rule_id="auth.authentication_error",
                rule_name="Authentication-related API error",
                category=CATEGORY,
                severity="medium",
                description=(
                    f"Failed authentication-related API calls were observed "
                    f"for {event_name}. A failed call can be benign, but "
                    "repeated failures may indicate misconfiguration or "
                    "credential probing."
                ),
                trigger_reason=(
                    f"{len(events)} failed {event_name} event(s) recorded "
                    f"error(s): {', '.join(errors)}."
                ),
                identity=identity_label(first),
                identity_key=first.get("identity_key"),
                principal_arn=first.get("principal_arn"),
                source_ip=first.get("source_ip"),
                event_time=event_time(first),
                event_ids=tuple(
                    sorted(
                        event["id"]
                        for event in events
                        if isinstance(event.get("id"), int)
                    )
                ),
                evidence={
                    "event_name": event_name,
                    "error_count": len(events),
                    "errors": errors,
                    "events": supporting_events(events),
                },
                recommended_steps=(
                    "Determine whether the failed calls were expected configuration or automation.",
                    "Review the caller identity, source IP, and user agent for context.",
                    "Check for successful calls from the same identity or source around the same time.",
                ),
                dedupe_key=(
                    f"auth.authentication_error:"
                    f"{identity_group_key(first)}:{event_name}"
                ),
            )
        )

    return findings
