"""Evidence-based JSON and CSV investigation report generation."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import database
from services.identity_keys import identity_display_name
from services.redaction import mask_access_key, redact_sensitive
from services.risk_scorer import score_findings


class ReportScopeError(ValueError):
    """Raised when a report scope references a missing dataset."""


def _json_load(value, fallback):
    if not value:
        return fallback
    try:
        loaded = json.loads(value)
    except (TypeError, ValueError):
        return fallback
    return loaded if isinstance(loaded, type(fallback)) else fallback


def _split_ids(value):
    if not value:
        return []
    return sorted({
        int(item)
        for item in str(value).split(",")
        if item.strip().isdigit()
    })


def _event_public(event):
    normalized = _json_load(event.get("normalized_event_json"), {})
    resources = normalized.get("resources")
    if not isinstance(resources, list):
        resources = []

    return {
        "event_db_id": event.get("id"),
        "event_id": event.get("event_id"),
        "event_time": event.get("event_time"),
        "event_name": event.get("event_name"),
        "event_source": event.get("event_source"),
        "aws_region": event.get("aws_region"),
        "account_id": event.get("account_id"),
        "identity": identity_display_name(
            event.get("username"),
            event.get("principal_arn"),
            event.get("principal_id"),
        ),
        "identity_key": event.get("identity_key"),
        "identity_type": event.get("identity_type"),
        "source_ip": event.get("source_ip"),
        "access_key_id": mask_access_key(event.get("access_key_id")),
        "resources": redact_sensitive(resources),
    }


def _finding_public(finding, event_map):
    linked_ids = _split_ids(finding.get("linked_event_ids"))
    supporting = [
        _event_public(event_map[event_id])
        for event_id in linked_ids
        if event_id in event_map
    ]
    related_cloudtrail_ids = [
        item["event_id"] for item in supporting if item.get("event_id")
    ]
    return {
        "id": finding.get("id"),
        "finding_id": finding.get("id"),
        "dedupe_key": finding.get("dedupe_key"),
        "dataset_id": finding.get("dataset_id"),
        "dataset_filename": finding.get("filename"),
        "rule_id": finding.get("rule_id"),
        "rule_name": finding.get("rule_name"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "identity": finding.get("identity"),
        "identity_key": finding.get("identity_key"),
        "principal_arn": finding.get("principal_arn"),
        "source_ip": finding.get("source_ip"),
        "event_time": finding.get("event_time"),
        "detection_timestamp": finding.get("detection_timestamp"),
        "description": finding.get("description"),
        "trigger_reason": finding.get("trigger_reason"),
        "related_event_ids": related_cloudtrail_ids,
        "evidence": redact_sensitive(
            _json_load(finding.get("evidence_json"), {})
        ),
        "recommended_steps": _json_load(
            finding.get("recommended_steps_json"), []
        ),
        "supporting_events": supporting,
    }


def build_report(
    connection,
    *,
    dataset_id=None,
    identity_key=None,
    start=None,
    end=None,
    analysis_time=None,
    event_limit=500,
    finding_limit=1000,
):
    """Build a report from stored events, findings, and risk scoring."""
    if dataset_id is not None and database.get_dataset(
        connection, dataset_id
    ) is None:
        raise ReportScopeError("Dataset not found")

    all_datasets = [
        dict(row) for row in database.list_datasets(connection)
    ]
    datasets = (
        [item for item in all_datasets if item["id"] == dataset_id]
        if dataset_id is not None
        else all_datasets
    )

    finding_rows = database.list_findings(
        connection,
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
        limit=finding_limit,
    )
    findings = [dict(row) for row in finding_rows]
    event_metrics = database.get_report_event_metrics(
        connection,
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
    )
    severity_distribution = database.get_report_severity_counts(
        connection,
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
    )
    finding_count = sum(severity_distribution.values())

    linked_ids = set()
    for finding in findings:
        linked_ids.update(_split_ids(finding.get("linked_event_ids")))
    linked_events = [
        dict(row)
        for row in database.get_events_by_ids(connection, linked_ids)
    ]
    event_map = {event["id"]: event for event in linked_events}

    scope_events = [
        dict(row)
        for row in database.list_report_events(
            connection,
            dataset_id=dataset_id,
            identity_key=identity_key,
            start=start,
            end=end,
            limit=event_limit,
        )
    ]

    public_findings = [
        _finding_public(finding, event_map) for finding in findings
    ]

    timeline_source = linked_events
    if not timeline_source:
        timeline_source = scope_events[:50]
    timeline = [_event_public(event) for event in timeline_source]

    risk_findings = database.list_findings(
        connection,
        dataset_id=dataset_id,
        identity_key=identity_key,
        start=start,
        end=end,
        limit=-1,
    )
    risk = score_findings([dict(row) for row in risk_findings])

    identity_stats = {}
    for event in scope_events:
        key = event.get("identity_key")
        if not key:
            continue
        item = identity_stats.setdefault(
            key,
            {
                "identity_key": key,
                "identity": identity_display_name(
                    event.get("username"),
                    event.get("principal_arn"),
                    event.get("principal_id"),
                ),
                "event_count": 0,
                "finding_count": 0,
            },
        )
        item["event_count"] += 1

    finding_identity_counts = {}
    for finding in public_findings:
        key = finding.get("identity_key")
        if key:
            finding_identity_counts[key] = (
                finding_identity_counts.get(key, 0) + 1
            )
    for key, item in identity_stats.items():
        item["finding_count"] = finding_identity_counts.get(key, 0)

    affected_identities = sorted(
        identity_stats.values(),
        key=lambda item: (
            -item["finding_count"],
            -item["event_count"],
            item["identity"] or "",
        ),
    )

    suspicious_ips = sorted({
        finding.get("source_ip")
        for finding in public_findings
        if finding.get("severity") in {"critical", "high"}
        and finding.get("source_ip")
    })

    scope_source_ips = sorted({
        event.get("source_ip")
        for event in scope_events
        if event.get("source_ip")
    })

    time_range = {
        "start": event_metrics["start"],
        "end": event_metrics["end"],
    }

    recommended_steps = set()
    for finding in public_findings:
        for step in finding.get("recommended_steps") or []:
            if isinstance(step, str) and step.strip():
                recommended_steps.add(step.strip())
    if not recommended_steps:
        recommended_steps.add(
            "Review the dataset for identity, authentication, access-key, "
            "permission, and logging changes that require context."
        )
    recommended_steps.add(
        "Validate all findings against change records, asset ownership, and "
        "known administrative activity before concluding that activity was malicious."
    )

    generated_at = (
        analysis_time
        or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    scope_label = (
        datasets[0]["filename"]
        if dataset_id is not None and datasets
        else "All datasets"
    )

    return {
        "report_title": f"IdentityTrail Investigation Report — {scope_label}",
        "application": "IdentityTrail",
        "generated_at": generated_at,
        "analysis_time": generated_at,
        "scope": {
            "dataset_id": dataset_id,
            "identity_key": identity_key,
            "start": start,
            "end": end,
            "description": "Local CloudTrail investigation report",
        },
        "datasets": [
            {
                "id": dataset.get("id"),
                "filename": dataset.get("filename"),
                "uploaded_at": dataset.get("uploaded_at"),
                "file_size": dataset.get("file_size"),
                "total_events": dataset.get("total_events"),
                "parsed_events": dataset.get("parsed_events"),
                "failed_events": dataset.get("failed_events"),
                "stored_events": dataset.get("stored_events"),
                "finding_count": dataset.get("finding_count"),
                "last_analyzed_at": dataset.get("last_analyzed_at"),
            }
            for dataset in datasets
        ],
        "summary": {
            "dataset_count": len(datasets),
            "event_count": event_metrics["event_count"],
            "finding_count": finding_count,
            "identity_count": event_metrics["identity_count"],
            "source_ip_count": event_metrics["source_ip_count"],
            "severity_distribution": severity_distribution,
            "time_range": time_range,
            "risk": risk,
        },
        "coverage": {
            "events_included": len(scope_events),
            "events_omitted": max(
                0, event_metrics["event_count"] - len(scope_events)
            ),
            "findings_included": len(public_findings),
            "findings_omitted": max(0, finding_count - len(public_findings)),
            "timeline_events_included": len(timeline),
            "identities_included": len(affected_identities),
            "source_ips_included": len(scope_source_ips),
        },
        "affected_identities": affected_identities,
        "suspicious_source_ips": suspicious_ips,
        "source_ips_observed": scope_source_ips,
        "findings": public_findings,
        "timeline": timeline,
        "recommended_steps": sorted(recommended_steps),
        "limitations": [
            "Detection is deterministic and rule-based; it does not prove malicious intent.",
            "Findings depend on the CloudTrail fields present in the uploaded dataset.",
            "Missing identity or network fields reduce the available context.",
            "Assumed-role sessions identify a role session, not necessarily the original human user.",
            "The risk score is a prioritisation aid, not a probability of compromise.",
            "This report covers only the selected local dataset and time range.",
        ],
        "caveats": [
            "Investigation findings are indicators that require validation against change records and business context.",
            "A high risk score does not prove that an attack occurred.",
            "Absence of findings does not prove that activity was benign.",
        ],
    }


def report_to_json(report):
    """Serialize a report as pretty-printed JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


CSV_COLUMNS = (
    "record_type",
    "title",
    "generated_at",
    "dataset_id",
    "dataset_filename",
    "identity",
    "source_ip",
    "event_time",
    "event_name",
    "event_source",
    "aws_region",
    "severity",
    "category",
    "rule_id",
    "rule_name",
    "description",
    "trigger_reason",
    "related_event_ids",
    "recommendations",
    "count",
    "value",
)


def csv_safe(value):
    """Neutralise spreadsheet formula injection in a CSV cell."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return text
    candidate = text.lstrip()
    while candidate and (ord(candidate[0]) < 32 or candidate[0] == "\ufeff"):
        candidate = candidate[1:].lstrip()
    if candidate and candidate[0] in ("=", "+", "-", "@"):
        return "'" + text
    if text[0] in ("\t", "\r", "\n") or ord(text[0]) < 32:
        return "'" + text
    return text


def report_to_csv(report):
    """Serialize a report as a flat CSV with summary, finding, and event rows."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    summary = report.get("summary", {})
    risk = summary.get("risk", {})

    def write_row(**values):
        writer.writerow([
            csv_safe(values.get(column)) for column in CSV_COLUMNS
        ])

    write_row(
        record_type="summary",
        title=report.get("report_title"),
        generated_at=report.get("generated_at"),
        description=(
            "Local CloudTrail investigation report. Findings are indicators, "
            "not proof of malicious activity."
        ),
        count=summary.get("event_count"),
        value=risk.get("score"),
    )
    write_row(
        record_type="risk",
        title="Basic explainable risk score",
        severity=risk.get("category"),
        description=risk.get("explanation"),
        value=risk.get("score"),
        count=risk.get("unique_findings"),
    )

    for dataset in report.get("datasets", []):
        write_row(
            record_type="dataset",
            dataset_id=dataset.get("id"),
            dataset_filename=dataset.get("filename"),
            event_time=dataset.get("uploaded_at"),
            count=dataset.get("stored_events"),
            description=(
                f"Uploaded dataset; parsed={dataset.get('parsed_events')}, "
                f"failed={dataset.get('failed_events')}"
            ),
        )

    for severity, count in (
        summary.get("severity_distribution") or {}
    ).items():
        write_row(
            record_type="severity",
            severity=severity,
            count=count,
        )

    for finding in report.get("findings", []):
        write_row(
            record_type="finding",
            dataset_id=finding.get("dataset_id"),
            dataset_filename=finding.get("dataset_filename"),
            identity=finding.get("identity"),
            source_ip=finding.get("source_ip"),
            event_time=finding.get("event_time"),
            severity=finding.get("severity"),
            category=finding.get("category"),
            rule_id=finding.get("rule_id"),
            rule_name=finding.get("rule_name"),
            description=finding.get("description"),
            trigger_reason=finding.get("trigger_reason"),
            related_event_ids="; ".join(
                str(value)
                for value in finding.get("related_event_ids") or []
            ),
            recommendations=" | ".join(
                finding.get("recommended_steps") or []
            ),
        )

    for contribution in risk.get("contributions", []):
        write_row(
            record_type="risk_contribution",
            identity=contribution.get("identity"),
            severity=contribution.get("severity"),
            category=contribution.get("category"),
            rule_id=contribution.get("rule_id"),
            rule_name=contribution.get("rule_name"),
            description=contribution.get("trigger_reason"),
            value=contribution.get("weight"),
        )

    for event in report.get("timeline", []):
        write_row(
            record_type="event",
            identity=event.get("identity"),
            source_ip=event.get("source_ip"),
            event_time=event.get("event_time"),
            event_name=event.get("event_name"),
            event_source=event.get("event_source"),
            aws_region=event.get("aws_region"),
            count=1,
        )

    for step in report.get("recommended_steps", []):
        write_row(
            record_type="recommendation",
            recommendations=step,
        )

    return output.getvalue()
