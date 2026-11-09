"""Detection engine orchestration.

Loads stored events for a dataset, runs the rule registry, and persists the
deduplicated findings through the database layer.
"""

from __future__ import annotations

import json

import database
from rules import evaluate_all
from rules.base import RuleContext


def thresholds_from_config(config) -> dict[str, int]:
    """Read configurable detection thresholds from a Flask config mapping."""
    return {
        "console_failure_threshold": max(
            1, int(config.get("DETECTION_CONSOLE_FAILURE_THRESHOLD", 3))
        ),
        "console_failure_window_minutes": max(
            1, int(config.get("DETECTION_CONSOLE_FAILURE_WINDOW_MINUTES", 15))
        ),
        "failure_success_window_minutes": max(
            1, int(config.get("DETECTION_FAILURE_SUCCESS_WINDOW_MINUTES", 30))
        ),
        "access_key_activity_window_hours": max(
            1, int(config.get("DETECTION_ACCESS_KEY_ACTIVITY_WINDOW_HOURS", 24))
        ),
    }


def _parse_json_object(value):
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _load_events(connection, dataset_id):
    rows = database.get_dataset_events_for_analysis(connection, dataset_id)
    events = []
    for row in rows:
        event = dict(row)
        event["_raw"] = _parse_json_object(row["raw_event_json"])
        event["_norm"] = _parse_json_object(row["normalized_event_json"])
        events.append(event)
    return events


def _deduplicate(findings):
    """Remove duplicate rule results while preserving deterministic order."""
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.rule_id, finding.dedupe_key)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def analyze_dataset(connection, dataset_id, config):
    """Run all rules for one dataset and replace its persisted findings."""
    dataset = database.get_dataset(connection, dataset_id)
    if dataset is None:
        raise ValueError("Dataset not found")

    events = _load_events(connection, dataset_id)
    context = RuleContext(
        events=events,
        thresholds=thresholds_from_config(config),
    )
    findings = _deduplicate(evaluate_all(context))
    inserted = database.replace_findings(connection, dataset_id, findings)

    return {
        "dataset_id": dataset_id,
        "filename": dataset["filename"],
        "event_count": len(events),
        "finding_count": inserted,
    }


def analyze_all_datasets(connection, config):
    """Run detection for every stored dataset."""
    results = []
    for dataset in database.list_datasets(connection):
        results.append(analyze_dataset(connection, dataset["id"], config))
    return results
