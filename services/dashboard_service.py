"""Dashboard view-model assembly from database metrics."""

from __future__ import annotations

import database
from services.risk_scorer import score_findings


def build_dashboard(connection):
    """Return actual database metrics and chart-ready distribution data."""
    metrics = database.get_dashboard_metrics(connection)
    severity_counts = database.get_severity_counts(connection)
    rule_counts = [dict(row) for row in database.get_rule_counts(connection)]
    recent_findings = [
        dict(row) for row in database.get_recent_findings(connection)
    ]

    distribution = [
        dict(row) for row in database.get_event_distribution(connection)
    ]
    distribution.sort(key=lambda item: item["day"] or "")
    max_day_count = max(
        (item["count"] for item in distribution), default=0
    )
    for item in distribution:
        item["percent"] = (
            round((item["count"] / max_day_count) * 100, 1)
            if max_day_count
            else 0
        )

    # Score every stored finding, not just the recent slice, so the
    # dashboard risk panel remains a dataset-wide prioritisation aid.
    all_findings = [
        dict(row)
        for row in database.list_findings(connection, limit=-1)
    ]
    risk = score_findings(all_findings)
    risk["scope"] = "all_findings"

    return {
        "metrics": metrics,
        "severity_counts": severity_counts,
        "rule_counts": rule_counts,
        "recent_findings": recent_findings,
        "distribution": distribution,
        "max_day_count": max_day_count,
        "recent_risk": risk,
    }
