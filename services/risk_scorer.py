"""Deterministic, explainable basic risk scoring.

The score is a capped sum of transparent severity weights. It is an
investigation-prioritisation aid, not a probability of compromise.
"""

from __future__ import annotations

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

MAX_SCORE = 100

RISK_BANDS = (
    ("critical", 75),
    ("high", 45),
    ("medium", 20),
    ("low", 1),
    ("none", 0),
)

DISCLAIMER = (
    "The risk score is a deterministic prioritisation aid, not a probability "
    "of compromise. A high score does not prove that an attack occurred."
)


def _as_dict(finding):
    if isinstance(finding, dict):
        return finding
    try:
        return dict(finding)
    except (TypeError, ValueError):
        return {}


def risk_category(score: int) -> str:
    """Map a numeric score to a documented risk band."""
    for label, threshold in RISK_BANDS:
        if score >= threshold:
            return label
    return "none"


def score_findings(findings) -> dict:
    """Return a score with one transparent contribution per unique finding."""
    contributions = []
    seen = set()
    duplicates = 0
    raw_score = 0

    for finding in findings:
        item = _as_dict(finding)
        rule_id = item.get("rule_id")
        dedupe_key = item.get("dedupe_key") or item.get("id")
        identity_key = item.get("identity_key")
        key = (rule_id, dedupe_key, identity_key)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)

        severity = str(item.get("severity") or "").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        raw_score += weight
        contributions.append({
            "finding_id": item.get("id"),
            "rule_id": rule_id,
            "rule_name": item.get("rule_name"),
            "category": item.get("category"),
            "severity": severity,
            "weight": weight,
            "identity": item.get("identity"),
            "trigger_reason": item.get("trigger_reason"),
        })

    score = min(MAX_SCORE, raw_score)
    return {
        "score": score,
        "raw_score": raw_score,
        "max_score": MAX_SCORE,
        "category": risk_category(score),
        "unique_findings": len(contributions),
        "duplicate_findings_ignored": duplicates,
        "contributions": contributions,
        "explanation": (
            "The score is the capped sum of severity weights for unique "
            "findings: critical=25, high=15, medium=8, low=3."
        ),
        "disclaimer": DISCLAIMER,
    }
