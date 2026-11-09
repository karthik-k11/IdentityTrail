"""Request-parameter parsing shared by explorer and report routes."""

from __future__ import annotations

from datetime import date, datetime


class FilterError(ValueError):
    """Raised when a user-supplied filter is invalid."""


def positive_int(value, field_name, default=None):
    """Parse a positive integer, raising a safe validation error."""
    if value is None or str(value).strip() == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise FilterError(f"{field_name} must be a whole number.") from exc
    if parsed < 1:
        raise FilterError(f"{field_name} must be a positive whole number.")
    return parsed


def optional_text(value, max_length=200):
    """Trim user text and enforce a sane maximum length."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        raise FilterError(
            f"Search text must be {max_length} characters or fewer."
        )
    return text


def normalize_time_bound(value, end=False):
    """Normalize a date or datetime filter to a sortable ISO timestamp."""
    text = optional_text(value, max_length=40)
    if text is None:
        return None
    if len(text) == 10:
        try:
            date.fromisoformat(text)
        except ValueError as exc:
            raise FilterError("Dates must use YYYY-MM-DD format.") from exc
        suffix = "T23:59:59.999999Z" if end else "T00:00:00Z"
        return text + suffix

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise FilterError(
            "Time filters must be ISO dates or datetimes."
        ) from exc
    return text


VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def _severity(value):
    text = optional_text(value, max_length=20)
    if text is None:
        return None
    text = text.lower()
    if text not in VALID_SEVERITIES:
        raise FilterError(
            "Severity must be critical, high, medium, or low."
        )
    return text


def common_filters(args):
    """Parse common event/explorer filter parameters."""
    return {
        "dataset_id": positive_int(
            args.get("dataset_id"), "Dataset ID"
        ),
        "identity_key": optional_text(args.get("identity"), max_length=500),
        "event_name": optional_text(args.get("event_name")),
        "source_ip": optional_text(args.get("source_ip")),
        "aws_region": optional_text(args.get("region")),
        "event_source": optional_text(args.get("event_source")),
        "start": normalize_time_bound(args.get("start")),
        "end": normalize_time_bound(args.get("end"), end=True),
        "search": optional_text(args.get("search")),
    }


def timeline_filters(args):
    """Parse timeline filters, including finding severity and category."""
    filters = common_filters(args)
    # Timeline queries do not support free-text search or a region filter.
    filters.pop("search", None)
    filters.pop("aws_region", None)
    filters["severity"] = _severity(args.get("severity"))
    filters["category"] = optional_text(args.get("category"))
    return filters


def finding_filters(args):
    """Parse finding-list filters."""
    return {
        "dataset_id": positive_int(
            args.get("dataset_id"), "Dataset ID"
        ),
        "severity": _severity(args.get("severity")),
        "category": optional_text(args.get("category")),
        "rule_id": optional_text(args.get("rule_id")),
        "identity_key": optional_text(args.get("identity"), max_length=500),
        "identity_search": optional_text(args.get("search")),
        "start": normalize_time_bound(args.get("start")),
        "end": normalize_time_bound(args.get("end"), end=True),
    }


def report_filters(args):
    """Parse report scope filters."""
    filters = {
        "dataset_id": positive_int(
            args.get("dataset_id"), "Dataset ID"
        ),
        "identity_key": optional_text(args.get("identity"), max_length=500),
        "start": normalize_time_bound(args.get("start")),
        "end": normalize_time_bound(args.get("end"), end=True),
    }
    if (
        filters["start"]
        and filters["end"]
        and filters["start"] > filters["end"]
    ):
        raise FilterError("The start time must be before the end time.")
    return filters
