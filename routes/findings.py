"""Detection findings blueprints."""

from flask import Blueprint, abort, current_app, render_template, request

import database
from routes.helpers import format_json, load_json, pagination_context
from services.query_filters import FilterError, finding_filters
from services.redaction import redact_sensitive


bp = Blueprint("findings", __name__)


def _page_size():
    return max(10, min(int(current_app.config.get("PAGE_SIZE", 50)), 200))


@bp.route("/findings")
def index():
    """List persisted findings with investigation filters."""
    try:
        filters = finding_filters(request.args)
        page = max(1, int(request.args.get("page", 1) or 1))
    except (FilterError, ValueError) as exc:
        return _render_error(str(exc))

    connection = database.get_db()
    per_page = _page_size()
    offset = (page - 1) * per_page
    findings = [
        dict(row)
        for row in database.list_findings(
            connection, limit=per_page, offset=offset, **filters
        )
    ]
    total = database.count_findings(connection, **filters)
    result = {
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "total": total,
    }

    return render_template(
        "findings.html",
        findings=findings,
        filter_options=database.get_filter_options(connection),
        datasets=database.list_datasets(connection),
        analysis_runs=database.get_analysis_runs(connection),
        error=None,
        **pagination_context(result, "findings.index"),
    )


def _render_error(message):
    connection = database.get_db()
    result = {"page": 1, "per_page": 0, "pages": 1, "total": 0}
    return (
        render_template(
            "findings.html",
            findings=[],
            filter_options=database.get_filter_options(connection),
            datasets=database.list_datasets(connection),
            analysis_runs=database.get_analysis_runs(connection),
            error=message,
            **pagination_context(result, "findings.index"),
        ),
        400,
    )


@bp.route("/findings/<int:finding_id>")
def detail(finding_id):
    """Show a finding, its evidence, recommendations, and linked events."""
    connection = database.get_db()
    finding, related_events = database.get_finding(connection, finding_id)
    if finding is None:
        abort(404)

    evidence = redact_sensitive(
        load_json(finding["evidence_json"], {})
    )
    recommended_steps = load_json(finding["recommended_steps_json"], [])
    finding_data = dict(finding)
    finding_data["linked_ids"] = sorted(
        int(value)
        for value in str(finding_data.get("linked_event_ids") or "").split(",")
        if value.strip().isdigit()
    )

    return render_template(
        "finding_detail.html",
        finding=finding_data,
        evidence_json=format_json(evidence),
        recommended_steps=recommended_steps,
        related_events=[dict(event) for event in related_events],
    )
