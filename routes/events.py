"""Event explorer blueprints."""

from flask import Blueprint, abort, current_app, render_template, request

import database
from routes.helpers import format_json, load_json, pagination_context
from services.identity_analyzer import categorize_event
from services.query_filters import FilterError, common_filters, optional_text
from services.redaction import mask_access_key, redact_sensitive


bp = Blueprint("events", __name__)


def _page_size():
    return max(10, min(int(current_app.config.get("PAGE_SIZE", 50)), 200))


@bp.route("/events")
def index():
    """List stored CloudTrail events with safe filters and pagination."""
    try:
        filters = common_filters(request.args)
        search = filters.pop("search", None)
        filters["search"] = search
        page = max(1, int(request.args.get("page", 1) or 1))
    except (FilterError, ValueError) as exc:
        return _render_error(str(exc))

    connection = database.get_db()
    per_page = _page_size()
    offset = (page - 1) * per_page
    events = [
        dict(row)
        for row in database.list_events(
            connection, limit=per_page, offset=offset, **filters
        )
    ]
    total = database.count_events(connection, **filters)

    for event in events:
        event["category"] = categorize_event(
            event.get("event_name"), event.get("event_source")
        )
        event["access_key_masked"] = mask_access_key(
            event.get("access_key_id")
        )

    result = {
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "total": total,
    }

    return render_template(
        "events.html",
        events=events,
        filter_options=database.get_filter_options(connection),
        error=None,
        **pagination_context(result, "events.index"),
    )


def _render_error(message):
    connection = database.get_db()
    result = {"page": 1, "per_page": 0, "pages": 1, "total": 0}
    return (
        render_template(
            "events.html",
            events=[],
            filter_options=database.get_filter_options(connection),
            error=message,
            **pagination_context(result, "events.index"),
        ),
        400,
    )


@bp.route("/events/<int:event_id>")
def detail(event_id):
    """Show normalized and raw information for a single event."""
    connection = database.get_db()
    event = database.get_event(connection, event_id)
    if event is None:
        abort(404)

    raw_event = load_json(event["raw_event_json"], {})
    normalized_event = load_json(event["normalized_event_json"], {})
    findings = database.get_findings_for_event(connection, event_id)

    event_data = dict(event)
    event_data["category"] = categorize_event(
        event_data.get("event_name"), event_data.get("event_source")
    )
    event_data["access_key_masked"] = mask_access_key(
        event_data.get("access_key_id")
    )

    return render_template(
        "event_detail.html",
        event=event_data,
        raw_json=format_json(redact_sensitive(raw_event)),
        normalized_json=format_json(redact_sensitive(normalized_event)),
        findings=[dict(finding) for finding in findings],
    )
