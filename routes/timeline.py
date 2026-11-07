"""Incident timeline blueprint."""

from flask import Blueprint, current_app, render_template, request

import database
from routes.helpers import pagination_context
from services.query_filters import FilterError, timeline_filters
from services.timeline_builder import build_timeline


bp = Blueprint("timeline", __name__)


@bp.route("/timeline")
def index():
    """Render a chronological, filtered investigation timeline."""
    try:
        filters = timeline_filters(request.args)
        page = max(1, int(request.args.get("page", 1) or 1))
    except (FilterError, ValueError) as exc:
        return _render_error(str(exc))

    connection = database.get_db()
    per_page = max(
        10, min(int(current_app.config.get("PAGE_SIZE", 50)) * 2, 200)
    )
    timeline = build_timeline(
        connection,
        filters,
        page=page,
        per_page=per_page,
        gap_minutes=int(
            current_app.config.get("DETECTION_TIMELINE_GAP_MINUTES", 60)
        ),
    )

    return render_template(
        "timeline.html",
        timeline=timeline,
        groups=timeline["groups"],
        events=timeline["events"],
        filter_options=database.get_filter_options(connection),
        datasets=database.list_datasets(connection),
        error=None,
        **pagination_context(timeline, "timeline.index"),
    )


def _render_error(message):
    connection = database.get_db()
    result = {"page": 1, "per_page": 0, "pages": 1, "total": 0}
    return (
        render_template(
            "timeline.html",
            timeline=result,
            groups=[],
            events=[],
            filter_options=database.get_filter_options(connection),
            datasets=database.list_datasets(connection),
            error=message,
            **pagination_context(result, "timeline.index"),
        ),
        400,
    )
