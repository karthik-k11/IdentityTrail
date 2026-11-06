"""Identity activity explorer blueprints."""

from flask import Blueprint, abort, current_app, render_template, request

import database
from routes.helpers import pagination_context
from services.identity_analyzer import (
    get_identity_activity,
    get_identity_detail,
    list_identities,
)
from services.identity_keys import decode_identity_key
from services.query_filters import (
    FilterError,
    normalize_time_bound,
    optional_text,
)


bp = Blueprint("identities", __name__)


def _page_size():
    return max(10, min(int(current_app.config.get("PAGE_SIZE", 50)), 200))


@bp.route("/identities")
def index():
    """List identities aggregated from stored CloudTrail events."""
    try:
        search = optional_text(request.args.get("search"))
        page = max(1, int(request.args.get("page", 1) or 1))
    except (FilterError, ValueError) as exc:
        return _render_list_error(str(exc))

    result = list_identities(
        database.get_db(),
        search=search,
        page=page,
        per_page=_page_size(),
    )
    return render_template(
        "identities.html",
        result=result,
        identities=result["items"],
        search=search or "",
        error=None,
        **pagination_context(result, "identities.index"),
    )


def _render_list_error(message):
    result = {
        "items": [],
        "total": 0,
        "page": 1,
        "per_page": 0,
        "pages": 1,
    }
    return (
        render_template(
            "identities.html",
            result=result,
            identities=[],
            search=request.args.get("search", ""),
            error=message,
            **pagination_context(result, "identities.index"),
        ),
        400,
    )


@bp.route("/identities/<token>")
def detail(token):
    """Show an identity profile, findings, categories, and activity."""
    identity_key = decode_identity_key(token)
    if identity_key is None:
        abort(404)

    try:
        filters = _activity_filters(request.args)
        page = max(1, int(request.args.get("page", 1) or 1))
    except (FilterError, ValueError) as exc:
        return _render_detail_error(token, identity_key, str(exc))

    connection = database.get_db()
    profile = get_identity_detail(connection, identity_key)
    if profile is None:
        abort(404)

    result = get_identity_activity(
        connection,
        identity_key,
        page=page,
        per_page=_page_size(),
        **filters,
    )

    return render_template(
        "identity_detail.html",
        profile=profile,
        identity_key=identity_key,
        token=token,
        activity=result["items"],
        error=None,
        **pagination_context(result, "identities.detail", token=token),
    )


def _activity_filters(args):
    return {
        "event_name": optional_text(args.get("event_name")),
        "source_ip": optional_text(args.get("source_ip")),
        "aws_region": optional_text(args.get("region")),
        "start": normalize_time_bound(args.get("start")),
        "end": normalize_time_bound(args.get("end"), end=True),
    }


def _render_detail_error(token, identity_key, message):
    connection = database.get_db()
    profile = get_identity_detail(connection, identity_key)
    if profile is None:
        abort(404)
    result = {
        "items": [],
        "total": 0,
        "page": 1,
        "per_page": 0,
        "pages": 1,
    }
    return (
        render_template(
            "identity_detail.html",
            profile=profile,
            identity_key=identity_key,
            token=token,
            activity=[],
            error=message,
            **pagination_context(
                result, "identities.detail", token=token
            ),
        ),
        400,
    )
