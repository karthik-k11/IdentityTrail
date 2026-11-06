"""Investigation report preview and export blueprints."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    render_template,
    request,
    url_for,
)

import database
from routes.helpers import format_json
from services.query_filters import FilterError, report_filters
from services.report_generator import (
    ReportScopeError,
    build_report,
    report_to_csv,
    report_to_json,
)


bp = Blueprint("reports", __name__, url_prefix="/reports")


def _build(connection, args, *, preview=False):
    filters = report_filters(args)
    if preview:
        event_limit = 50
        finding_limit = 100
    else:
        event_limit = max(
            10, int(current_app.config.get("REPORT_EVENT_LIMIT", 500))
        )
        finding_limit = 2000
    return build_report(
        connection,
        dataset_id=filters["dataset_id"],
        identity_key=filters["identity_key"],
        start=filters["start"],
        end=filters["end"],
        event_limit=event_limit,
        finding_limit=finding_limit,
    )


@bp.route("")
def index():
    """Show report scope controls and a preview built from stored data."""
    connection = database.get_db()
    try:
        report = _build(connection, request.args, preview=True)
        error = None
        status = 200
    except FilterError as exc:
        report = None
        error = str(exc)
        status = 400
    except ReportScopeError:
        abort(404)

    if report is not None:
        report_json_preview = format_json(report["summary"])
        export_arguments = {
            key: value
            for key, value in request.args.items()
            if key in {"dataset_id", "identity", "start", "end"}
        }
        json_url = url_for("reports.export_json", **export_arguments)
        csv_url = url_for("reports.export_csv", **export_arguments)
    else:
        json_url = None
        csv_url = None

    return (
        render_template(
            "reports.html",
            report=report,
            report_json_preview=(
                report_json_preview if report is not None else ""
            ),
            datasets=database.list_datasets(connection),
            error=error,
            json_url=json_url,
            csv_url=csv_url,
        ),
        status,
    )


@bp.route("/json")
def export_json():
    """Download a valid JSON investigation report."""
    connection = database.get_db()
    try:
        report = _build(connection, request.args)
    except FilterError as exc:
        return Response(
            f"Invalid report parameters: {exc}",
            status=400,
            mimetype="text/plain",
        )
    except ReportScopeError:
        abort(404)

    payload = report_to_json(report)
    return Response(
        payload,
        mimetype="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_download_name(report, "json")}"'
            ),
            "Cache-Control": "no-store",
        },
    )


@bp.route("/csv")
def export_csv():
    """Download a CSV investigation report with formula injection protection."""
    connection = database.get_db()
    try:
        report = _build(connection, request.args)
    except FilterError as exc:
        return Response(
            f"Invalid report parameters: {exc}",
            status=400,
            mimetype="text/plain",
        )
    except ReportScopeError:
        abort(404)

    payload = report_to_csv(report)
    return Response(
        payload,
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_download_name(report, "csv")}"'
            ),
            "Cache-Control": "no-store",
        },
    )


def _download_name(report, extension):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dataset_id = (report.get("scope") or {}).get("dataset_id")
    scope = f"dataset-{dataset_id}" if dataset_id is not None else "all-data"
    return f"identitytrail-report-{scope}-{stamp}.{extension}"
