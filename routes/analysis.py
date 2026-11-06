"""Detection analysis execution blueprints."""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    request,
    url_for,
)

import database
from services.detection_engine import analyze_all_datasets, analyze_dataset
from services.query_filters import FilterError, positive_int


bp = Blueprint("analysis", __name__, url_prefix="/analysis")


@bp.post("/run")
def run_dataset():
    """Run every detection rule against one stored dataset."""
    try:
        dataset_id = positive_int(
            request.form.get("dataset_id"), "Dataset ID"
        )
    except FilterError:
        dataset_id = None

    if dataset_id is None:
        flash("Select a dataset before running analysis.", "error")
        return redirect(url_for("findings.index"))

    try:
        result = analyze_dataset(
            database.get_db(), dataset_id, current_app.config
        )
    except ValueError:
        flash("That dataset does not exist.", "error")
        return redirect(url_for("dataset_history"))

    flash(
        f"Analysis complete for {result['filename']}: "
        f"{result['finding_count']} finding(s) across "
        f"{result['event_count']} event(s).",
        "success",
    )
    return redirect(url_for("findings.index", dataset_id=dataset_id))


@bp.post("/run-all")
def run_all():
    """Run detection against every stored dataset."""
    results = analyze_all_datasets(database.get_db(), current_app.config)
    total = sum(result["finding_count"] for result in results)
    flash(
        f"Analysis complete for {len(results)} dataset(s); "
        f"{total} finding(s) are stored.",
        "success",
    )
    return redirect(url_for("findings.index"))
