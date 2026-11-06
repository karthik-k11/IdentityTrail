"""Dataset management blueprints."""

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

import database


bp = Blueprint("datasets", __name__)


@bp.route("/datasets/<int:dataset_id>/delete", methods=["GET", "POST"])
def delete(dataset_id):
    """Confirm and delete one dataset with its dependent records."""
    connection = database.get_db()
    dataset = database.get_dataset(connection, dataset_id)
    if dataset is None:
        abort(404)

    stored_events = connection.execute(
        "SELECT COUNT(*) FROM events WHERE dataset_id = ?", (dataset_id,)
    ).fetchone()[0]
    finding_count = connection.execute(
        "SELECT COUNT(*) FROM findings WHERE dataset_id = ?", (dataset_id,)
    ).fetchone()[0]

    error = None
    if request.method == "POST":
        if request.form.get("confirm") != "yes":
            error = "Tick the confirmation box before deleting the dataset."
            return (
                render_template(
                    "dataset_delete.html",
                    dataset=dict(dataset),
                    stored_events=stored_events,
                    finding_count=finding_count,
                    error=error,
                ),
                400,
            )

        deleted = database.delete_dataset(connection, dataset_id)
        if deleted:
            flash(
                f"Dataset #{dataset_id} and its stored investigation data "
                "were deleted.",
                "success",
            )
        else:
            flash("That dataset no longer exists.", "error")
        return redirect(url_for("dataset_history"))

    return render_template(
        "dataset_delete.html",
        dataset=dict(dataset),
        stored_events=stored_events,
        finding_count=finding_count,
        error=error,
    )
