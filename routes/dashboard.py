"""Dashboard blueprint."""

from flask import Blueprint, render_template

from database import get_db
from services.dashboard_service import build_dashboard


bp = Blueprint("dashboard", __name__)


@bp.route("/dashboard")
def index():
    """Render the investigation dashboard from stored database metrics."""
    data = build_dashboard(get_db())
    return render_template("dashboard.html", **data)
