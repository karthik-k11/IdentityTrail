"""Blueprint registration for the IdentityTrail application."""

from routes.analysis import bp as analysis_bp
from routes.dashboard import bp as dashboard_bp
from routes.datasets import bp as datasets_bp
from routes.events import bp as events_bp
from routes.findings import bp as findings_bp
from routes.identities import bp as identities_bp
from routes.reports import bp as reports_bp
from routes.timeline import bp as timeline_bp


BLUEPRINTS = (
    dashboard_bp,
    events_bp,
    identities_bp,
    findings_bp,
    analysis_bp,
    timeline_bp,
    reports_bp,
    datasets_bp,
)


def register_blueprints(app):
    """Register every feature blueprint on the Flask application."""
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)
