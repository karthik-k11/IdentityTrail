import hmac
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, render_template, request, session

from config import Config
from database import get_db, init_app as init_database, list_datasets
from routes import register_blueprints
from services.cloudtrail_ingestion import (
    IngestionPersistenceError,
    IngestionValidationError,
    ingest_cloudtrail,
)


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    init_database(app)
    register_blueprints(app)

    @app.before_request
    def protect_state_changes():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None

        expected = session.get("_csrf_token")
        supplied = request.form.get("_csrf_token") or request.headers.get(
            "X-CSRF-Token"
        )
        if (
            not isinstance(expected, str)
            or not isinstance(supplied, str)
            or not hmac.compare_digest(expected, supplied)
        ):
            abort(400, description="Request security validation failed.")

        origin = request.headers.get("Origin")
        if origin and origin != "null":
            try:
                supplied_origin = urlsplit(origin)
                request_origin = urlsplit(request.host_url)
                origin_matches = (
                    supplied_origin.scheme == request_origin.scheme
                    and supplied_origin.netloc.casefold()
                    == request_origin.netloc.casefold()
                    and not supplied_origin.path
                    and not supplied_origin.query
                    and not supplied_origin.fragment
                )
            except ValueError:
                origin_matches = False
            if not origin_matches:
                abort(400, description="Request security validation failed.")

        if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            abort(400, description="Request security validation failed.")
        return None

    @app.context_processor
    def inject_csrf_token():
        token = session.get("_csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return {"csrf_token": token}

    @app.template_filter("filesize")
    def format_filesize(size):
        try:
            size = int(size)
        except (TypeError, ValueError):
            return "—"

        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} MB"

    @app.after_request
    def add_security_headers(response):
        """Apply lightweight local-workbench security headers."""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        return response

    @app.errorhandler(404)
    def not_found(error):
        return (
            render_template(
                "error.html",
                code=404,
                title="Not found",
                message=(
                    "The requested page, dataset, event, identity, or "
                    "finding does not exist."
                ),
            ),
            404,
        )

    @app.errorhandler(400)
    def bad_request(error):
        return (
            render_template(
                "error.html",
                code=400,
                title="Invalid request",
                message=(
                    "The request could not be validated. Reload the page and "
                    "try again."
                ),
            ),
            400,
        )

    @app.errorhandler(500)
    def server_error(error):
        return (
            render_template(
                "error.html",
                code=500,
                title="Unexpected error",
                message=(
                    "The request could not be completed. No uploaded content "
                    "was executed. Check the application log for details."
                ),
            ),
            500,
        )

    @app.errorhandler(413)
    def upload_too_large(error):
        max_mb = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        return (
            render_template(
                "upload.html",
                error=f"The upload is too large. Maximum size is {max_mb:g} MB.",
            ),
            413,
        )

    @app.route("/")
    def home():
        return jsonify({
            "application": "IdentityTrail",
            "status": "running",
            "message": "Cloud Identity Investigation Workbench"
        })

    @app.route("/health")
    def health():
        return jsonify({
            "status": "healthy"
        })

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "GET":
            return render_template("upload.html")

        uploaded_file = request.files.get("file")
        if uploaded_file is None or not uploaded_file.filename:
            return render_template(
                "upload.html",
                error="Please select a CloudTrail JSON file.",
            ), 400

        filename = _safe_filename(uploaded_file.filename)
        if Path(filename).suffix.lower() != ".json":
            return render_template(
                "upload.html",
                error="Only .json CloudTrail files are supported.",
            ), 400

        content = uploaded_file.read()
        if not content:
            return render_template(
                "upload.html",
                error="The uploaded file is empty.",
            ), 400

        max_content_length = app.config["MAX_CONTENT_LENGTH"]
        if len(content) > max_content_length:
            max_mb = max_content_length / (1024 * 1024)
            return render_template(
                "upload.html",
                error=f"The upload is too large. Maximum size is {max_mb:g} MB.",
            ), 413

        try:
            result = ingest_cloudtrail(
                get_db(),
                filename=filename,
                content=content,
                max_events=app.config["MAX_EVENT_COUNT"],
            )
        except IngestionValidationError as exc:
            return render_template(
                "upload.html",
                error=str(exc),
                error_details=exc.errors,
            ), 400
        except IngestionPersistenceError:
            return render_template(
                "upload.html",
                error=(
                    "The upload could not be saved to the database. "
                    "No data was committed."
                ),
            ), 500

        return render_template("upload.html", result=result)

    @app.route("/datasets")
    def dataset_history():
        return render_template(
            "datasets.html",
            datasets=list_datasets(get_db()),
        )

    return app


def _safe_filename(filename):
    """Return a display-safe basename without using it as a filesystem path."""
    return (filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
