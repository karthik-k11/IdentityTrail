from flask import Flask, jsonify

from config import Config
from database import init_app as init_database


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    init_database(app)

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

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )