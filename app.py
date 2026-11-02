from flask import Flask, jsonify

from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

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