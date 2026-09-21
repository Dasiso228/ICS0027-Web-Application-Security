"""Checkpoint 1 scaffold. Authentication and vault operations are planned."""

from flask import Flask, jsonify, render_template


def create_app():
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=64 * 1024,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
    )

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok", stage="checkpoint-1-scaffold")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
