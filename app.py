"""One-process HTTPS development application for ICS0027 Checkpoint 3."""
from functools import lru_cache
import logging
from pathlib import Path
import secrets
import threading
import time
from flask import Flask, abort, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, SecurityError
import auth_routes
import database
import vault_routes
from audit_log import audit, configure_logging, error_location
from crypto_utils import VaultError, hash_password
from security import COOKIE, LoginThrottle, SessionStore
from validation import ValidationError


@lru_cache(maxsize=1)
def dummy_hash():
    return hash_password(secrets.token_urlsafe(32))


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        DATABASE=str(Path(app.instance_path) / "vault.sqlite3"),
        MAX_CONTENT_LENGTH=64 * 1024,
        MAX_FORM_MEMORY_SIZE=64 * 1024,
        MAX_FORM_PARTS=32,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
        SESSION_SWEEP=True,
        CLOCK=time.monotonic,
    )
    if test_config:
        app.config.update(test_config)
    # The security log lives next to the database, in the private instance directory.
    app.config.setdefault("LOG_FILE", str(Path(app.config["DATABASE"]).with_name("security.log")))
    # Escape every template, not only files ending in .html (defence in depth against XSS).
    app.jinja_env.autoescape = True
    database.initialize(app.config["DATABASE"])
    configure_logging(app)
    app.extensions["sessions"] = SessionStore(app.config["CLOCK"], sweep=app.config["SESSION_SWEEP"])
    app.extensions["login_throttle"] = LoginThrottle(app.config["CLOCK"])
    app.extensions["kdf_slots"] = threading.BoundedSemaphore(2)
    app.extensions["dummy_hash"] = dummy_hash()

    @app.before_request
    def validate_request():
        g.request_id = secrets.token_hex(8)
        g.pm_session = None
        if isinstance(request.routing_exception, SecurityError):
            # An untrusted Host leaves no URL adapter, so stop before CSRF checks or templates run.
            raise request.routing_exception
        if not request.is_secure:
            abort(400)
        token = request.cookies.get(COOKIE, "")
        if len(token) == 43:
            g.pm_session = app.extensions["sessions"].get(token)
        if request.method == "POST":
            values = request.form.getlist("csrf_token")
            if (g.pm_session is None or len(values) != 1 or len(values[0]) != 43
                    or not secrets.compare_digest(values[0].encode(), g.pm_session.csrf.encode())):
                audit("csrf", "denied", g.pm_session.user_id if g.pm_session else None)
                abort(400)
            if request.files:
                abort(400)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=3600"
        if getattr(g, "remove_session_cookie", False):
            response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
        elif getattr(g, "new_session_cookie", None):
            token, max_age = g.new_session_cookie
            response.set_cookie(COOKIE, token, max_age=max_age, path="/",
                                secure=True, httponly=True, samesite="Strict")
        return response

    @app.context_processor
    def session_context():
        record = getattr(g, "pm_session", None)
        return {"csrf_token": record.csrf if record else "",
                "signed_in": record is not None and record.user_id is not None}

    @app.teardown_appcontext
    def close_database(error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.errorhandler(Exception)
    def handle_error(error):
        record = getattr(g, "pm_session", None)
        user_id = record.user_id if record else None
        if isinstance(error, SecurityError):
            # Host rejection happens before Flask can construct a URL adapter.
            audit("http_error", "rejected", user_id, status=400, reason="untrusted_host")
            return "Invalid Host header.", 400, {"Content-Type": "text/plain; charset=utf-8"}
        if isinstance(error, HTTPException):
            code = error.code
        elif isinstance(error, (VaultError, ValidationError)):
            code = 400
        else:
            code = 500
        messages = {400: "Unable to process this request.", 404: "Not found.",
                    405: "Method not allowed.", 413: "Request too large.",
                    429: "Too many login attempts. Try again in five minutes.",
                    503: "The application is busy. Please try again shortly."}
        if isinstance(error, VaultError):
            audit("vault_decryption", "failure", user_id, level=logging.ERROR)
        if code == 500:
            # Type and location go to the server log only; the message may contain data.
            audit("server_error", "failure", user_id, level=logging.ERROR, status=code,
                  error_type=type(error).__name__, location=error_location(error))
        else:
            audit("http_error", "rejected" if code < 500 else "failure", user_id,
                  level=logging.WARNING if code < 500 else logging.ERROR, status=code)
        return render_template("error.html", message=messages.get(code, "An internal error occurred."),
                               request_id=g.get("request_id")), code

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok", stage="checkpoint-2")

    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(vault_routes.bp)
    return app


if __name__ == "__main__":
    raise SystemExit("Use the HTTPS Flask command in docs/DEVELOPMENT.md.")
