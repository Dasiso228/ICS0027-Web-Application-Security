"""Registration and login use independent verification and encryption salts."""
import secrets
import sqlite3
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for
import database
from crypto_utils import VaultError, derive_key, hash_password, verify_password
from security import audit, form_session, form_value, get_db, issue_session, kdf_slot, require_login, store
from validation import ValidationError, login_name, master_password

bp = Blueprint("auth", __name__)
LOGIN_ERROR = "Invalid username or master password."


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        if g.pm_session is not None and g.pm_session.user_id is not None:
            return redirect(url_for("vault.list_vault"), code=303)
        form_session()
        return render_template("auth.html", registering=True)
    try:
        name = login_name(form_value("login_username"))
        password = master_password(form_value("master_password"))
        if password != form_value("confirm_password"):
            raise ValidationError("The master passwords do not match.")
        salt = secrets.token_bytes(16)
        with kdf_slot():
            encoded = hash_password(password)
            key = derive_key(password, salt)
        user_id = database.create_user(get_db(), name, encoded, salt)
    except ValidationError as error:
        return render_template("auth.html", registering=True, error=str(error)), 400
    except sqlite3.IntegrityError:
        return render_template("auth.html", registering=True,
                               error="That login name is unavailable."), 400
    issue_session(user_id, key)
    audit("registration", "success", user_id)
    return redirect(url_for("vault.list_vault"), code=303)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if g.pm_session is not None and g.pm_session.user_id is not None:
            return redirect(url_for("vault.list_vault"), code=303)
        form_session()
        return render_template("auth.html", registering=False)
    try:
        name = login_name(form_value("login_username"))
        password = master_password(form_value("master_password"))
    except ValidationError:
        return render_template("auth.html", registering=False, error=LOGIN_ERROR), 401
    ip = request.remote_addr or "unknown"
    throttle = current_app.extensions["login_throttle"]
    if not throttle.allowed(name, ip):
        audit("login", "throttled")
        abort(429)
    user = database.find_user(get_db(), name)
    encoded = user["password_hash"] if user else current_app.extensions["dummy_hash"]
    key = None
    with kdf_slot():
        valid = verify_password(encoded, password)
        if valid and user is not None:
            try:
                key = derive_key(password, user["kdf_salt"], user["kdf_memory"],
                                 user["kdf_iterations"], user["kdf_parallelism"], user["kdf_version"])
            except VaultError:
                valid = False
    if not valid or user is None:
        throttle.failed(name, ip)
        audit("login", "failure", user["id"] if user else None)
        return render_template("auth.html", registering=False, error=LOGIN_ERROR), 401
    issue_session(user["id"], key)
    audit("login", "success", user["id"])
    return redirect(url_for("vault.list_vault"), code=303)


@bp.post("/logout")
@require_login
def logout():
    audit("logout", "success", g.pm_session.user_id)
    store().delete(g.pm_session.token)
    g.pm_session = None
    g.remove_session_cookie = True
    return redirect(url_for("auth.login"), code=303)
