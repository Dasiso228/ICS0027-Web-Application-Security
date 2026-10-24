"""Every database lookup is constrained by the authenticated owner."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for
import database
from crypto_utils import decrypt_entry
from security import audit, form_value, get_db, require_login
from validation import FIELDS, ValidationError, entry_fields

bp = Blueprint("vault", __name__)


def owned_entry(entry_id):
    row = database.find_entry(get_db(), g.pm_session.user_id, entry_id)
    if row is None:
        audit("entry_access", "denied", g.pm_session.user_id)
        abort(404)
    return row


def submitted_entry():
    return entry_fields({name: form_value(name) for name in FIELDS})


@bp.get("/vault")
@require_login
def list_vault():
    entries = []
    for row in database.list_entries(get_db(), g.pm_session.user_id):
        values = decrypt_entry(g.pm_session.key, row)
        entries.append({"id": row["id"], "title": values["title"], "website_url": values["website_url"]})
    return render_template("vault.html", entries=entries)


@bp.route("/vault/new", methods=["GET", "POST"])
@require_login
def new_entry():
    if request.method == "GET":
        return render_template("entry_form.html", editing=False, values={})
    try:
        values = submitted_entry()
    except ValidationError as error:
        return render_template("entry_form.html", editing=False, values={}, error=str(error)), 400
    entry_id = database.create_entry(get_db(), g.pm_session.user_id, g.pm_session.key, values)
    return redirect(url_for("vault.show_entry", entry_id=entry_id), code=303)


@bp.get("/vault/<int:entry_id>")
@require_login
def show_entry(entry_id):
    values = decrypt_entry(g.pm_session.key, owned_entry(entry_id))
    return render_template("entry.html", entry_id=entry_id, values=values)


@bp.route("/vault/<int:entry_id>/edit", methods=["GET", "POST"])
@require_login
def edit_entry(entry_id):
    row = owned_entry(entry_id)
    values = decrypt_entry(g.pm_session.key, row)
    if request.method == "GET":
        return render_template("entry_form.html", editing=True, values=values)
    try:
        values = submitted_entry()
    except ValidationError as error:
        return render_template("entry_form.html", editing=True, values={}, error=str(error)), 400
    if not database.update_entry(get_db(), g.pm_session.user_id, entry_id, g.pm_session.key, values):
        abort(404)
    return redirect(url_for("vault.show_entry", entry_id=entry_id), code=303)


@bp.post("/vault/<int:entry_id>/delete")
@require_login
def delete_entry(entry_id):
    owned_entry(entry_id)
    if form_value("confirm_delete") != "yes":
        abort(400)
    if not database.delete_entry(get_db(), g.pm_session.user_id, entry_id):
        abort(404)
    return redirect(url_for("vault.list_vault"), code=303)
