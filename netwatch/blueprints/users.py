"""User account management (FR2 — 'Manage User Accounts' use case). Administrators only."""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

from . import admin_required
from ..extensions import db
from ..forms import ConfirmForm, UserForm
from ..models import User, utcnow
from ..services import audit
from ..utils import int_arg

bp = Blueprint("users", __name__, url_prefix="/users")


def _active_admins(excluding=None):
    q = User.query.filter_by(role="admin", is_active_account=True)
    if excluding:
        q = q.filter(User.user_id != excluding)
    return q.count()


@bp.route("/")
@admin_required
def index():
    q = (request.args.get("q") or "").strip()[:50]
    query = User.query
    if q:
        query = query.filter(or_(User.username.ilike(f"%{q}%"), User.email.ilike(f"%{q}%")))
    page = query.order_by(User.username).paginate(page=int_arg("page", 1, 1), per_page=20, error_out=False)
    return render_template("users/index.html", page=page, q=q, form=ConfirmForm(), now_utc=utcnow())


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def create():
    form = UserForm()
    if form.validate_on_submit():
        u = User(username=form.username.data, email=form.email.data.lower(), role=form.role.data,
                 is_active_account=form.is_active_account.data, receive_alert_emails=form.receive_alert_emails.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.flush()
        audit.record("user_created", "user", u.user_id, f"Created {u.role} '{u.username}'")
        db.session.commit()
        flash(f"Account “{u.username}” created.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", form=form, user=None), (400 if form.errors else 200)


@bp.route("/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(user_id):
    u = db.session.get(User, user_id) or abort(404)
    form = UserForm(obj=u, user_id=u.user_id)
    if request.method == "GET":
        form.password.data = ""
    if form.validate_on_submit():
        demoting = u.role == "admin" and (form.role.data != "admin" or not form.is_active_account.data)
        if demoting and _active_admins(excluding=u.user_id) == 0:
            flash("At least one active administrator is required — this change was not saved.", "danger")
            return render_template("users/form.html", form=form, user=u), 400
        u.username, u.email, u.role = form.username.data, form.email.data.lower(), form.role.data
        u.is_active_account = form.is_active_account.data
        u.receive_alert_emails = form.receive_alert_emails.data
        if form.password.data:
            u.set_password(form.password.data)
            u.failed_logins, u.locked_until = 0, None
        audit.record("user_updated", "user", u.user_id, f"Edited '{u.username}' (role {u.role})")
        db.session.commit()
        flash("Account updated.", "success")
        return redirect(url_for("users.index"))
    return render_template("users/form.html", form=form, user=u), (400 if form.errors else 200)


@bp.route("/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete(user_id):
    u = db.session.get(User, user_id) or abort(404)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    if u.user_id == current_user.user_id:
        flash("You cannot delete your own account while signed in.", "danger")
        return redirect(url_for("users.index"))
    if u.role == "admin" and _active_admins(excluding=u.user_id) == 0:
        flash("You cannot delete the last administrator.", "danger")
        return redirect(url_for("users.index"))
    audit.record("user_deleted", "user", u.user_id, f"Deleted '{u.username}'")
    db.session.delete(u)
    db.session.commit()
    flash(f"Account “{u.username}” deleted.", "success")
    return redirect(url_for("users.index"))
