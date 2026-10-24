"""Authentication: first-run setup, login, logout, own profile (FR1, NFR1)."""
from datetime import timedelta
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db
from ..forms import LoginForm, ProfileForm, SetupForm
from ..models import User, utcnow
from ..services import audit

bp = Blueprint("auth", __name__)


def _safe_next(target):
    if not target:
        return None
    parts = urlparse(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the first administrator. Disabled once any user exists."""
    if User.query.count() > 0:
        return redirect(url_for("auth.login"))
    form = SetupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role="admin")
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        audit.record("setup_admin", "user", user.user_id, f"First administrator '{user.username}' created",
                     user_id=user.user_id)
        db.session.commit()
        login_user(user)
        flash("Administrator account created. Next, register the first device you want to monitor.", "success")
        return redirect(url_for("dashboard.index"))
    return render_template("auth/setup.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if User.query.count() == 0:
        return redirect(url_for("auth.setup"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.username.ilike(form.username.data)).first()
        now = utcnow()
        generic = "Invalid username or password."
        if user and user.locked_until and user.locked_until > now:
            mins = int((user.locked_until - now).total_seconds() // 60) + 1
            audit.record("login_locked", "user", user.user_id, "Login attempt while locked", user_id=user.user_id,
                         commit=True)
            flash(f"Too many failed attempts. Try again in about {mins} minute(s).", "danger")
            return render_template("auth/login.html", form=form), 429
        if user is None or not user.check_password(form.password.data):
            if user is not None:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                    user.locked_until = now + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                    user.failed_logins = 0
            audit.record("login_failed", "user", user.user_id if user else None,
                         f"Failed sign-in for '{form.username.data[:50]}'", user_id=user.user_id if user else None)
            db.session.commit()
            flash(generic, "danger")
            return render_template("auth/login.html", form=form), 401
        if not user.is_active_account:
            flash("This account has been deactivated. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form), 403
        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = now
        login_user(user, remember=form.remember.data, duration=timedelta(days=7))
        audit.record("login", "user", user.user_id, "Signed in", user_id=user.user_id)
        db.session.commit()
        return redirect(_safe_next(request.args.get("next")) or url_for("dashboard.index"))
    return render_template("auth/login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.record("logout", "user", current_user.user_id, "Signed out", commit=True)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        email = form.email.data.lower()
        clash = User.query.filter(User.email.ilike(email), User.user_id != current_user.user_id).first()
        if clash:
            form.email.errors.append("That email address is already registered.")
            return render_template("auth/profile.html", form=form), 400
        if form.new_password.data:
            if not form.current_password.data or not current_user.check_password(form.current_password.data):
                form.current_password.errors.append("Current password is incorrect.")
                return render_template("auth/profile.html", form=form), 400
            current_user.set_password(form.new_password.data)
            audit.record("password_changed", "user", current_user.user_id, "Changed own password")
        current_user.email = email
        current_user.receive_alert_emails = form.receive_alert_emails.data
        audit.record("profile_updated", "user", current_user.user_id, "Updated own profile")
        db.session.commit()
        flash("Profile saved.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("auth/profile.html", form=form)
