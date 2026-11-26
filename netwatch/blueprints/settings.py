"""System settings, email test and audit log (configuration pages)."""
import platform

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from . import admin_required
from ..extensions import db
from ..forms import ConfirmForm
from ..models import AuditLog, User
from ..services import audit, collector, notifier, scheduler
from ..services import settings as app_settings
from ..utils import date_range_from_args, int_arg, per_page_arg

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/", methods=["GET", "POST"])
@admin_required
def index():
    form = ConfirmForm()
    errors = {}
    if request.method == "POST":
        if not form.validate_on_submit():
            flash("Your session expired — please try again.", "danger")
            return redirect(url_for("settings.index"))
        changed = []
        for key, (kind, *_rest) in app_settings.DEFAULTS.items():
            if kind is not bool and key not in request.form:
                continue  # not on the submitted form (e.g. a setting added later): keep its value
            raw =("true" if request.form.get(key) else "false") if kind is bool else request.form.get(key, "")
            if kind is str and key == "extra_alert_recipients":
                emails = [e.strip() for e in raw.split(",") if e.strip()]
                bad = [e for e in emails if "@" not in e or " " in e or len(e) > 120]
                if bad:
                    errors[key] = "Invalid address: " + ", ".join(bad[:3])
                    continue
                raw = ", ".join(emails)
            try:
                old = app_settings.get(key)
                new = app_settings.set_value(key, raw)
                if new != old:
                    changed.append(f"{key}={new}")
            except (ValueError, TypeError) as exc:
                errors[key] = str(exc) if "between" in str(exc) else "Enter a whole number."
        if errors:
            db.session.rollback()
            flash("Some settings were invalid; nothing was saved.", "danger")
        else:
            if changed:
                audit.record("settings_updated", "settings", None, "; ".join(changed)[:500])
            db.session.commit()
            flash("Settings saved." if changed else "No changes to save.", "success" if changed else "info")
            return redirect(url_for("settings.index"))
    cfg = current_app.config
    env = {
        "smtp_configured": notifier.smtp_configured(),
        "mail_server": cfg.get("MAIL_SERVER") or None, "mail_port": cfg.get("MAIL_PORT"),
        "mail_from": cfg.get("MAIL_FROM") or None,
        "mail_tls": "SSL" if cfg.get("MAIL_USE_SSL") else ("STARTTLS" if cfg.get("MAIL_USE_TLS") else "none"),
        "recipients": notifier.recipients(),
        "monitor_method": cfg["MONITOR_METHOD"], "ping": collector.icmp_status(),
        "tcp_ports": cfg["TCP_PROBE_PORTS"], "ping_count": cfg["PING_COUNT"],
        "ping_timeout": cfg["PING_TIMEOUT_SECONDS"],
        "db_engine": db.engine.dialect.name, "platform": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(), "scheduler": scheduler.status(),
        "tz": cfg["DISPLAY_TIMEZONE"],
    }
    return render_template("settings/index.html", values=app_settings.get_all(), defs=app_settings.DEFAULTS,
                           errors=errors, env=env, form=form, form_values=request.form if errors else None)


@bp.route("/test-email", methods=["POST"])
@admin_required
def test_email():
    if not ConfirmForm().validate_on_submit():
        flash("Your session expired — please try again.", "danger")
        return redirect(url_for("settings.index"))
    status = notifier.send_email("[Netwatch] Test email",
                                 "This is a test message from Netwatch. If you received it, email alerts are "
                                 "configured correctly.\n", to=[current_user.email])
    audit.record("test_email", "settings", None, f"Test email to {current_user.email}: {status}", commit=True)
    messages = {
        "sent": ("success", f"Test email sent to {current_user.email}. Check your inbox (and spam folder)."),
        "failed": ("danger", "The SMTP server rejected the message or could not be reached. See the application "
                             "log for the technical reason."),
        "not_configured": ("warning", "SMTP is not configured. Set MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, "
                                      "MAIL_PASSWORD and MAIL_FROM in your .env file and restart."),
        "disabled": ("warning", "Email notifications are switched off in the settings below."),
        "no_recipients": ("warning", "No recipient address."),
    }
    cat, msg = messages.get(status, ("info", status))
    flash(msg, cat)
    return redirect(url_for("settings.index"))


@bp.route("/audit")
@admin_required
def audit_log():
    action = (request.args.get("action") or "").strip()[:50]
    user_id = int_arg("user", 0)
    q = AuditLog.query
    if action:
        q = q.filter(AuditLog.action == action)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)
    if request.args.get("start") or request.args.get("end"):
        s, e, *_rest, err = date_range_from_args(default_days=7)
        if err:
            flash(err, "warning")
        q = q.filter(AuditLog.log_time >= s, AuditLog.log_time <= e)
    page = q.order_by(AuditLog.log_time.desc(), AuditLog.log_id.desc()).paginate(
        page=int_arg("page", 1, 1), per_page=per_page_arg(50), error_out=False)
    actions = [a for (a,) in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action)]
    return render_template("settings/audit.html", page=page, action=action, user_id=user_id, actions=actions,
                           users=User.query.order_by(User.username).all(),
                           start=request.args.get("start", ""), end=request.args.get("end", ""))
