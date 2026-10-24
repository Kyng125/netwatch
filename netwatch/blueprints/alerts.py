"""Alert inspection and handling (FR8, FR14)."""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from . import admin_required
from ..extensions import db
from ..forms import ConfirmForm
from ..models import Alert, Device, utcnow
from ..services import alerting, audit
from ..utils import date_range_from_args, int_arg, per_page_arg

bp = Blueprint("alerts", __name__, url_prefix="/alerts")

SORTS = {"opened": Alert.opened_at, "severity": Alert.severity, "status": Alert.status,
         "device": Device.device_name}


@bp.route("/")
@login_required
def index():
    status = request.args.get("status", "active")
    severity = request.args.get("severity", "")
    device_id = int_arg("device", 0)
    q = (request.args.get("q") or "").strip()[:100]
    sort = request.args.get("sort", "opened")
    order = request.args.get("order", "desc")
    query = Alert.query.join(Device)
    if status == "active":
        query = query.filter(Alert.status.in_(("open", "acknowledged")))
    elif status in Alert.STATUSES:
        query = query.filter(Alert.status == status)
    if severity in ("warning", "critical"):
        query = query.filter(Alert.severity == severity)
    if device_id:
        query = query.filter(Alert.device_id == device_id)
    date_error = None
    if request.args.get("start") or request.args.get("end"):
        s, e, *_rest, date_error = date_range_from_args(default_days=7)
        query = query.filter(Alert.opened_at >= s, Alert.opened_at <= e)
    if q:
        query = query.filter(or_(Alert.message.ilike(f"%{q}%"), Device.device_name.ilike(f"%{q}%")))
    col = SORTS.get(sort, Alert.opened_at)
    query = query.order_by(col.desc() if order == "desc" else col.asc(), Alert.alert_id.desc())
    page = query.paginate(page=int_arg("page", 1, 1), per_page=per_page_arg(), error_out=False)
    if date_error:
        flash(date_error, "warning")
    counts = {s: Alert.query.filter_by(status=s).count() for s in Alert.STATUSES}
    return render_template("alerts/index.html", page=page, status=status, severity=severity, device_id=device_id,
                           q=q, sort=sort, order=order, counts=counts, form=ConfirmForm(),
                           devices=Device.query.order_by(Device.device_name).all(),
                           start=request.args.get("start", ""), end=request.args.get("end", ""))


@bp.route("/<int:alert_id>")
@login_required
def detail(alert_id):
    a = db.session.get(Alert, alert_id) or abort(404)
    return render_template("alerts/detail.html", a=a, form=ConfirmForm())


def _back(alert_id):
    nxt = request.form.get("next") or ""
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//")
                    else url_for("alerts.detail", alert_id=alert_id))


@bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge(alert_id):
    a = db.session.get(Alert, alert_id) or abort(404)
    form = ConfirmForm()
    if not form.validate_on_submit():
        abort(400)
    if a.status != "open":
        flash("Only open alerts can be acknowledged.", "warning")
        return _back(alert_id)
    a.status = "acknowledged"
    a.acknowledged_at = utcnow()
    a.acknowledged_by = current_user.user_id
    if form.note.data:
        a.resolution_note = form.note.data
    audit.record("alert_acknowledged", "alert", a.alert_id, f"{a.device.device_name}: {a.message[:120]}")
    db.session.commit()
    flash(f"Alert #{a.alert_id} acknowledged. Reminder emails are paused for it.", "success")
    return _back(alert_id)


@bp.route("/<int:alert_id>/resolve", methods=["POST"])
@admin_required
def resolve(alert_id):
    a = db.session.get(Alert, alert_id) or abort(404)
    form = ConfirmForm()
    if not form.validate_on_submit():
        abort(400)
    if a.status == "resolved":
        flash("This alert is already closed.", "info")
        return _back(alert_id)
    if a.acknowledged_at is None:
        a.acknowledged_at = utcnow()
        a.acknowledged_by = current_user.user_id
    alerting.resolve(a, note=form.note.data or "Closed manually", user_id=current_user.user_id)
    audit.record("alert_closed", "alert", a.alert_id, f"{a.device.device_name}: {a.message[:120]}")
    db.session.commit()
    flash(f"Alert #{a.alert_id} closed. If the condition is still present, a new alert will be raised "
          "on the next check.", "success")
    return _back(alert_id)
