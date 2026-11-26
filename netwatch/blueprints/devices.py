"""Device management + per-device thresholds (FR3, FR7)."""
from datetime import timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from . import admin_required
from ..extensions import db
from ..forms import ConfirmForm, DeviceForm, ThresholdForm
from ..models import Alert, Device, MonitoringResult, Threshold, utcnow
from ..services import alerting, audit, monitor, secrets_box, stats
from ..services import settings as app_settings
from ..utils import int_arg, per_page_arg

bp = Blueprint("devices", __name__, url_prefix="/devices")

SORTS = {
    "name": Device.device_name, "ip": Device.ip_address, "type": Device.device_type,
    "status": Device.status, "checked": Device.last_checked_at, "created": Device.created_at,
}

RECOMMENDED = [("latency_ms", ">", 150, "warning"), ("latency_ms", ">", 500, "critical"),
               ("packet_loss_percent", ">", 25, "warning"), ("packet_loss_percent", ">=", 75, "critical")]


def _get(device_id):
    d = db.session.get(Device, device_id)
    if d is None:
        abort(404)
    return d


@bp.route("/")
@login_required
def index():
    q = (request.args.get("q") or "").strip()[:100]
    dtype = request.args.get("type", "")
    status = request.args.get("status", "")
    source = request.args.get("source", "")
    sort = request.args.get("sort", "name")
    order = request.args.get("order", "asc")
    query = Device.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Device.device_name.ilike(like), Device.ip_address.ilike(like),
                                 Device.location.ilike(like)))
    if dtype in Device.TYPES:
        query = query.filter(Device.device_type == dtype)
    if status == "disabled":
        query = query.filter(Device.enabled.is_(False))
    elif status in ("up", "down", "unknown"):
        query = query.filter(Device.enabled.is_(True), Device.status == status)
    if source == "real":
        query = query.filter(Device.is_simulated.is_(False))
    elif source == "simulated":
        query = query.filter(Device.is_simulated.is_(True))
    col = SORTS.get(sort, Device.device_name)
    query = query.order_by(col.desc() if order == "desc" else col.asc(), Device.device_id)
    page = query.paginate(page=int_arg("page", 1, 1), per_page=per_page_arg(), error_out=False)
    latest = {d.device_id: d.latest_result() for d in page.items}
    return render_template("devices/index.html", page=page, latest=latest, q=q, dtype=dtype, status=status,
                           source=source, sort=sort, order=order, form=ConfirmForm(), total=Device.query.count())


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def create():
    form = DeviceForm()
    if request.method == "GET":
        form.polling_interval.data = app_settings.get("default_polling_interval")
        site_arg = request.args.get("site", type=int)
        if site_arg and site_arg in {v for v, _l in form.site_id.choices}:
            form.site_id.data = site_arg
    if form.validate_on_submit():
        d = Device(user_id=current_user.user_id)
        _apply(form, d)
        db.session.add(d)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            form.device_name.errors.append("A device with this name already exists.")
            return render_template("devices/form.html", form=form, device=None), 400
        if form.add_default_thresholds.data:
            for metric, op, val, sev in RECOMMENDED:
                db.session.add(Threshold(device_id=d.device_id, metric_name=metric, comparison_operator=op,
                                         threshold_value=val, severity=sev))
        audit.record("device_created", "device", d.device_id, f"Registered {d.device_name} ({d.ip_address})")
        db.session.commit()
        flash(f"Device “{d.device_name}” registered. Its first check will run within a few seconds — "
              "or use “Check now”.", "success")
        return redirect(url_for("devices.detail", device_id=d.device_id))
    return render_template("devices/form.html", form=form, device=None), (400 if form.errors else 200)


def _apply(form, d):
    d.device_name = form.device_name.data
    new_site = form.site_id.data or None
    if d.ip_address != form.ip_address.data or d.site_id != new_site:
        d.status, d.consecutive_failures = "unknown", 0
        if d.device_id and d.site_id != new_site:
            # measured from a different place now: any 'agent offline' alert no longer applies
            for a in d.alerts.filter(Alert.alert_type == "agent_offline", Alert.status.in_(("open", "acknowledged"))):
                alerting.resolve(a, note="Device moved to another collector", user_id=current_user.user_id)
    d.site_id = new_site
    d.ip_address = form.ip_address.data
    d.device_type = form.device_type.data
    d.location = form.location.data or None
    d.description = form.description.data or None
    d.polling_interval = form.polling_interval.data
    d.enabled = form.enabled.data
    d.snmp_enabled = form.snmp_enabled.data
    if form.snmp_community.data:
        d.snmp_community = secrets_box.encrypt(form.snmp_community.data)
    elif d.snmp_community and not secrets_box.is_encrypted(d.snmp_community):
        d.snmp_community = secrets_box.encrypt(d.snmp_community)  # upgrade a legacy plaintext value


@bp.route("/<int:device_id>")
@login_required
def detail(device_id):
    d = _get(device_id)
    now = utcnow()
    summary_24h = stats.device_summary(d.device_id, now - timedelta(hours=24), now)
    uptime_7d = stats.uptime_percent(d.device_id, now - timedelta(days=7), now)
    recent = d.results.order_by(MonitoringResult.checked_at.desc()).limit(10).all()
    alerts = d.alerts.order_by(Alert.opened_at.desc()).limit(8).all()
    return render_template("devices/detail.html", d=d, s=summary_24h, uptime_7d=uptime_7d, recent=recent,
                           alerts=alerts, latest=recent[0] if recent else None, form=ConfirmForm(),
                           tform=ThresholdForm(formdata=None))


@bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(device_id):
    d = _get(device_id)
    form = DeviceForm(obj=d, device_id=d.device_id)
    if request.method == "GET":
        form.snmp_community.data = ""  # never echo the stored secret back into the page
        form.site_id.data = d.site_id or 0
    if form.validate_on_submit():
        was_enabled = d.enabled
        _apply(form, d)
        if was_enabled and not d.enabled:
            _close_active_alerts(d, "Monitoring disabled by administrator")
            d.status = "unknown"
        audit.record("device_updated", "device", d.device_id, f"Edited {d.device_name}")
        db.session.commit()
        flash("Device updated.", "success")
        return redirect(url_for("devices.detail", device_id=d.device_id))
    return render_template("devices/form.html", form=form, device=d), (400 if form.errors else 200)


def _close_active_alerts(d, note):
    for a in d.alerts.filter(Alert.status.in_(("open", "acknowledged"))):
        alerting.resolve(a, note=note, user_id=current_user.user_id)


@bp.route("/<int:device_id>/toggle", methods=["POST"])
@admin_required
def toggle(device_id):
    d = _get(device_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    d.enabled = not d.enabled
    if not d.enabled:
        _close_active_alerts(d, "Monitoring disabled by administrator")
        d.status, d.consecutive_failures = "unknown", 0
    audit.record("device_enabled" if d.enabled else "device_disabled", "device", d.device_id, d.device_name)
    db.session.commit()
    flash(f"Monitoring {'enabled' if d.enabled else 'disabled'} for “{d.device_name}”.", "success")
    return redirect(request.form.get("next") if (request.form.get("next") or "").startswith("/") else
                    url_for("devices.detail", device_id=d.device_id))


@bp.route("/<int:device_id>/delete", methods=["POST"])
@admin_required
def delete(device_id):
    d = _get(device_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    name = d.device_name
    audit.record("device_deleted", "device", d.device_id, f"Removed {name} ({d.ip_address})")
    db.session.delete(d)
    db.session.commit()
    flash(f"Device “{name}” and its monitoring history were removed.", "success")
    return redirect(url_for("devices.index"))


@bp.route("/<int:device_id>/check", methods=["POST"])
@login_required
def check_now(device_id):
    d = _get(device_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    if not d.enabled:
        flash("Enable monitoring for this device before running a check.", "warning")
        return redirect(url_for("devices.detail", device_id=device_id))
    if d.checked_by_agent:
        site = d.site
        d.check_requested_at = utcnow()
        db.session.commit()
        if site.connection_state == "online":
            flash(f"Check requested. The agent at “{site.name}” will run it within about "
                  f"{current_app.config['AGENT_POLL_SECONDS']} seconds — refresh the page to see the result.", "info")
        else:
            flash(f"Check requested, but the agent for “{site.name}” is {site.connection_state.replace('never', 'not connected yet')}. "
                  "It will run when the agent reconnects.", "warning")
        return redirect(url_for("devices.detail", device_id=device_id))
    result = monitor.check_device(device_id)
    if result is None:
        flash("A check for this device is already running — refresh in a moment.", "warning")
    elif result.reachable:
        lat = f"{result.latency_ms:.2f} ms" if result.latency_ms is not None else "n/a"
        loss = f"{result.packet_loss_percent:g}%" if result.packet_loss_percent is not None else "n/a"
        sim = " (simulated)" if result.method == "simulated" else ""
        flash(f"Reachable via {result.method.upper()}{sim} — latency {lat}, packet loss {loss}.", "success")
    else:
        flash(f"No response: {result.error_message or 'device unreachable'}.", "danger")
    return redirect(url_for("devices.detail", device_id=device_id))


# ------------------------------------------------------------------ thresholds
@bp.route("/<int:device_id>/thresholds", methods=["POST"])
@admin_required
def threshold_create(device_id):
    d = _get(device_id)
    form = ThresholdForm()
    if form.validate_on_submit():
        exists = Threshold.query.filter_by(device_id=d.device_id, metric_name=form.metric_name.data,
                                           severity=form.severity.data).first()
        if exists:
            flash(f"A {form.severity.data} rule for {exists.metric_label} already exists — edit it instead.",
                  "warning")
        else:
            t = Threshold(device_id=d.device_id)
            form.populate_obj(t)
            db.session.add(t)
            db.session.flush()
            audit.record("threshold_created", "threshold", t.threshold_id, f"{d.device_name}: {t.describe()}")
            db.session.commit()
            flash("Threshold rule added. It applies from the next check.", "success")
    else:
        for field, errs in form.errors.items():
            flash(f"{getattr(form, field).label.text}: {errs[0]}", "danger")
    return redirect(url_for("devices.detail", device_id=d.device_id) + "#thresholds")


@bp.route("/thresholds/<int:threshold_id>/edit", methods=["GET", "POST"])
@admin_required
def threshold_edit(threshold_id):
    t = db.session.get(Threshold, threshold_id) or abort(404)
    form = ThresholdForm(obj=t)
    if form.validate_on_submit():
        clash = Threshold.query.filter(Threshold.device_id == t.device_id,
                                       Threshold.metric_name == form.metric_name.data,
                                       Threshold.severity == form.severity.data,
                                       Threshold.threshold_id != t.threshold_id).first()
        if clash:
            form.severity.errors.append("Another rule already uses this metric and severity.")
        else:
            form.populate_obj(t)
            if not t.enabled:
                for a in Alert.query.filter(Alert.threshold_id == t.threshold_id,
                                            Alert.status.in_(("open", "acknowledged"))):
                    alerting.resolve(a, note="Threshold rule disabled", user_id=current_user.user_id)
            audit.record("threshold_updated", "threshold", t.threshold_id, f"{t.device.device_name}: {t.describe()}")
            db.session.commit()
            flash("Threshold rule updated.", "success")
            return redirect(url_for("devices.detail", device_id=t.device_id) + "#thresholds")
    return render_template("devices/threshold_form.html", form=form, t=t), (400 if form.errors else 200)


@bp.route("/thresholds/<int:threshold_id>/delete", methods=["POST"])
@admin_required
def threshold_delete(threshold_id):
    t = db.session.get(Threshold, threshold_id) or abort(404)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    device_id = t.device_id
    for a in Alert.query.filter(Alert.threshold_id == t.threshold_id, Alert.status.in_(("open", "acknowledged"))):
        alerting.resolve(a, note="Threshold rule removed", user_id=current_user.user_id)
    audit.record("threshold_deleted", "threshold", t.threshold_id, f"{t.device.device_name}: {t.describe()}")
    db.session.delete(t)
    db.session.commit()
    flash("Threshold rule removed.", "success")
    return redirect(url_for("devices.detail", device_id=device_id) + "#thresholds")
