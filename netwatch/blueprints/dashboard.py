"""Central dashboard (FR10, Presentation Layer)."""
from flask import Blueprint, render_template
from flask_login import login_required

from ..models import Alert, AuditLog, Device
from ..services import stats

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    overview = stats.fleet_overview()
    devices = Device.query.order_by(Device.enabled.desc(), Device.device_name).all()
    latest = {d.device_id: d.latest_result() for d in devices}
    alerts = (Alert.query.filter(Alert.status.in_(("open", "acknowledged")))
              .order_by(Alert.severity.asc(), Alert.opened_at.desc()).limit(6).all())
    events = AuditLog.query.order_by(AuditLog.log_time.desc()).limit(6).all()
    return render_template("dashboard.html", o=overview, devices=devices, latest=latest, alerts=alerts,
                           events=events)
