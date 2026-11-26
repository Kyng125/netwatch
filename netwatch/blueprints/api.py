"""JSON endpoints used by the dashboard and charts. All require login except /healthz."""
from datetime import timedelta

from flask import Blueprint, abort, jsonify, request
from flask_login import login_required
from sqlalchemy import text

from ..extensions import db
from ..models import Alert, Device, MonitoringResult, utcnow
from ..services import scheduler, series, stats
from ..utils import fmt_dt, iso_utc, time_ago

bp = Blueprint("api", __name__)


def _device_json(d, r):
    return {
        "id": d.device_id, "name": d.device_name, "ip": d.ip_address, "type": d.type_label,
        "status": d.display_status, "simulated": d.is_simulated,
        "site": d.site.name if d.checked_by_agent else None,
        "latency": r.latency_ms if r else None, "loss": r.packet_loss_percent if r else None,
        "uptime": r.uptime_percent if r else None, "method": r.method if r else None,
        "checked": iso_utc(d.last_checked_at), "checked_ago": time_ago(d.last_checked_at),
        "error": r.error_message if r and not r.reachable else None,
    }


@bp.route("/api/dashboard")
@login_required
def dashboard():
    devices = Device.query.order_by(Device.enabled.desc(), Device.device_name).all()
    alerts = (Alert.query.filter(Alert.status.in_(("open", "acknowledged")))
              .order_by(Alert.severity.asc(), Alert.opened_at.desc()).limit(6).all())
    # fleet latency chart: up to 8 enabled devices, last 6h, 5-minute buckets
    since = utcnow() - timedelta(hours=6)
    chart = []
    for d in [d for d in devices if d.enabled][:8]:
        rows = (MonitoringResult.query.with_entities(MonitoringResult.checked_at, MonitoringResult.reachable,
                                                     MonitoringResult.latency_ms,
                                                     MonitoringResult.packet_loss_percent)
                .filter(MonitoringResult.device_id == d.device_id, MonitoringResult.checked_at >= since)
                .order_by(MonitoringResult.checked_at).all())
        chart.append({"id": d.device_id, "name": d.device_name, "simulated": d.is_simulated,
                      "points": series.bucket_rows(rows, 300)})
    return jsonify({
        "overview": stats.fleet_overview(),
        "devices": [_device_json(d, d.latest_result()) for d in devices],
        "alerts": [{"id": a.alert_id, "device": a.device.device_name, "severity": a.severity, "status": a.status,
                    "message": a.message, "opened": fmt_dt(a.opened_at), "opened_ago": time_ago(a.opened_at),
                    "simulated": a.device.is_simulated} for a in alerts],
        "chart": chart,
        "generated_at": iso_utc(utcnow()),
        "scheduler": {"running": scheduler.status()["running"]},
    })


@bp.route("/api/devices/<int:device_id>/series")
@login_required
def device_series(device_id):
    if db.session.get(Device, device_id) is None:
        abort(404)
    return jsonify(series.device_series(device_id, request.args.get("range", "24h")))


@bp.route("/healthz")
def healthz():
    """Liveness/readiness probe for the cloud host (NFR7). Reveals no sensitive data."""
    ok = True
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        db.session.rollback()
        ok = False
    body = {"status": "ok" if ok else "degraded", "database": "ok" if ok else "unavailable",
            "scheduler": "running" if scheduler.status()["running"] else "stopped"}
    return jsonify(body), (200 if ok else 503)
