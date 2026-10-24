"""Processing helpers: uptime and descriptive statistics computed from stored results (§1.9, §3.10)."""
from datetime import timedelta

from sqlalchemy import case, func

from ..extensions import db
from ..models import Alert, Device, MonitoringResult, utcnow


def uptime_percent(device_id, start, end=None):
    """Uptime = successful checks / total checks in [start, end]. None if no checks."""
    q = db.session.query(func.count(MonitoringResult.result_id),
                         func.sum(case((MonitoringResult.reachable.is_(True), 1), else_=0))
                         ).filter(MonitoringResult.device_id == device_id, MonitoringResult.checked_at >= start)
    if end is not None:
        q = q.filter(MonitoringResult.checked_at <= end)
    total, ok = q.one()
    if not total:
        return None
    return round((ok or 0) / total * 100, 2)


def device_summary(device_id, start, end):
    """Descriptive statistics for one device over a period (min/avg/max, §3.10)."""
    r = MonitoringResult
    row = db.session.query(
        func.count(r.result_id),
        func.sum(case((r.reachable.is_(True), 1), else_=0)),
        func.min(r.latency_ms), func.avg(r.latency_ms), func.max(r.latency_ms),
        func.min(r.packet_loss_percent), func.avg(r.packet_loss_percent), func.max(r.packet_loss_percent),
        func.min(r.checked_at), func.max(r.checked_at),
    ).filter(r.device_id == device_id, r.checked_at >= start, r.checked_at <= end).one()
    total, ok = row[0] or 0, row[1] or 0
    alerts = Alert.query.filter(Alert.device_id == device_id, Alert.opened_at >= start,
                                Alert.opened_at <= end).count()
    methods = [m for (m,) in db.session.query(r.method).filter(
        r.device_id == device_id, r.checked_at >= start, r.checked_at <= end).distinct()]

    def rnd(v, n=2):
        return round(float(v), n) if v is not None else None

    return {
        "checks": total, "successful": ok, "failed": total - ok,
        "uptime": round(ok / total * 100, 2) if total else None,
        "latency_min": rnd(row[2]), "latency_avg": rnd(row[3]), "latency_max": rnd(row[4]),
        "loss_min": rnd(row[5]), "loss_avg": rnd(row[6]), "loss_max": rnd(row[7]),
        "first_check": row[8], "last_check": row[9], "alerts": alerts,
        "methods": sorted(methods),
    }


def fleet_overview():
    """Numbers for the dashboard stat cards."""
    now = utcnow()
    devices = Device.query.all()
    enabled = [d for d in devices if d.enabled]
    counts = {"total": len(devices), "up": 0, "down": 0, "unknown": 0, "disabled": len(devices) - len(enabled),
              "simulated": sum(1 for d in devices if d.is_simulated)}
    for d in enabled:
        counts[d.status] = counts.get(d.status, 0) + 1
    since = now - timedelta(hours=24)
    r = MonitoringResult
    total, ok = db.session.query(func.count(r.result_id),
                                 func.sum(case((r.reachable.is_(True), 1), else_=0))
                                 ).filter(r.checked_at >= since).one()
    avg_lat = db.session.query(func.avg(r.latency_ms)).filter(
        r.checked_at >= now - timedelta(hours=1), r.latency_ms.isnot(None)).scalar()
    active = Alert.query.filter(Alert.status.in_(("open", "acknowledged")))
    return {
        **counts,
        "uptime_24h": round((ok or 0) / total * 100, 2) if total else None,
        "checks_24h": total or 0,
        "avg_latency_1h": round(float(avg_lat), 2) if avg_lat is not None else None,
        "alerts_open": active.filter(Alert.status == "open").count(),
        "alerts_ack": active.filter(Alert.status == "acknowledged").count(),
        "alerts_critical": active.filter(Alert.severity == "critical").count(),
        "alerts_warning": active.filter(Alert.severity == "warning").count(),
    }
