"""Processing Layer — runs one device check end to end (Fig 3.4 processes 1.0 → 4.0).

collect → validate → store result → compute uptime → evaluate thresholds → alert → notify
"""
import logging
import threading
from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import Device, MonitoringResult, utcnow
from . import alerting, collector, notifier, secrets_box, stats
from ..utils import fmt_dt

log = logging.getLogger(__name__)

_device_locks = {}
_locks_guard = threading.Lock()


def _lock_for(device_id):
    with _locks_guard:
        return _device_locks.setdefault(device_id, threading.Lock())


def run_probe(device):
    """Perform the measurement for one device (no DB writes)."""
    cfg = current_app.config
    if device.is_simulated:
        return collector.simulated_probe(device.device_id, device.sim_profile, device.device_type)
    try:
        host = collector.validate_host(device.ip_address)
    except ValueError as exc:
        return collector.ProbeResult(False, None, None, "icmp", f"Invalid address: {exc}")
    res = collector.probe(host, method=cfg["MONITOR_METHOD"], count=cfg["PING_COUNT"],
                          timeout_s=cfg["PING_TIMEOUT_SECONDS"], tcp_ports=cfg["TCP_PROBE_PORTS"])
    if device.snmp_enabled and res.reachable:
        community = secrets_box.decrypt(device.snmp_community) if device.snmp_community else "public"
        if community is None:
            res.error = res.error or "SNMP community string could not be read; re-enter it on the device"
        else:
            cpu, mem, err = collector.snmp_probe(host, community, timeout_s=cfg["PING_TIMEOUT_SECONDS"])
            res.cpu_percent, res.memory_percent = cpu, mem
            if err and not res.error:
                res.error = err
    return res


def check_device(device_id, now=None):
    """Check one device, store the result and process alerts.

    Returns the MonitoringResult, or None if the device no longer exists / is busy.
    Any exception is contained here so one bad device cannot stop the others (NFR2)."""
    lock = _lock_for(device_id)
    if not lock.acquire(blocking=False):
        log.info("Device %s is already being checked; skipping duplicate run", device_id)
        return None
    try:
        device = db.session.get(Device, device_id)
        if device is None:
            return None
        if device.checked_by_agent:
            # A private-LAN device: the cloud server cannot reach it, so never probe it from here.
            return None
        try:
            probe = run_probe(device)
        except Exception as exc:  # collector bug or OS error -> record failed check
            log.exception("Probe of device %s failed", device_id)
            probe = collector.ProbeResult(False, None, None, "icmp", f"Collector error: {type(exc).__name__}")
        return record_probe(device, probe, now)
    except Exception:
        db.session.rollback()
        log.exception("Monitoring check for device %s could not be stored", device_id)
        return None
    finally:
        lock.release()


def record_probe(device, probe, now=None):
    """Store one measurement for `device` and run the alert logic (Fig 3.4 processes 2.0 → 4.0).

    Shared by the cloud collector and by results reported from on-site agents, so both kinds of
    measurement are stored, evaluated and notified in exactly the same way."""
    now = now or utcnow()
    result = MonitoringResult(
        device_id=device.device_id, checked_at=now, reachable=probe.reachable,
        latency_ms=round(probe.latency_ms, 3) if probe.latency_ms is not None else None,
        packet_loss_percent=probe.packet_loss_percent, cpu_percent=probe.cpu_percent,
        memory_percent=probe.memory_percent, method=probe.method,
        error_message=(probe.error or None) and probe.error[:255])
    db.session.add(result)
    db.session.flush()
    result.uptime_percent = stats.uptime_percent(device.device_id, now - timedelta(hours=24), now)
    device.last_checked_at = now
    device.check_requested_at = None
    notifications = alerting.evaluate(device, result, now)
    db.session.commit()
    send_notifications(notifications, now)
    return result


def send_notifications(notifications, now):
    if not notifications:
        return
    send_recovery = alerting.app_settings.get("send_recovery_emails")
    for alert, kind in notifications:
        if kind == "resolved" and not send_recovery:
            continue
        subject, body = notifier.alert_email(alert, kind, fmt_dt)
        status = notifier.send_email(subject, body)
        if kind != "resolved":
            alert.email_status = status
            alert.last_notified_at = now
            alert.notification_count = (alert.notification_count or 0) + 1
    db.session.commit()


def is_due(device, now):
    return device.last_checked_at is None or (now - device.last_checked_at).total_seconds() >= device.polling_interval - 1


def due_device_ids(now=None):
    """Enabled devices whose polling interval has elapsed and that THIS server checks itself.

    Devices assigned to a site are checked by that site's on-site agent instead."""
    now = now or utcnow()
    return [d.device_id for d in Device.query.filter_by(enabled=True).all()
            if not d.checked_by_agent and is_due(d, now)]


def purge_old_results(days):
    cutoff = utcnow() - timedelta(days=days)
    n = MonitoringResult.query.filter(MonitoringResult.checked_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return n
