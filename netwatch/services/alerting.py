"""Alerting Layer — threshold evaluation and alert lifecycle (§2.2.7, §3.8.1, Fig 3.6).

Rules implemented:
* A device is marked DOWN only after N consecutive failed checks (configurable).
* A new alert is raised when status changes to down, or when a metric FIRST crosses a threshold.
* While the condition persists no new alert is created; a reminder email is sent at most
  once per reminder interval (suppression of repeated notifications).
* When the condition clears, the alert is auto-resolved and (optionally) a recovery email is sent.
* Threshold rules are not evaluated while a device is unreachable — the device-down alert
  already covers that condition, avoiding duplicate alerts.
"""
from datetime import timedelta

from ..extensions import db
from ..models import Alert, utcnow
from . import settings as app_settings

ACTIVE = ("open", "acknowledged")


def _active_alert(device_id, **filters):
    return (Alert.query.filter_by(device_id=device_id, **filters)
            .filter(Alert.status.in_(ACTIVE)).order_by(Alert.opened_at.desc()).first())


def _reminder_due(alert, now):
    minutes = app_settings.get("reminder_interval_minutes")
    if minutes <= 0 or alert.status != "open":
        return False  # acknowledged alerts are not nagged
    last = alert.last_notified_at or alert.opened_at
    return now - last >= timedelta(minutes=minutes)


def resolve(alert, now=None, note=None, user_id=None):
    alert.status = "resolved"
    alert.resolved_at = now or utcnow()
    alert.resolved_by = user_id
    if note:
        alert.resolution_note = note[:255]


def evaluate(device, result, now=None):
    """Update device state + alerts from a freshly stored result.

    Returns a list of (alert, kind) notifications to send after commit,
    where kind is 'new', 'reminder' or 'resolved'."""
    now = now or utcnow()
    out = []

    if result.reachable:
        device.consecutive_failures = 0
        if device.status != "up":
            device.status = "up"
            device.last_status_change_at = now
        down = _active_alert(device.device_id, alert_type="device_down")
        if down:
            resolve(down, now, "Device responded again")
            out.append((down, "resolved"))

        for th in device.thresholds:
            if not th.enabled:
                continue
            value = getattr(result, th.metric_name, None)
            active = _active_alert(device.device_id, alert_type="threshold", threshold_id=th.threshold_id)
            if th.is_breached(value):
                if active is None:
                    alert = Alert(device_id=device.device_id, result_id=result.result_id,
                                  threshold_id=th.threshold_id, alert_type="threshold",
                                  metric_name=th.metric_name, severity=th.severity, opened_at=now,
                                  message=f"{th.metric_label} is {value:g}, which breaches the rule "
                                          f"{th.comparison_operator} {th.threshold_value:g}")
                    db.session.add(alert)
                    out.append((alert, "new"))
                elif _reminder_due(active, now):
                    out.append((active, "reminder"))
            elif active is not None and value is not None:
                resolve(active, now, f"{th.metric_label} returned to {value:g}")
                out.append((active, "resolved"))
    else:
        device.consecutive_failures = (device.consecutive_failures or 0) + 1
        needed = app_settings.get("failure_threshold")
        if device.consecutive_failures >= needed:
            if device.status != "down":
                device.status = "down"
                device.last_status_change_at = now
            active = _active_alert(device.device_id, alert_type="device_down")
            if active is None:
                why = result.error_message or "no response"
                alert = Alert(device_id=device.device_id, result_id=result.result_id, alert_type="device_down",
                              severity="critical", opened_at=now,
                              message=f"Device unreachable for {device.consecutive_failures} consecutive "
                                      f"checks ({why})")
                db.session.add(alert)
                out.append((alert, "new"))
            elif _reminder_due(active, now):
                out.append((active, "reminder"))
    return out
