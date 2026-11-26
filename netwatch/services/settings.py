"""Typed access to the configurable system parameters (Settings page)."""
from ..extensions import db
from ..models import SystemSetting

# key: (type, default, label, help, min, max)
DEFAULTS = {
    "failure_threshold": (int, 2, "Consecutive failures before 'down'",
                          "Number of failed checks in a row before a device is marked down and a "
                          "device-down alert is raised (reduces false alarms, §3.8.1).", 1, 10),
    "reminder_interval_minutes": (int, 60, "Reminder interval (minutes)",
                                  "While a condition stays active, repeat the email notification at most "
                                  "this often. 0 disables reminders.", 0, 1440),
    "default_polling_interval": (int, 60, "Default polling interval (seconds)",
                                 "Pre-filled interval for newly registered devices.", 10, 86400),
    "retention_days": (int, 90, "Keep monitoring history (days)",
                       "Results older than this are purged once a day.", 1, 3650),
    "email_alerts_enabled": (bool, True, "Send email notifications",
                             "Requires SMTP settings in the environment (.env).", None, None),
    "send_recovery_emails": (bool, True, "Email when a condition clears",
                             "Send a 'resolved' email when a device recovers or a metric returns to normal.",
                             None, None),
    "agent_offline_minutes": (int, 3, "Agent offline after (minutes)",
                              "If an on-site agent sends nothing for this long, its devices are marked "
                              "unknown and an agent-offline alert is raised.", 1, 1440),
    "extra_alert_recipients": (str, "", "Additional alert recipients",
                               "Comma-separated email addresses that receive alerts in addition to users "
                               "who opted in.", None, None),
}


def _cast(kind, raw):
    if kind is bool:
        return str(raw).lower() in {"1", "true", "yes", "on"}
    if kind is int:
        return int(raw)
    return str(raw)


def get(key):
    kind, default = DEFAULTS[key][0], DEFAULTS[key][1]
    row = db.session.get(SystemSetting, key)
    if row is None:
        return default
    try:
        return _cast(kind, row.value)
    except (TypeError, ValueError):
        return default


def get_all():
    return {k: get(k) for k in DEFAULTS}


def set_value(key, value):
    if key not in DEFAULTS:
        raise KeyError(key)
    kind, _d, _l, _h, lo, hi = DEFAULTS[key]
    value = _cast(kind, value)
    if kind is int and ((lo is not None and value < lo) or (hi is not None and value > hi)):
        raise ValueError(f"{DEFAULTS[key][2]} must be between {lo} and {hi}.")
    row = db.session.get(SystemSetting, key)
    stored = ("true" if value else "false") if kind is bool else str(value)
    if row is None:
        db.session.add(SystemSetting(key=key, value=stored))
    else:
        row.value = stored
    return value
