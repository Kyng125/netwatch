"""Email notification via SMTP (Alerting Layer, Fig 3.1; context diagram 'Alert Recipient')."""
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from flask import current_app

from ..models import User
from . import settings as app_settings

log = logging.getLogger(__name__)


def smtp_configured():
    cfg = current_app.config
    return bool(cfg.get("MAIL_SERVER") and cfg.get("MAIL_FROM"))


def recipients():
    emails = {u.email.lower() for u in User.query.filter_by(is_active_account=True, receive_alert_emails=True)}
    extra = app_settings.get("extra_alert_recipients") or ""
    emails |= {e.strip().lower() for e in extra.split(",") if e.strip()}
    return sorted(emails)


def send_email(subject, body, to=None):
    """Send a plain-text email. Returns 'sent', 'failed', 'disabled', 'not_configured' or 'no_recipients'.

    Never raises: email failure must not stop monitoring (§3.11 reliability testing)."""
    if not app_settings.get("email_alerts_enabled"):
        return "disabled"
    if not smtp_configured():
        return "not_configured"
    to = to if to is not None else recipients()
    if not to:
        return "no_recipients"
    cfg = current_app.config
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="netwatch.local")
    msg.set_content(body)
    try:
        timeout = cfg.get("MAIL_TIMEOUT_SECONDS", 10)
        if cfg.get("MAIL_USE_SSL"):
            server = smtplib.SMTP_SSL(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=timeout,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=timeout)
        with server:
            if cfg.get("MAIL_USE_TLS") and not cfg.get("MAIL_USE_SSL"):
                server.starttls(context=ssl.create_default_context())
            if cfg.get("MAIL_USERNAME"):
                server.login(cfg["MAIL_USERNAME"], cfg.get("MAIL_PASSWORD", ""))
            server.send_message(msg)
        log.info("Email sent: %s -> %d recipient(s)", subject, len(to))
        return "sent"
    except Exception as exc:  # network, auth, TLS ... log without secrets
        log.error("Email delivery failed (%s): %s", type(exc).__name__, str(exc)[:200])
        return "failed"


def alert_email(alert, kind, display_time):
    """Compose subject/body for an alert notification. kind: new | reminder | resolved"""
    d = alert.device
    prefix = {"new": "ALERT", "reminder": "REMINDER", "resolved": "RESOLVED"}[kind]
    sev = alert.severity.upper()
    subject = f"[Netwatch] {prefix}: {d.device_name} — " + (
        "device down" if alert.alert_type == "device_down" else alert.message.split(":")[0])
    if kind == "resolved":
        subject = f"[Netwatch] RESOLVED: {d.device_name} — condition cleared"
    sim = "\nNOTE: this is a SIMULATED demonstration device, not a real network observation.\n" if d.is_simulated else ""
    body = (
        f"{prefix} ({sev})\n\n"
        f"Device:   {d.device_name} ({d.ip_address})\n"
        f"Type:     {d.type_label}\n"
        f"Detail:   {alert.message}\n"
        f"Opened:   {display_time(alert.opened_at)}\n"
        + (f"Resolved: {display_time(alert.resolved_at)}\n" if alert.resolved_at else "")
        + f"Alert ID: #{alert.alert_id}\n{sim}\n"
        "Sign in to the Netwatch dashboard to acknowledge or review this alert.\n"
    )
    return subject, body
