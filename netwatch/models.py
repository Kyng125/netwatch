"""Database models — implements Table 3.4 of the seminar report.

Users, Devices, Monitoring_Results, Thresholds, Alerts, Audit_Log
(+ system_settings for the configurable values described in §3.8.1).
All timestamps are stored in UTC.
"""
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------- Users
class User(UserMixin, db.Model):
    __tablename__ = "users"
    ROLES = ("admin", "viewer")

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="admin")
    is_active_account = db.Column(db.Boolean, nullable=False, default=True)
    receive_alert_emails = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    devices = db.relationship("Device", back_populates="owner", lazy="dynamic")

    __table_args__ = (CheckConstraint("role in ('admin','viewer')", name="ck_user_role"),)

    def get_id(self):
        return str(self.user_id)

    @property
    def is_active(self):
        return self.is_active_account

    @property
    def is_admin(self):
        return self.role == "admin"

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


# ---------------------------------------------------------------- Devices
class Device(db.Model):
    __tablename__ = "devices"
    TYPES = ("router", "switch", "server", "access_point", "firewall", "printer", "workstation", "other")
    TYPE_LABELS = {
        "router": "Router", "switch": "Switch", "server": "Server", "access_point": "Access point",
        "firewall": "Firewall", "printer": "Printer", "workstation": "Workstation", "other": "Other",
    }

    device_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"), index=True)
    device_name = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(255), nullable=False, index=True)
    device_type = db.Column(db.String(30), nullable=False, default="other")
    location = db.Column(db.String(120))
    description = db.Column(db.String(255))
    snmp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    snmp_community = db.Column(db.String(400))  # stored encrypted ("enc:v1:...") — see services/secrets_box.py
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    # status: up | down | unknown  (disabled is shown from `enabled`)
    status = db.Column(db.String(20), nullable=False, default="unknown")
    polling_interval = db.Column(db.Integer, nullable=False, default=60)  # seconds
    is_simulated = db.Column(db.Boolean, nullable=False, default=False)
    # Behaviour of a simulated device: stable | degraded | flaky (ignored for real devices)
    sim_profile = db.Column(db.String(20))
    consecutive_failures = db.Column(db.Integer, nullable=False, default=0)
    last_checked_at = db.Column(db.DateTime)
    last_status_change_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    owner = db.relationship("User", back_populates="devices")
    results = db.relationship("MonitoringResult", back_populates="device", lazy="dynamic",
                              cascade="all, delete-orphan", passive_deletes=True)
    thresholds = db.relationship("Threshold", back_populates="device", lazy="select",
                                 cascade="all, delete-orphan", passive_deletes=True,
                                 order_by="Threshold.metric_name")
    alerts = db.relationship("Alert", back_populates="device", lazy="dynamic",
                             cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (
        CheckConstraint("polling_interval >= 10 AND polling_interval <= 86400", name="ck_poll_interval"),
        CheckConstraint("status in ('up','down','unknown')", name="ck_device_status"),
    )

    @property
    def type_label(self):
        return self.TYPE_LABELS.get(self.device_type, self.device_type.title())

    @property
    def display_status(self):
        return "disabled" if not self.enabled else self.status

    def latest_result(self):
        return self.results.order_by(MonitoringResult.checked_at.desc()).first()


# ---------------------------------------------------------------- Monitoring_Results
class MonitoringResult(db.Model):
    __tablename__ = "monitoring_results"
    METHODS = ("icmp", "tcp", "simulated")

    result_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    checked_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    reachable = db.Column(db.Boolean, nullable=False)
    latency_ms = db.Column(db.Float)
    packet_loss_percent = db.Column(db.Float)
    uptime_percent = db.Column(db.Float)  # 24h rolling uptime at the time of the check
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    method = db.Column(db.String(20), nullable=False, default="icmp")
    error_message = db.Column(db.String(255))

    device = db.relationship("Device", back_populates="results")

    __table_args__ = (
        Index("ix_results_device_time", "device_id", "checked_at"),
        Index("ix_results_time", "checked_at"),
        CheckConstraint("packet_loss_percent IS NULL OR (packet_loss_percent >= 0 AND packet_loss_percent <= 100)",
                        name="ck_loss_range"),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_latency_nonneg"),
    )


# ---------------------------------------------------------------- Thresholds
class Threshold(db.Model):
    __tablename__ = "thresholds"
    METRICS = {
        "latency_ms": "Latency (ms)",
        "packet_loss_percent": "Packet loss (%)",
        "uptime_percent": "24h uptime (%)",
        "cpu_percent": "CPU load (%) — SNMP",
        "memory_percent": "Memory use (%) — SNMP",
    }
    OPERATORS = (">", ">=", "<", "<=")
    SEVERITIES = ("warning", "critical")

    threshold_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False, index=True)
    metric_name = db.Column(db.String(40), nullable=False)
    comparison_operator = db.Column(db.String(2), nullable=False, default=">")
    threshold_value = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="warning")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    device = db.relationship("Device", back_populates="thresholds")

    __table_args__ = (
        UniqueConstraint("device_id", "metric_name", "severity", name="uq_threshold_metric_severity"),
        CheckConstraint("comparison_operator in ('>','>=','<','<=')", name="ck_threshold_op"),
        CheckConstraint("severity in ('warning','critical')", name="ck_threshold_sev"),
    )

    @property
    def metric_label(self):
        return self.METRICS.get(self.metric_name, self.metric_name)

    def is_breached(self, value):
        if value is None:
            return False
        op = self.comparison_operator
        v, t = float(value), float(self.threshold_value)
        return {">": v > t, ">=": v >= t, "<": v < t, "<=": v <= t}[op]

    def describe(self):
        return f"{self.metric_label} {self.comparison_operator} {self.threshold_value:g}"


# ---------------------------------------------------------------- Alerts
class Alert(db.Model):
    __tablename__ = "alerts"
    TYPES = ("device_down", "threshold")
    STATUSES = ("open", "acknowledged", "resolved")

    alert_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False, index=True)
    result_id = db.Column(db.Integer, db.ForeignKey("monitoring_results.result_id", ondelete="SET NULL"))
    threshold_id = db.Column(db.Integer, db.ForeignKey("thresholds.threshold_id", ondelete="SET NULL"))
    alert_type = db.Column(db.String(20), nullable=False)
    metric_name = db.Column(db.String(40))
    severity = db.Column(db.String(20), nullable=False, default="warning")
    message = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open", index=True)
    opened_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    resolution_note = db.Column(db.String(255))
    last_notified_at = db.Column(db.DateTime)
    notification_count = db.Column(db.Integer, nullable=False, default=0)
    email_status = db.Column(db.String(20), nullable=False, default="not_configured")  # sent|failed|not_configured|disabled

    device = db.relationship("Device", back_populates="alerts")
    result = db.relationship("MonitoringResult")
    threshold = db.relationship("Threshold")
    acknowledger = db.relationship("User", foreign_keys=[acknowledged_by])
    resolver = db.relationship("User", foreign_keys=[resolved_by])

    __table_args__ = (
        CheckConstraint("status in ('open','acknowledged','resolved')", name="ck_alert_status"),
        CheckConstraint("severity in ('warning','critical','info')", name="ck_alert_sev"),
    )

    @property
    def is_active(self):
        return self.status in ("open", "acknowledged")


# ---------------------------------------------------------------- Audit_Log
class AuditLog(db.Model):
    __tablename__ = "audit_log"

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"), index=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    entity_type = db.Column(db.String(30))
    entity_id = db.Column(db.Integer)
    details = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))
    log_time = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User")


# ---------------------------------------------------------------- System settings
class SystemSetting(db.Model):
    __tablename__ = "system_settings"

    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
