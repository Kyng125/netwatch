"""WTForms definitions — server-side validation for every input (NFR1, NFR8). CSRF via Flask-WTF."""
import re

from flask_wtf import FlaskForm
from wtforms import (BooleanField, FloatField, IntegerField, PasswordField, SelectField, StringField,
                     TextAreaField)
from wtforms.validators import (DataRequired, Email, EqualTo, InputRequired, Length, NumberRange, Optional,
                                ValidationError)

from .models import Device, Threshold, User
from .services.collector import validate_host

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def strip(v):
    return v.strip() if isinstance(v, str) else v


def strong_password(form, field):
    pw = field.data or ""
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise ValidationError("Use at least 8 characters, including letters and at least one number.")


def valid_username(form, field):
    if not USERNAME_RE.match(field.data or ""):
        raise ValidationError("3–50 characters: letters, numbers, dot, dash or underscore.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=50)], filters=[strip])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    remember = BooleanField("Keep me signed in on this computer")


class SetupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), valid_username], filters=[strip])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)], filters=[strip])
    password = PasswordField("Password", validators=[DataRequired(), strong_password, Length(max=128)])
    confirm = PasswordField("Confirm password",
                            validators=[DataRequired(), EqualTo("password", "Passwords do not match.")])


class DeviceForm(FlaskForm):
    device_name = StringField("Device name", validators=[DataRequired(), Length(min=2, max=100)], filters=[strip])
    ip_address = StringField("IP address or hostname", validators=[DataRequired(), Length(max=253)],
                             filters=[strip])
    device_type = SelectField("Device type", choices=[(t, Device.TYPE_LABELS[t]) for t in Device.TYPES])
    location = StringField("Location", validators=[Optional(), Length(max=120)], filters=[strip])
    description = TextAreaField("Notes", validators=[Optional(), Length(max=255)], filters=[strip])
    polling_interval = IntegerField("Polling interval (seconds)",
                                    validators=[InputRequired(message="Enter a polling interval."),
                                                NumberRange(10, 86400, "Must be between 10 and 86400 seconds.")])
    enabled = BooleanField("Monitoring enabled", default=True)
    snmp_enabled = BooleanField("Collect CPU / memory via SNMP (optional)")
    snmp_community = StringField("SNMP community string", validators=[Length(max=100)],
                                 filters=[strip])
    add_default_thresholds = BooleanField("Add recommended thresholds (latency, packet loss)", default=True)

    def __init__(self, *args, device_id=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._device_id = device_id

    def validate_ip_address(self, field):
        try:
            field.data = validate_host(field.data)
        except ValueError as exc:
            raise ValidationError(str(exc))

    def validate_device_name(self, field):
        q = Device.query.filter(Device.device_name.ilike(field.data))
        if self._device_id:
            q = q.filter(Device.device_id != self._device_id)
        if q.first():
            raise ValidationError("A device with this name already exists.")

    def validate_snmp_community(self, field):
        if self.snmp_enabled.data and not field.data and not (self._device_id and
                                                              _has_community(self._device_id)):
            raise ValidationError("Enter the SNMP community string configured on the device.")


def _has_community(device_id):
    from .extensions import db
    d = db.session.get(Device, device_id)
    return bool(d and d.snmp_community)


class ThresholdForm(FlaskForm):
    metric_name = SelectField("Metric", choices=list(Threshold.METRICS.items()))
    comparison_operator = SelectField("Condition", choices=[(">", "greater than (>)"),
                                                            (">=", "greater than or equal (≥)"),
                                                            ("<", "less than (<)"),
                                                            ("<=", "less than or equal (≤)")])
    threshold_value = FloatField("Value", validators=[InputRequired(message="Enter a number.")])
    severity = SelectField("Severity", choices=[("warning", "Warning"), ("critical", "Critical")])
    enabled = BooleanField("Rule enabled", default=True)

    def validate_threshold_value(self, field):
        v = field.data
        if v is None:
            return
        if v < 0:
            raise ValidationError("Value cannot be negative.")
        if self.metric_name.data != "latency_ms" and v > 100:
            raise ValidationError("Percentages must be between 0 and 100.")
        if self.metric_name.data == "latency_ms" and v > 60000:
            raise ValidationError("Latency thresholds must be at most 60000 ms.")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), valid_username], filters=[strip])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)], filters=[strip])
    role = SelectField("Role", choices=[("admin", "Administrator — full control"),
                                        ("viewer", "Viewer — read-only, can acknowledge alerts")])
    password = PasswordField("Password", validators=[Optional(), strong_password, Length(max=128)])
    is_active_account = BooleanField("Account active", default=True)
    receive_alert_emails = BooleanField("Receive alert emails", default=True)

    def __init__(self, *args, user_id=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_id = user_id

    def validate_username(self, field):
        q = User.query.filter(User.username.ilike(field.data))
        if self._user_id:
            q = q.filter(User.user_id != self._user_id)
        if q.first():
            raise ValidationError("That username is taken.")

    def validate_email(self, field):
        q = User.query.filter(User.email.ilike(field.data))
        if self._user_id:
            q = q.filter(User.user_id != self._user_id)
        if q.first():
            raise ValidationError("That email address is already registered.")

    def validate_password(self, field):
        if not self._user_id and not field.data:
            raise ValidationError("A password is required for a new account.")


class ProfileForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)], filters=[strip])
    receive_alert_emails = BooleanField("Receive alert emails")
    current_password = PasswordField("Current password", validators=[Optional()])
    new_password = PasswordField("New password", validators=[Optional(), strong_password, Length(max=128)])
    confirm = PasswordField("Confirm new password",
                            validators=[EqualTo("new_password", "Passwords do not match.")])


class ConfirmForm(FlaskForm):
    """Empty form used for CSRF-protected POST buttons (delete, acknowledge, check now...)."""
    note = StringField("Note", validators=[Optional(), Length(max=255)], filters=[strip])
