"""Audit_Log helper — records significant actions for accountability."""
import logging

from flask import has_request_context, request
from flask_login import current_user

from ..extensions import db
from ..models import AuditLog

log = logging.getLogger(__name__)


def record(action, entity_type=None, entity_id=None, details=None, user_id=None, commit=False):
    """Add an audit entry to the current session. Never raises."""
    try:
        if user_id is None and has_request_context() and current_user and current_user.is_authenticated:
            user_id = current_user.user_id
        ip = None
        if has_request_context():
            ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()[:45]
        db.session.add(AuditLog(user_id=user_id, action=action, entity_type=entity_type,
                                entity_id=entity_id, details=(details or "")[:500] or None, ip_address=ip))
        if commit:
            db.session.commit()
    except Exception:  # pragma: no cover - audit must never break the request
        log.exception("Could not write audit log entry %s", action)
