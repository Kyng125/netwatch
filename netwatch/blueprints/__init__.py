"""Blueprint registration + shared authorisation decorators."""
from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def admin_required(view):
    """Only administrators may change configuration, devices and accounts."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def register_blueprints(app):
    from . import alerts, api, auth, dashboard, devices, history, reports, settings, users
    for bp in (auth.bp, dashboard.bp, devices.bp, alerts.bp, history.bp, reports.bp, users.bp,
               settings.bp, api.bp):
        app.register_blueprint(bp)
