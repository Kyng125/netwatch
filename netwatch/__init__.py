"""Netwatch — Cloud-Based Network Monitoring System for a Small Organisation.

Application factory.
"""
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from .config import INSTANCE_DIR, Config
from .extensions import csrf, db, login_manager

__version__ = "2.1.0"


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """Enforce FK constraints and allow concurrent readers on SQLite (NFR8)."""
    if dbapi_conn.__class__.__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=15000")
        try:
            cur.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        cur.close()


def _configure_logging(app):
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    root = logging.getLogger()
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    root.setLevel(logging.INFO)
    log_file = app.config.get("LOG_FILE")
    if log_file and not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.INFO)


def create_app(config_object=Config, start_scheduler=None):
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config.from_object(config_object)
    os.makedirs(app.instance_path, exist_ok=True)
    _configure_logging(app)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from . import models  # noqa: F401  (register tables)
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    from .blueprints import register_blueprints
    register_blueprints(app)
    _register_template_helpers(app)
    _register_error_handlers(app)
    _register_security_headers(app)

    with app.app_context():
        try:
            db.create_all()
            from . import migrations
            migrations.upgrade()
        except SQLAlchemyError:
            app.logger.exception("Database initialisation failed — check DATABASE_URL")

    if start_scheduler is None:
        start_scheduler = app.config.get("SCHEDULER_ENABLED", True)
    if start_scheduler:
        from .services import scheduler
        scheduler.start(app)
    return app


def _register_template_helpers(app):
    from .models import Device, Threshold
    from .utils import fmt_dt, iso_utc, time_ago, to_local

    app.jinja_env.filters["dt"] = fmt_dt
    app.jinja_env.filters["iso"] = iso_utc
    app.jinja_env.filters["ago"] = time_ago
    app.jinja_env.filters["local"] = to_local

    @app.template_filter("num")
    def num(v, digits=2, suffix=""):
        if v is None:
            return "—"
        return f"{v:,.{digits}f}{suffix}"

    @app.context_processor
    def inject_globals():
        from flask_login import current_user
        from .models import Alert
        open_alerts = 0
        if current_user.is_authenticated:
            try:
                open_alerts = Alert.query.filter_by(status="open").count()
            except SQLAlchemyError:
                db.session.rollback()
        return {"APP_NAME": app.config["APP_NAME"], "APP_VERSION": __version__, "nav_open_alerts": open_alerts,
                "DEVICE_TYPES": Device.TYPE_LABELS, "METRIC_LABELS": Threshold.METRICS,
                "DISPLAY_TZ": app.config["DISPLAY_TIMEZONE"]}


def _register_error_handlers(app):
    def wants_json():
        return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"

    def render_error(code, title, message):
        if wants_json():
            return {"error": title, "message": message}, code
        return render_template("errors/error.html", code=code, title=title, message=message), code

    @app.errorhandler(403)
    def forbidden(_e):
        return render_error(403, "Access denied", "Your account does not have permission to do that. "
                                                  "Ask an administrator if you need access.")

    @app.errorhandler(404)
    def not_found(_e):
        return render_error(404, "Page not found", "The page or record you requested does not exist. "
                                                   "It may have been deleted.")

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return render_error(405, "Action not allowed", "That action cannot be performed this way.")

    @app.errorhandler(CSRFError)
    def csrf_error(_e):
        if wants_json():
            return {"error": "csrf", "message": "Session expired — reload the page."}, 400
        flash("Your form session expired or was invalid. Please try again.", "danger")
        return redirect(request.referrer or url_for("dashboard.index"))

    @app.errorhandler(SQLAlchemyError)
    def db_error(e):
        db.session.rollback()
        app.logger.error("Database error on %s: %s", request.path, type(e).__name__)
        return render_error(503, "Database unavailable",
                            "The application could not reach its database. The problem has been logged; "
                            "please try again shortly.")

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_error(500, "Something went wrong", "An unexpected error occurred and has been logged.")


def _register_security_headers(app):
    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'self'")
        if request.endpoint and request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp
