"""Sites — private networks monitored through an on-site agent (see services/agents.py)."""
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request, send_file,
                   session, url_for)
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from . import admin_required
from ..extensions import db
from ..forms import ConfirmForm, SiteForm
from ..models import Alert, Device, Site
from ..services import agents, alerting, audit

bp = Blueprint("sites", __name__, url_prefix="/sites")

AGENT_FILE = Path(__file__).resolve().parent.parent.parent / "agent" / "netwatch_agent.py"


def _get(site_id):
    s = db.session.get(Site, site_id)
    if s is None:
        abort(404)
    return s


def _server_url():
    return request.host_url.rstrip("/")


@bp.route("/")
@login_required
def index():
    sites = Site.query.order_by(Site.name).all()
    unassigned_private = [d for d in Device.query.filter(Device.site_id.is_(None), Device.is_simulated.is_(False)).all()
                          if _is_private(d.ip_address)]
    return render_template("sites/index.html", sites=sites, form=ConfirmForm(),
                           offline_after=int(agents.offline_after().total_seconds() // 60),
                           unassigned_private=unassigned_private)


def _is_private(host):
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith(".local") or "." not in host
    return ip.is_private and not ip.is_loopback


@bp.route("/new", methods=["GET", "POST"])
@admin_required
def create():
    form = SiteForm()
    if form.validate_on_submit():
        key = Site.new_key()
        s = Site(name=form.name.data, description=form.description.data or None, enabled=form.enabled.data,
                 created_by=current_user.user_id)
        s.set_key(key)
        db.session.add(s)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            form.name.errors.append("A site with this name already exists.")
            return render_template("sites/form.html", form=form, site=None), 400
        audit.record("site_created", "site", s.site_id, f"Created site {s.name}")
        db.session.commit()
        session[f"new_agent_key_{s.site_id}"] = key  # shown once on the next page, then forgotten
        return redirect(url_for("sites.detail", site_id=s.site_id, new=1))
    return render_template("sites/form.html", form=form, site=None), (400 if form.errors else 200)


@bp.route("/<int:site_id>")
@login_required
def detail(site_id):
    s = _get(site_id)
    new_key = None
    if current_user.is_admin:
        new_key = session.pop(f"new_agent_key_{s.site_id}", None)
    active_offline = Alert.query.join(Device).filter(Device.site_id == s.site_id,
                                                     Alert.alert_type == "agent_offline",
                                                     Alert.status.in_(("open", "acknowledged"))).count()
    return render_template("sites/detail.html", s=s, new_key=new_key, server_url=_server_url(), form=ConfirmForm(),
                           active_offline=active_offline,
                           offline_after=int(agents.offline_after().total_seconds() // 60),
                           poll_seconds=current_app.config["AGENT_POLL_SECONDS"])


@bp.route("/<int:site_id>/edit", methods=["GET", "POST"])
@admin_required
def edit(site_id):
    s = _get(site_id)
    form = SiteForm(obj=s, site_id=s.site_id)
    if form.validate_on_submit():
        was_enabled = s.enabled
        s.name, s.description, s.enabled = form.name.data, form.description.data or None, form.enabled.data
        if was_enabled and not s.enabled:
            _close_offline_alerts(s, "Site disabled by administrator")
            agents.site_devices_unknown(s)
            s.agent_offline = False
        audit.record("site_updated", "site", s.site_id, f"Edited site {s.name}"
                     + ("" if s.enabled == was_enabled else f" ({'enabled' if s.enabled else 'disabled'})"))
        db.session.commit()
        flash("Site updated.", "success")
        return redirect(url_for("sites.detail", site_id=s.site_id))
    return render_template("sites/form.html", form=form, site=s), (400 if form.errors else 200)


def _close_offline_alerts(s, note):
    for a in Alert.query.join(Device).filter(Device.site_id == s.site_id, Alert.alert_type == "agent_offline",
                                             Alert.status.in_(("open", "acknowledged"))):
        alerting.resolve(a, note=note, user_id=current_user.user_id)


@bp.route("/<int:site_id>/rotate-key", methods=["POST"])
@admin_required
def rotate_key(site_id):
    s = _get(site_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    key = Site.new_key()
    s.set_key(key)
    audit.record("site_key_rotated", "site", s.site_id, f"New agent key for {s.name}; the old key stopped working")
    db.session.commit()
    session[f"new_agent_key_{s.site_id}"] = key
    flash("A new agent key was created. The old key no longer works — update the agent with the new one.",
          "warning")
    return redirect(url_for("sites.detail", site_id=s.site_id, new=1))


@bp.route("/<int:site_id>/delete", methods=["POST"])
@admin_required
def delete(site_id):
    s = _get(site_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    name, n = s.name, len(s.devices)
    _close_offline_alerts(s, "Site deleted")
    for d in list(s.devices):
        # Without an agent the server cannot reach a private address, so pause the device
        # rather than letting it fail from the cloud. Its history is kept.
        d.site_id, d.enabled, d.status, d.consecutive_failures = None, False, "unknown", 0
    audit.record("site_deleted", "site", s.site_id, f"Deleted site {name}; {n} device(s) disabled")
    db.session.delete(s)
    db.session.commit()
    flash(f"Site “{name}” deleted. Its {n} device(s) were kept but disabled — assign them to another site "
          "or edit them to re-enable.", "success")
    return redirect(url_for("sites.index"))


@bp.route("/agent/netwatch_agent.py")
@login_required
def download_agent():
    if not AGENT_FILE.is_file():
        abort(404)
    return send_file(AGENT_FILE, mimetype="text/x-python", as_attachment=True,
                     download_name="netwatch_agent.py", max_age=0)


@bp.app_context_processor
def inject_site_status():
    """Number of offline agents, for the sidebar badge."""
    if not current_user.is_authenticated:
        return {}
    try:
        n = Site.query.filter_by(enabled=True, agent_offline=True).count()
    except Exception:
        db.session.rollback()
        n = 0
    return {"nav_offline_agents": n}
