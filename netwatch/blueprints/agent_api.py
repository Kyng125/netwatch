"""Machine-to-machine API used by on-site agents (see services/agents.py).

Authenticated by the site's agent key in an ``Authorization: Bearer nwa_...`` header — not by a
login session — so these routes are exempt from CSRF protection (which only applies to browser
forms). They return JSON only.
"""
from flask import Blueprint, current_app, jsonify, request

from ..extensions import csrf, db
from ..models import utcnow
from ..services import agents
from ..utils import iso_utc

bp = Blueprint("agent_api", __name__, url_prefix="/api/agent/v1")
csrf.exempt(bp)

MAX_BODY_BYTES = 512 * 1024


def _site_or_error():
    auth = request.headers.get("Authorization", "")
    key = auth[7:] if auth[:7].lower() == "bearer " else ""
    site = agents.authenticate(key)
    if site is None:
        return None, (jsonify(error="unauthorized",
                              message="Missing or wrong agent key. Copy the key from the site's page "
                                      "in Netwatch, or create a new one."), 401)
    if site == "disabled":
        return None, (jsonify(error="disabled",
                              message="This site is disabled in Netwatch. An administrator can enable it "
                                      "on the Sites page."), 403)
    return site, None


def _remote_addr():
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


@bp.route("/jobs", methods=["GET", "POST"])
def jobs():
    """Heartbeat + the list of devices this agent should check now."""
    site, err = _site_or_error()
    if err:
        return err
    info = request.get_json(silent=True) if request.method == "POST" else dict(request.args)
    agents.heartbeat(site, info or {}, _remote_addr())
    now = utcnow()
    body = {
        "site": {"id": site.site_id, "name": site.name},
        "server_time": iso_utc(now),
        "poll_seconds": current_app.config["AGENT_POLL_SECONDS"],
        "probe": agents.probe_settings(),
        "jobs": agents.jobs_for(site, now),
        "device_count": sum(1 for d in site.devices if d.enabled),
    }
    db.session.commit()
    return jsonify(body)


@bp.route("/results", methods=["POST"])
def results():
    site, err = _site_or_error()
    if err:
        return err
    if (request.content_length or 0) > MAX_BODY_BYTES:
        return jsonify(error="too_large", message="Request body is too large."), 413
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="bad_request", message="Send a JSON object with a 'results' list."), 400
    agents.heartbeat(site, payload.get("agent") or {}, _remote_addr())
    stored, rejected = agents.ingest(site, payload.get("results"))
    return jsonify(stored=stored, rejected=rejected), (200 if stored or not rejected else 422)
