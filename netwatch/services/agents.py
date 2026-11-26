"""On-site agents — monitoring private LAN devices from the cloud (extends the collection layer, Fig 3.1).

A cloud server cannot open connections to private addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x):
they are not routable on the internet. Instead, a small agent program runs on a computer inside the
LAN. It only makes OUTGOING HTTPS requests to this server, so no router changes, port forwarding or
public IP are needed:

    agent  --GET  /api/agent/v1/jobs     -->  server   "which of my devices are due?"
    agent  <--   [{device_id, host, ...}]       server
    agent  pings each device on the LAN (ICMP, TCP-connect fallback)
    agent  --POST /api/agent/v1/results  -->  server   stored + alerting exactly like cloud checks

Every request is authenticated with the site's secret agent key (only its SHA-256 hash is stored).
If a site's agent stops reporting, its devices are marked 'unknown' — not 'down', because the
devices themselves may be fine — and an agent-offline alert is raised.
"""
import logging
from datetime import timedelta

from flask import current_app

from ..extensions import db
from ..models import Alert, Site, utcnow
from . import alerting, audit, collector, monitor, notifier
from . import settings as app_settings

log = logging.getLogger(__name__)

MAX_RESULTS_PER_REQUEST = 500
ACTIVE = ("open", "acknowledged")


# ------------------------------------------------------------------ authentication
def authenticate(raw_key):
    """Return the enabled Site for an agent key, 'disabled' for a disabled site, or None."""
    raw_key = (raw_key or "").strip()
    if not raw_key.startswith(Site.KEY_PREFIX) or len(raw_key) > 200:
        return None
    site = Site.query.filter_by(agent_key_hash=Site.hash_key(raw_key)).first()
    if site is None:
        return None
    if not site.enabled:
        return "disabled"
    return site


def heartbeat(site, info, remote_addr, now=None):
    """Record that the agent is alive; clears an agent-offline condition."""
    now = now or utcnow()
    info = info if isinstance(info, dict) else {}
    site.last_seen_at = now
    site.agent_hostname = _clip(info.get("hostname"), 100) or site.agent_hostname
    site.agent_platform = _clip(info.get("platform"), 100) or site.agent_platform
    site.agent_version = _clip(info.get("version"), 20) or site.agent_version
    site.agent_address = _clip(remote_addr, 45)
    if site.agent_offline:
        site.agent_offline = False
        resolved = 0
        for a in _active_offline_alerts(site):
            alerting.resolve(a, now, "Agent reconnected")
            resolved += 1
        audit.record("agent_online", "site", site.site_id, f"Agent for {site.name} reconnected "
                     f"from {site.agent_hostname or 'unknown host'}", user_id=None)
        db.session.commit()
        if resolved and app_settings.get("send_recovery_emails"):
            notifier.send_email(f"[Netwatch] RESOLVED: agent for site {site.name} is back online",
                                f"The Netwatch agent for site '{site.name}' is reporting again "
                                f"(host {site.agent_hostname or 'unknown'}). Monitoring of its "
                                f"{len(site.devices)} device(s) has resumed.\n")
    db.session.commit()


def _clip(v, n):
    return str(v).strip()[:n] if v not in (None, "") else None


# ------------------------------------------------------------------ jobs
def probe_settings():
    cfg = current_app.config
    return {
        "method": cfg.get("AGENT_MONITOR_METHOD", "auto"),
        "ping_count": cfg["PING_COUNT"],
        "timeout_seconds": cfg["PING_TIMEOUT_SECONDS"],
        "tcp_ports": cfg.get("AGENT_TCP_PORTS", [80, 443, 22]),
    }


def jobs_for(site, now=None):
    """Enabled devices of this site that are due (or have a pending 'Check now')."""
    now = now or utcnow()
    out = []
    for d in site.devices:
        if not d.enabled or d.is_simulated:
            continue
        if d.check_requested_at is not None or monitor.is_due(d, now):
            try:
                host = collector.validate_host(d.ip_address)
            except ValueError:
                continue
            out.append({"device_id": d.device_id, "name": d.device_name, "host": host,
                        "interval": d.polling_interval})
    return out


# ------------------------------------------------------------------ results
def _num(v, lo, hi):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError("not a number")
    v = float(v)
    if v != v or v < lo or v > hi:  # NaN or out of range
        raise ValueError("out of range")
    return v


def ingest(site, results, now=None):
    """Validate and store results reported by an agent. Returns (stored, rejected[])."""
    now = now or utcnow()
    if not isinstance(results, list):
        return 0, [{"error": "results must be a list"}]
    if len(results) > MAX_RESULTS_PER_REQUEST:
        return 0, [{"error": f"at most {MAX_RESULTS_PER_REQUEST} results per request"}]
    own = {d.device_id: d for d in site.devices}
    stored, rejected = 0, []
    for item in results:
        if not isinstance(item, dict):
            rejected.append({"error": "result must be an object"})
            continue
        did = item.get("device_id")
        device = own.get(did) if isinstance(did, int) and not isinstance(did, bool) else None
        if device is None:
            rejected.append({"device_id": did, "error": "device is not assigned to this site"})
            continue
        if not device.enabled or device.is_simulated:
            rejected.append({"device_id": did, "error": "device is disabled"})
            continue
        try:
            reachable = item.get("reachable")
            if not isinstance(reachable, bool):
                raise ValueError("reachable must be true or false")
            latency = _num(item.get("latency_ms"), 0, 600000)
            loss = _num(item.get("packet_loss_percent"), 0, 100)
            method = item.get("method", "icmp")
            if method not in ("icmp", "tcp"):
                raise ValueError("method must be icmp or tcp")
            error = item.get("error")
            error = str(error)[:255] if error else None
        except ValueError as exc:
            rejected.append({"device_id": did, "error": f"invalid result: {exc}"})
            continue
        probe = collector.ProbeResult(reachable, latency if reachable else None, loss, method, error)
        lock = monitor._lock_for(device.device_id)
        if not lock.acquire(timeout=10):
            rejected.append({"device_id": did, "error": "device busy, retry"})
            continue
        try:
            monitor.record_probe(device, probe, now)
            stored += 1
        except Exception:
            db.session.rollback()
            log.exception("Could not store agent result for device %s", did)
            rejected.append({"device_id": did, "error": "could not be stored"})
        finally:
            lock.release()
    return stored, rejected


# ------------------------------------------------------------------ offline detection
def offline_after():
    return timedelta(minutes=app_settings.get("agent_offline_minutes"))


def _active_offline_alerts(site):
    ids = [d.device_id for d in site.devices]
    if not ids:
        return []
    return Alert.query.filter(Alert.device_id.in_(ids), Alert.alert_type == "agent_offline",
                              Alert.status.in_(ACTIVE)).all()


def check_sites(now=None):
    """Mark agents that stopped reporting as offline (run by the scheduler on every tick)."""
    now = now or utcnow()
    limit = offline_after()
    changed = []
    for site in Site.query.filter_by(enabled=True, agent_offline=False).all():
        if site.last_seen_at is None or now - site.last_seen_at < limit:
            continue
        site.agent_offline = True
        minutes = int((now - site.last_seen_at).total_seconds() // 60)
        new_alerts = []
        for d in site.devices:
            if not d.enabled or d.is_simulated:
                continue
            d.status, d.consecutive_failures, d.last_status_change_at = "unknown", 0, now
            a = Alert(device_id=d.device_id, alert_type="agent_offline", severity="warning", opened_at=now,
                      message=f"Not being monitored: the Netwatch agent for site '{site.name}' has not "
                              f"reported for {minutes} min (agent computer off, asleep, or offline). "
                              f"The device itself may still be working.")
            db.session.add(a)
            new_alerts.append(a)
        audit.record("agent_offline", "site", site.site_id,
                     f"Agent for {site.name} silent since {site.last_seen_at:%Y-%m-%d %H:%M} UTC", user_id=None)
        db.session.commit()
        if new_alerts:
            status = notifier.send_email(
                f"[Netwatch] WARNING: agent for site {site.name} is offline",
                f"The Netwatch agent for site '{site.name}' has not reported for {minutes} minutes.\n"
                f"Last seen from host: {site.agent_hostname or 'unknown'}.\n\n"
                f"{len(new_alerts)} device(s) on that network are NOT being monitored until it reconnects:\n"
                + "".join(f"  - {a.device.device_name} ({a.device.ip_address})\n" for a in new_alerts)
                + "\nCheck that the agent computer is switched on, connected to the network and that "
                  "the agent program is running.\n")
            for a in new_alerts:
                a.email_status, a.last_notified_at, a.notification_count = status, now, 1
            db.session.commit()
        changed.append(site.site_id)
    return changed


def site_devices_unknown(site, now=None):
    """Used when a site is disabled: its devices can no longer be measured."""
    now = now or utcnow()
    for d in site.devices:
        if d.status != "unknown":
            d.status, d.consecutive_failures, d.last_status_change_at = "unknown", 0, now
