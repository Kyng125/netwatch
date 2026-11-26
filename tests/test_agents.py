"""On-site agents: monitoring private LAN devices from the cloud server.

Covers the Site model and key handling, the agent API (auth, jobs, results), the cloud collector
leaving agent devices alone, offline detection, the schema upgrade for existing databases, the
Sites pages, and a real end-to-end run of agent/netwatch_agent.py against a live HTTP server."""
import importlib.util
import re
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy.schema import CreateTable

from conftest import csrf, make_config, make_device, make_user
from netwatch import create_app
from netwatch.extensions import db
from netwatch.models import Alert, AuditLog, Device, MonitoringResult, Site, utcnow
from netwatch.services import agents, collector, monitor
from netwatch.services import settings as app_settings

ROOT = Path(__file__).resolve().parent.parent


def load_agent():
    spec = importlib.util.spec_from_file_location("netwatch_agent", ROOT / "agent" / "netwatch_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_site(app, name="Head office LAN", enabled=True):
    with app.app_context():
        key = Site.new_key()
        s = Site(name=name, enabled=enabled)
        s.set_key(key)
        db.session.add(s)
        db.session.commit()
        return s.site_id, key


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def ok(lat=3.0, loss=0.0, did=None, method="icmp"):
    return {"device_id": did, "reachable": True, "latency_ms": lat, "packet_loss_percent": loss, "method": method}


def fail(did=None):
    return {"device_id": did, "reachable": False, "latency_ms": None, "packet_loss_percent": 100.0,
            "method": "icmp", "error": "No echo replies received"}


@pytest.fixture
def site(app):
    return make_site(app)


# ------------------------------------------------------------------ keys
def test_key_is_stored_only_as_hash(app, site):
    sid, key = site
    with app.app_context():
        s = db.session.get(Site, sid)
        assert key.startswith("nwa_") and len(key) > 40
        assert s.agent_key_hash == Site.hash_key(key) and key not in s.agent_key_hash
        assert s.key_hint == key[:10]
        assert agents.authenticate(key).site_id == sid
        assert agents.authenticate(key + "x") is None
        assert agents.authenticate("") is None and agents.authenticate("Bearer nope") is None


# ------------------------------------------------------------------ API auth
def test_api_requires_valid_key(app, client, site):
    sid, key = site
    assert client.get("/api/agent/v1/jobs").status_code == 401
    assert client.get("/api/agent/v1/jobs", headers=auth("nwa_wrong")).status_code == 401
    r = client.post("/api/agent/v1/results", json={"results": []}, headers=auth("nwa_wrong"))
    assert r.status_code == 401 and r.get_json()["error"] == "unauthorized"
    assert client.get("/api/agent/v1/jobs", headers=auth(key)).status_code == 200


def test_disabled_site_is_refused(app, client):
    _sid, key = make_site(app, enabled=False)
    r = client.get("/api/agent/v1/jobs", headers=auth(key))
    assert r.status_code == 403 and r.get_json()["error"] == "disabled"


def test_agent_api_needs_no_csrf_token(app, client, site):
    """Agents authenticate with their key, not a browser session; CSRF is ON in the test config."""
    sid, key = site
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    r = client.post("/api/agent/v1/results", json={"results": [ok(did=did)]}, headers=auth(key))
    assert r.status_code == 200 and r.get_json()["stored"] == 1


# ------------------------------------------------------------------ jobs
def test_jobs_lists_only_this_sites_enabled_due_devices(app, client, site):
    sid, key = site
    other_sid, _ = make_site(app, "Lab 2")
    gw = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    make_device(app, "Paused printer", "10.150.121.50", site_id=sid, enabled=False)
    make_device(app, "Other site", "192.168.5.1", site_id=other_sid)
    make_device(app, "Cloud target", "8.8.8.8")
    r = client.post("/api/agent/v1/jobs", json={"hostname": "LAB-PC", "version": "1.0.0", "platform": "Windows 11"},
                    headers=auth(key))
    body = r.get_json()
    assert r.status_code == 200
    assert [j["host"] for j in body["jobs"]] == ["10.150.121.187"]
    assert body["jobs"][0]["device_id"] == gw and body["site"]["name"] == "Head office LAN"
    assert body["device_count"] == 1 and body["poll_seconds"] > 0
    assert body["probe"]["method"] == "auto" and body["probe"]["tcp_ports"]
    with app.app_context():
        s = db.session.get(Site, sid)
        assert s.agent_hostname == "LAB-PC" and s.agent_version == "1.0.0" and s.last_seen_at is not None
        assert s.connection_state == "online"


def test_recently_checked_device_is_not_due_until_check_requested(app, client, site):
    sid, key = site
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid, polling_interval=300)
    client.post("/api/agent/v1/results", json={"results": [ok(did=did)]}, headers=auth(key))
    assert client.get("/api/agent/v1/jobs", headers=auth(key)).get_json()["jobs"] == []
    with app.app_context():
        db.session.get(Device, did).check_requested_at = utcnow()
        db.session.commit()
    assert [j["device_id"] for j in client.get("/api/agent/v1/jobs", headers=auth(key)).get_json()["jobs"]] == [did]
    client.post("/api/agent/v1/results", json={"results": [ok(did=did)]}, headers=auth(key))
    with app.app_context():
        assert db.session.get(Device, did).check_requested_at is None  # request served


# ------------------------------------------------------------------ results
def test_results_are_stored_and_drive_status_and_alerts(app, client, site):
    sid, key = site
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid,
                      thresholds=[("latency_ms", ">", 100, "warning")])
    r = client.post("/api/agent/v1/results", json={"results": [ok(2.5, did=did)]}, headers=auth(key))
    assert r.get_json() == {"stored": 1, "rejected": []}
    with app.app_context():
        d = db.session.get(Device, did)
        res = d.latest_result()
        assert d.status == "up" and res.latency_ms == 2.5 and res.method == "icmp" and res.uptime_percent == 100
    client.post("/api/agent/v1/results", json={"results": [ok(250, did=did, method="tcp")]}, headers=auth(key))
    client.post("/api/agent/v1/results", json={"results": [fail(did)]}, headers=auth(key))
    client.post("/api/agent/v1/results", json={"results": [fail(did)]}, headers=auth(key))  # 2 = failure_threshold
    with app.app_context():
        d = db.session.get(Device, did)
        types = sorted((a.alert_type, a.status) for a in Alert.query.filter_by(device_id=did))
        assert d.status == "down"
        assert ("device_down", "open") in types and ("threshold", "open") in types
        assert MonitoringResult.query.filter_by(device_id=did).count() == 4
    client.post("/api/agent/v1/results", json={"results": [ok(3, did=did)]}, headers=auth(key))
    with app.app_context():
        assert db.session.get(Device, did).status == "up"
        assert Alert.query.filter_by(device_id=did, alert_type="device_down").one().status == "resolved"


def test_results_for_other_sites_or_bad_values_are_rejected(app, client, site):
    sid, key = site
    other_sid, _ = make_site(app, "Lab 2")
    mine = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    theirs = make_device(app, "Their router", "192.168.5.1", site_id=other_sid)
    cloud = make_device(app, "Cloud", "8.8.8.8")
    payload = {"results": [
        ok(did=theirs), ok(did=cloud), ok(did=99999), ok(did="1"),
        dict(ok(did=mine), latency_ms=-5), dict(ok(did=mine), packet_loss_percent=150),
        dict(ok(did=mine), reachable="yes"), dict(ok(did=mine), method="simulated"),
        "junk",
    ]}
    r = client.post("/api/agent/v1/results", json=payload, headers=auth(key))
    body = r.get_json()
    assert r.status_code == 422 and body["stored"] == 0 and len(body["rejected"]) == 9
    with app.app_context():
        assert MonitoringResult.query.count() == 0
    assert client.post("/api/agent/v1/results", data="not json", headers=auth(key)).status_code == 400
    r = client.post("/api/agent/v1/results", json={"results": [ok(did=mine)] * 501}, headers=auth(key))
    assert r.status_code == 422


# ------------------------------------------------------------------ cloud collector leaves agent devices alone
def test_cloud_scheduler_never_probes_agent_devices(app, site, monkeypatch):
    sid, _key = site
    lan = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    pub = make_device(app, "Public", "203.0.113.5")
    calls = []
    monkeypatch.setattr(collector, "probe", lambda host, **kw: calls.append(host) or collector.ProbeResult(True, 1.0, 0.0))
    with app.app_context():
        assert monitor.due_device_ids() == [pub]
        assert monitor.check_device(lan) is None
        assert monitor.check_device(pub) is not None
    assert calls == ["203.0.113.5"]


# ------------------------------------------------------------------ offline detection
def test_silent_agent_marks_devices_unknown_and_recovers(app, client, site, smtp_sink):
    sid, key = site
    app.config.update(MAIL_SERVER="127.0.0.1", MAIL_PORT=smtp_sink.server_address[1], MAIL_USE_TLS=False,
                      MAIL_FROM="netwatch@example.com")
    make_user(app, "ops", email="ops@example.com")
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    client.post("/api/agent/v1/results", json={"results": [ok(did=did)]}, headers=auth(key))
    with app.app_context():
        assert agents.check_sites() == []  # just reported
        later = utcnow() + timedelta(minutes=app_settings.get("agent_offline_minutes") + 1)
        assert agents.check_sites(later) == [sid]
        assert agents.check_sites(later) == []  # only once
        s, d = db.session.get(Site, sid), db.session.get(Device, did)
        assert s.connection_state == "offline" and d.status == "unknown"  # not 'down': the device may be fine
        a = Alert.query.filter_by(device_id=did, alert_type="agent_offline").one()
        assert a.status == "open" and "not being monitored" in a.message.lower()
        assert AuditLog.query.filter_by(action="agent_offline").count() == 1
    assert any("agent for site Head office LAN is offline" in m for m in smtp_sink.messages)
    # agent comes back
    assert client.get("/api/agent/v1/jobs", headers=auth(key)).status_code == 200
    with app.app_context():
        assert db.session.get(Site, sid).connection_state == "online"
        assert Alert.query.filter_by(device_id=did, alert_type="agent_offline").one().status == "resolved"
    assert any("back online" in m for m in smtp_sink.messages)


def test_site_that_never_connected_raises_no_alert(app, site):
    sid, _key = site
    make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    with app.app_context():
        assert agents.check_sites(utcnow() + timedelta(days=1)) == []
        assert db.session.get(Site, sid).connection_state == "never"


# ------------------------------------------------------------------ schema upgrade of an existing database
@pytest.mark.skipif(bool(__import__("conftest").PG_URL),
                    reason="builds an old-format SQLite file; the PostgreSQL upgrade is checked with the live "
                           "code's schema as described in docs/VERIFICATION_REPORT.md")
def test_existing_database_gets_new_columns(tmp_path):
    """The live deployment's devices table predates agents; create_all() alone would not add columns."""
    path = tmp_path / "old.db"
    ddl = str(CreateTable(Device.__table__).compile(dialect=__import__("sqlalchemy.dialects.sqlite",
                                                                     fromlist=["dialect"]).dialect()))
    ddl = re.sub(r",\s*site_id INTEGER", "", ddl)
    ddl = re.sub(r",\s*check_requested_at DATETIME", "", ddl)
    ddl = re.sub(r",\s*FOREIGN KEY\(site_id\)[^,)]*\)[^,)]*", "", ddl)
    ddl = re.sub(r",\s*FOREIGN KEY\(user_id\)[^,)]*\)[^,)]*", "", ddl)
    con = sqlite3.connect(path)
    con.execute(ddl)
    con.execute("INSERT INTO devices (device_name, ip_address, device_type, snmp_enabled, enabled, status, "
                "polling_interval, is_simulated, consecutive_failures, created_at) "
                "VALUES ('Old router', '192.168.1.1', 'router', 0, 1, 'up', 60, 0, 0, '2026-10-01 00:00:00')")
    con.commit()
    cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
    con.close()
    assert "site_id" not in cols
    app = create_app(make_config(path))  # runs create_all() + migrations.upgrade()
    with app.app_context():
        d = Device.query.one()
        assert d.device_name == "Old router" and d.site_id is None and d.checked_by_agent is False
        from netwatch import migrations
        assert migrations.upgrade() == []  # idempotent
        db.session.remove()
        db.engine.dispose()


# ------------------------------------------------------------------ pages
def test_admin_creates_site_and_sees_key_once(app, admin_client):
    token = csrf(admin_client, "/sites/new")
    r = admin_client.post("/sites/new", data={"name": "Computer lab", "description": "Block C", "enabled": "y",
                                              "csrf_token": token})
    assert r.status_code == 302
    page = admin_client.get(r.headers["Location"]).get_data(as_text=True)
    key = re.search(r"(nwa_[A-Za-z0-9_-]{30,})", page).group(1)
    assert "copy it now" in page and f"--key {key} --save" in page
    with app.app_context():
        s = Site.query.one()
        assert s.agent_key_hash == Site.hash_key(key) and AuditLog.query.filter_by(action="site_created").count() == 1
    again = admin_client.get(f"/sites/{s.site_id}").get_data(as_text=True)
    assert key not in again and "PASTE-THE-AGENT-KEY-HERE" in again
    assert "Computer lab" in admin_client.get("/sites/").get_data(as_text=True)


def test_rotate_key_invalidates_old_key(app, admin_client, site):
    sid, old = site
    token = csrf(admin_client, f"/sites/{sid}")
    r = admin_client.post(f"/sites/{sid}/rotate-key", data={"csrf_token": token})
    new = re.search(r"(nwa_[A-Za-z0-9_-]{30,})", admin_client.get(r.headers["Location"]).get_data(as_text=True)).group(1)
    assert new != old
    assert admin_client.get("/api/agent/v1/jobs", headers=auth(old)).status_code == 401
    assert admin_client.get("/api/agent/v1/jobs", headers=auth(new)).status_code == 200


def test_register_device_on_a_site_via_form(app, admin_client, site):
    sid, _key = site
    html = admin_client.get(f"/devices/new?site={sid}").get_data(as_text=True)
    assert re.search(rf'<option selected value="{sid}">|<option value="{sid}" selected', html)
    token = csrf(admin_client, "/devices/new")
    r = admin_client.post("/devices/new", data={"device_name": "Hotspot gateway", "ip_address": "10.150.121.187",
                                                "device_type": "router", "polling_interval": "60", "enabled": "y",
                                                "site_id": str(sid), "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        d = Device.query.filter_by(device_name="Hotspot gateway").one()
        assert d.site_id == sid and d.checked_by_agent
    page = admin_client.get(f"/devices/{d.device_id}").get_data(as_text=True)
    assert "On-site agent" in page and "not connected yet" in page
    bad = admin_client.post("/devices/new", data={"device_name": "X", "ip_address": "10.0.0.2", "device_type": "router",
                                                  "polling_interval": "60", "site_id": "999", "csrf_token": token})
    assert bad.status_code == 400 and b"Choose a site" in bad.data


def test_check_now_on_agent_device_queues_request(app, admin_client, site, monkeypatch):
    sid, _key = site
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    monkeypatch.setattr(collector, "probe", lambda *a, **k: pytest.fail("cloud must not probe a LAN device"))
    token = csrf(admin_client, f"/devices/{did}")
    r = admin_client.post(f"/devices/{did}/check", data={"csrf_token": token}, follow_redirects=True)
    assert b"Check requested" in r.data
    with app.app_context():
        assert db.session.get(Device, did).check_requested_at is not None


def test_deleting_site_keeps_but_disables_devices(app, admin_client, site):
    sid, key = site
    did = make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    token = csrf(admin_client, f"/sites/{sid}")
    assert admin_client.post(f"/sites/{sid}/delete", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        d = db.session.get(Device, did)
        assert d.site_id is None and d.enabled is False and Site.query.count() == 0
    assert admin_client.get("/api/agent/v1/jobs", headers=auth(key)).status_code == 401


def test_viewer_can_view_but_not_manage_sites(app, viewer_client, site):
    sid, key = site
    assert viewer_client.get("/sites/").status_code == 200
    page = viewer_client.get(f"/sites/{sid}").get_data(as_text=True)
    assert "Start the agent" not in page and key not in page
    assert viewer_client.get("/sites/new").status_code == 403
    token = csrf(viewer_client, f"/sites/{sid}")
    assert viewer_client.post(f"/sites/{sid}/rotate-key", data={"csrf_token": token}).status_code == 403


def test_agent_download_requires_login(app, client, admin_client):
    anon = app.test_client()
    assert anon.get("/sites/agent/netwatch_agent.py").status_code == 302
    r = admin_client.get("/sites/agent/netwatch_agent.py")
    assert r.status_code == 200 and b"Netwatch on-site agent" in r.data and "attachment" in r.headers["Content-Disposition"]


def test_dashboard_api_reports_site(app, admin_client, site):
    sid, _key = site
    make_device(app, "Gateway", "10.150.121.187", site_id=sid)
    dev = admin_client.get("/api/dashboard").get_json()["devices"][0]
    assert dev["site"] == "Head office LAN"


# ------------------------------------------------------------------ the agent program itself
@pytest.mark.parametrize("name", ["LINUX_OK", "LINUX_DOWN", "BUSYBOX", "MAC", "WINDOWS_OK", "WINDOWS_UNREACH"])
def test_agent_parses_ping_exactly_like_the_server(name):
    import test_collector
    agent = load_agent()
    text = getattr(test_collector, name)
    assert agent.parse_ping_output(text, 4) == collector.parse_ping_output(text, 4)


@pytest.mark.parametrize("bad", ["-f", "--help", "1.2.3.4; rm -rf /", "a b", ""])
def test_agent_refuses_unsafe_addresses(bad):
    with pytest.raises(ValueError):
        load_agent().validate_host(bad)


def test_agent_end_to_end_against_live_server(tmp_path, listening_port):
    """Start the real web app on a port, then run the real agent code against it."""
    from werkzeug.serving import make_server

    app = create_app(make_config(tmp_path / "e2e.db", PING_COUNT=1, PING_TIMEOUT_SECONDS=1,
                                 AGENT_MONITOR_METHOD="tcp", AGENT_TCP_PORTS=[listening_port]))
    sid, key = make_site(app, "Test LAN")
    up_id = make_device(app, "Loopback", "127.0.0.1", site_id=sid)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        agent = load_agent()
        url = f"http://127.0.0.1:{srv.server_port}"
        assert agent.run_once(agent.Client(url, key)) == 0
        assert agent.run_once(agent.Client(url, "nwa_definitely-wrong")) == 2
        with app.app_context():
            d = db.session.get(Device, up_id)
            r = d.latest_result()
            assert d.status == "up" and r.reachable and r.method == "tcp" and r.latency_ms is not None
            s = db.session.get(Site, sid)
            assert s.connection_state == "online" and s.agent_version == agent.VERSION
    finally:
        srv.shutdown()
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


def test_agent_settings_file_roundtrip(tmp_path, monkeypatch):
    agent = load_agent()
    monkeypatch.setattr(agent, "CONFIG_FILE", tmp_path / "netwatch-agent.ini")
    monkeypatch.delenv("NETWATCH_SERVER", raising=False)
    monkeypatch.delenv("NETWATCH_AGENT_KEY", raising=False)
    agent.save_settings("https://nw.example.com", "nwa_abc")
    args = type("A", (), {"server": None, "key": None})()
    assert agent.load_settings(args) == ("https://nw.example.com", "nwa_abc")
    assert agent.main(["--server", "https://x", "--key", "wrong-prefix", "--once"]) == 2


class _FakeSocket:
    """Stands in for socket.socket; `behaviour` decides what connect() does for every address."""
    behaviour = "refuse"

    def __init__(self, *a, **k):
        pass

    def settimeout(self, _t):
        pass

    def connect(self, _addr):
        if self.behaviour == "refuse":
            raise ConnectionRefusedError
        raise TimeoutError

    def close(self):
        pass


@pytest.mark.parametrize("behaviour, trusted", [("refuse", False), ("timeout", True)])
def test_agent_detects_networks_that_fake_refusals(monkeypatch, behaviour, trusted):
    agent = load_agent()
    _FakeSocket.behaviour = behaviour
    monkeypatch.setattr(agent.socket, "socket", _FakeSocket)
    assert agent.refusals_are_trustworthy() is trusted


def test_faked_refusal_does_not_make_a_missing_lan_device_look_up(monkeypatch):
    """On a firewall that answers for every address, a switched-off printer must still be DOWN."""
    agent = load_agent()
    _FakeSocket.behaviour = "refuse"
    monkeypatch.setattr(agent.socket, "socket", _FakeSocket)
    res = agent.tcp_probe("10.150.121.50", [22, 9100], 2, 0.2)
    assert res["reachable"] is False and res["method"] == "tcp"
    monkeypatch.setattr(agent, "refusals_are_trustworthy", lambda: True)
    assert agent.tcp_probe("10.150.121.50", [22], 1, 0.2)["reachable"] is True  # normal network: RST = alive


def test_agent_confirms_failed_ping_over_tcp(monkeypatch):
    agent = load_agent()
    down = {"reachable": False, "latency_ms": None, "packet_loss_percent": 100.0, "method": "icmp", "error": "x"}
    up = {"reachable": True, "latency_ms": 1.0, "packet_loss_percent": 0.0, "method": "tcp", "error": None}
    monkeypatch.setattr(agent, "icmp_probe", lambda *a: dict(down))
    monkeypatch.setattr(agent, "tcp_probe", lambda *a: dict(up))
    assert agent.probe("10.0.0.5", {"method": "auto"})["method"] == "tcp"      # PC that blocks ping
    assert agent.probe("10.0.0.5", {"method": "icmp"})["reachable"] is False   # ICMP-only: no fallback
    monkeypatch.setattr(agent, "tcp_probe", lambda *a: dict(down, method="tcp"))
    assert agent.probe("10.0.0.5", {"method": "auto"})["method"] == "icmp"     # genuinely down
