"""NFR1/NFR3/NFR7/NFR8 — security controls, failure handling, persistence, performance."""
import time
from datetime import timedelta

from sqlalchemy.exc import OperationalError

from netwatch import create_app
from netwatch.extensions import db
from netwatch.models import Device, MonitoringResult, User, utcnow

from conftest import PASSWORD, csrf, make_config, make_device, make_user


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_session_cookie_flags(app, client):
    make_user(app)
    from conftest import login
    login(client)
    cookie = client.get_cookie("session")
    assert cookie is not None and cookie.http_only and cookie.same_site == "Lax"


def test_passwords_are_hashed(app):
    uid = make_user(app)
    with app.app_context():
        h = db.session.get(User, uid).password_hash
        assert PASSWORD not in h and (h.startswith("scrypt:") or h.startswith("pbkdf2:"))


def test_sql_injection_in_search_is_harmless(app, admin_client):
    make_device(app, name="Alpha")
    for q in ["' OR 1=1 --", "\"; DROP TABLE devices; --", "%' UNION SELECT password_hash FROM users --"]:
        r = admin_client.get("/devices/", query_string={"q": q})
        assert r.status_code == 200 and b"No devices match" in r.data
        assert admin_client.get("/history/", query_string={"device": q}).status_code == 200
    with app.app_context():
        assert Device.query.count() == 1


def test_stored_xss_is_escaped(app, admin_client):
    payload = '<script>alert("x")</script>'
    token = csrf(admin_client, "/devices/new")
    admin_client.post("/devices/new", data={"device_name": payload, "ip_address": "10.0.0.1", "device_type": "router",
                                            "polling_interval": "60", "enabled": "y", "csrf_token": token})
    for url in ["/devices/", "/", "/devices/1"]:
        html = admin_client.get(url).get_data(as_text=True)
        assert payload not in html and "&lt;script&gt;" in html


def test_secrets_not_exposed(app, admin_client):
    app.config["MAIL_PASSWORD"] = "very-secret-mail-password"
    html = admin_client.get("/settings/").get_data(as_text=True)
    assert "very-secret-mail-password" not in html and app.config["SECRET_KEY"] not in html
    assert "SECRET_KEY" not in admin_client.get("/healthz").get_data(as_text=True)


def test_database_failure_shows_friendly_page(app, admin_client, monkeypatch):
    from netwatch.blueprints import devices as dev_bp

    class Broken:
        def __getattr__(self, name):
            raise OperationalError("SELECT", {}, Exception("connection refused to db host 10.1.2.3"))
    monkeypatch.setattr(dev_bp, "Device", Broken())
    r = admin_client.get("/devices/")
    assert r.status_code == 503 and b"Database unavailable" in r.data
    assert b"10.1.2.3" not in r.data  # no internal details leaked


def test_health_endpoint_reports_db_failure(app, client, monkeypatch):
    assert client.get("/healthz").get_json()["database"] == "ok"

    def fail(*a, **k):
        raise OperationalError("SELECT 1", {}, Exception("down"))
    monkeypatch.setattr(db.session, "execute", fail)
    r = client.get("/healthz")
    assert r.status_code == 503 and r.get_json()["database"] == "unavailable"


def test_unreachable_database_url_does_not_crash_startup(tmp_path):
    bad = make_config(tmp_path / "x.db", SQLALCHEMY_DATABASE_URI="sqlite:////nonexistent-dir/forbidden/x.db")
    app = create_app(bad)  # logs the error instead of raising
    r = app.test_client().get("/healthz")
    assert r.status_code == 503


def test_data_persists_across_restart(db_path):
    app1 = create_app(make_config(db_path))
    did = make_device(app1, name="Persistent")
    with app1.app_context():
        db.session.add(MonitoringResult(device_id=did, reachable=True, latency_ms=3.3, packet_loss_percent=0))
        db.session.commit()
        db.engine.dispose()
    app2 = create_app(make_config(db_path))  # "restart"
    with app2.app_context():
        assert Device.query.one().device_name == "Persistent"
        assert MonitoringResult.query.one().latency_ms == 3.3


def test_dashboard_performance_with_many_records(app, admin_client):
    """NFR3 — 10 devices × 2,000 results each (20k rows) should still render quickly."""
    now = utcnow()
    with app.app_context():
        for i in range(10):
            d = Device(device_name=f"Dev {i}", ip_address=f"10.0.0.{i + 1}", status="up", last_checked_at=now)
            db.session.add(d)
            db.session.flush()
            db.session.bulk_insert_mappings(MonitoringResult, [
                {"device_id": d.device_id, "checked_at": now - timedelta(minutes=j), "reachable": j % 50 != 0,
                 "latency_ms": 5 + j % 7, "packet_loss_percent": 0.0, "method": "icmp"} for j in range(2000)])
        db.session.commit()
    timings = {}
    for url in ["/", "/api/dashboard", "/history/", "/reports/", "/api/devices/1/series?range=7d"]:
        t = time.perf_counter()
        assert admin_client.get(url).status_code == 200
        timings[url] = time.perf_counter() - t
    print("\nNFR3 response times (s):", {k: round(v, 3) for k, v in timings.items()})
    assert max(timings.values()) < 3.0, timings
