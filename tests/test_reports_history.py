"""FR10/FR11/FR12 — dashboard data, history filters, reports and exports match stored data."""
import csv
import io
from datetime import timedelta

from netwatch.extensions import db
from netwatch.models import Alert, MonitoringResult, utcnow

from conftest import make_device


def add_results(app, did, rows, start=None):
    start = start or utcnow() - timedelta(minutes=30)
    with app.app_context():
        for i, (ok, lat, loss) in enumerate(rows):
            db.session.add(MonitoringResult(device_id=did, checked_at=start + timedelta(minutes=i), reachable=ok,
                                            latency_ms=lat, packet_loss_percent=loss,
                                            method="icmp"))
        db.session.commit()


def test_dashboard_api_reflects_stored_data(app, admin_client):
    a = make_device(app, name="Alpha", ip="10.0.0.1", status="up", last_checked_at=utcnow())
    make_device(app, name="Beta", ip="10.0.0.2", status="down", last_checked_at=utcnow())
    make_device(app, name="Gamma", ip="10.0.0.3", enabled=False)
    add_results(app, a, [(True, 10.0, 0.0), (True, 20.0, 0.0), (False, None, 100.0), (True, 30.0, 0.0)])
    with app.app_context():
        db.session.add(Alert(device_id=a, alert_type="threshold", severity="warning", message="m"))
        db.session.commit()
    j = admin_client.get("/api/dashboard").get_json()
    o = j["overview"]
    assert (o["total"], o["up"], o["down"], o["disabled"]) == (3, 1, 1, 1)
    assert o["uptime_24h"] == 75.0 and o["checks_24h"] == 4
    assert o["avg_latency_1h"] == 20.0  # (10+20+30)/3, failed check has no latency
    assert o["alerts_open"] == 1 and o["alerts_warning"] == 1
    alpha = next(d for d in j["devices"] if d["name"] == "Alpha")
    assert alpha["latency"] == 30.0 and alpha["status"] == "up"
    assert any(s["name"] == "Alpha" and s["points"] for s in j["chart"])
    html = admin_client.get("/").get_data(as_text=True)
    assert "Alpha" in html and "Beta" in html


def test_dashboard_empty_state(admin_client):
    html = admin_client.get("/").get_data(as_text=True)
    assert "No devices registered yet" in html


def test_series_api_ranges(app, admin_client):
    did = make_device(app)
    add_results(app, did, [(True, float(i), 0.0) for i in range(30)], start=utcnow() - timedelta(minutes=40))
    raw = admin_client.get(f"/api/devices/{did}/series?range=1h").get_json()
    assert raw["count"] == 30 and len(raw["points"]) == 30 and raw["points"][0]["latency"] == 0.0
    b = admin_client.get(f"/api/devices/{did}/series?range=24h").get_json()
    assert b["bucket_seconds"] == 600 and sum(p["n"] for p in b["points"]) == 30
    assert admin_client.get(f"/api/devices/{did}/series?range=bogus").get_json()["range"] == "24h"


def test_history_filters_sort_and_pagination(app, admin_client):
    a = make_device(app, name="Alpha", ip="10.0.0.1")
    b = make_device(app, name="Beta", ip="10.0.0.2")
    add_results(app, a, [(True, 1.5, 0.0)] * 30 + [(False, None, 100.0)] * 5)
    add_results(app, b, [(True, 99.0, 0.0)] * 3)
    html = admin_client.get(f"/history/?device={a}&per_page=20").get_data(as_text=True)
    assert "of 35 results" in html and "Beta" not in html.split("<tbody>")[1]
    html = admin_client.get(f"/history/?device={a}&outcome=down").get_data(as_text=True)
    assert "of 5 results" in html
    html = admin_client.get("/history/?sort=latency&order=desc&outcome=up").get_data(as_text=True)
    body = html.split("<tbody>")[1]
    assert body.index("99.00 ms") < body.index("1.50 ms")
    html = admin_client.get("/history/?start=2000-01-01&end=2000-01-02").get_data(as_text=True)
    assert "No results in this period" in html
    r = admin_client.get("/history/?start=not-a-date")
    assert r.status_code == 200 and b"YYYY-MM-DD" in r.data


def test_history_csv_export_matches_filter(app, admin_client):
    a = make_device(app, name="Alpha", ip="10.0.0.1")
    add_results(app, a, [(True, 2.0, 0.0), (False, None, 100.0), (True, 4.0, 25.0)])
    r = admin_client.get(f"/history/export.csv?device={a}&outcome=up")
    assert r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert len(rows) == 2 and {row["latency_ms"] for row in rows} == {"2.0", "4.0"}
    assert all(row["data_source"] == "measured" for row in rows)


def test_report_statistics_match_stored_data(app, admin_client):
    a = make_device(app, name="Alpha", ip="10.0.0.1")
    add_results(app, a, [(True, 10.0, 0.0), (True, 30.0, 25.0), (False, None, 100.0), (True, 20.0, 0.0)])
    sim = make_device(app, name="Sim", ip="10.9.9.9", is_simulated=True)
    with app.app_context():
        db.session.add(Alert(device_id=a, alert_type="device_down", severity="critical", message="x"))
        db.session.commit()
    r = admin_client.get(f"/reports/export.csv?device={a}&device={sim}")
    lines = r.get_data(as_text=True).splitlines()
    header_idx = next(i for i, l in enumerate(lines) if l.startswith("device,"))
    rows = {row["device"]: row for row in csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))}
    alpha = rows["Alpha"]
    assert alpha["checks"] == "4" and alpha["successful"] == "3" and alpha["uptime_percent"] == "75.0"
    assert (alpha["latency_min_ms"], alpha["latency_avg_ms"], alpha["latency_max_ms"]) == ("10.0", "20.0", "30.0")
    assert alpha["loss_max_percent"] == "100.0" and alpha["alerts_opened"] == "1"
    assert rows["Sim"]["data_source"] == "SIMULATED" and rows["Sim"]["checks"] == "0"
    html = admin_client.get(f"/reports/?device={a}").get_data(as_text=True)
    assert "75.00%" in html


def test_report_pdf_export(app, admin_client):
    a = make_device(app, name="Alpha", ip="10.0.0.1")
    add_results(app, a, [(True, 10.0, 0.0)])
    r = admin_client.get("/reports/export.pdf")
    assert r.mimetype == "application/pdf" and r.data[:5] == b"%PDF-" and len(r.data) > 1500


def test_report_date_validation(admin_client):
    r = admin_client.get("/reports/?start=2026-05-10&end=2026-05-01")
    assert r.status_code == 200 and b"swapped" in r.data
    r = admin_client.get("/reports/?start=1990-01-01&end=2026-01-01")
    assert r.status_code == 200 and b"limited" in r.data


def test_audit_log_page_and_filter(app, admin_client):
    make_device(app)
    html = admin_client.get("/settings/audit?action=login").get_data(as_text=True)
    assert "Signed in" in html


def test_settings_validation_and_save(app, admin_client):
    from conftest import csrf
    from netwatch.services import settings as s
    token = csrf(admin_client, "/settings/")
    base = {"failure_threshold": "3", "reminder_interval_minutes": "30", "default_polling_interval": "120",
            "retention_days": "30", "email_alerts_enabled": "y", "extra_alert_recipients": "noc@example.com",
            "csrf_token": token}
    r = admin_client.post("/settings/", data=base)
    assert r.status_code == 302
    with app.app_context():
        assert s.get("failure_threshold") == 3 and s.get("send_recovery_emails") is False
        assert s.get("extra_alert_recipients") == "noc@example.com"
    bad = dict(base, failure_threshold="50", extra_alert_recipients="not-an-email")
    r = admin_client.post("/settings/", data=bad)
    assert r.status_code == 200 and b"nothing was saved" in r.data
    with app.app_context():
        assert s.get("failure_threshold") == 3
