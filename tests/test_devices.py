"""FR3/FR7/NFR8 — device registration, editing, enable/disable, removal, thresholds, listing."""
import pytest

from netwatch.extensions import db
from netwatch.models import Alert, AuditLog, Device, MonitoringResult, Threshold, utcnow

from conftest import csrf, make_device


def post_device(client, url="/devices/new", **data):
    payload = {"device_name": "Core Switch", "ip_address": "192.168.1.2", "device_type": "switch",
               "polling_interval": "60", "enabled": "y", "location": "Server room"}
    payload.update(data)
    payload = {k: v for k, v in payload.items() if v is not None}
    payload["csrf_token"] = csrf(client, url)
    return client.post(url, data=payload)


def test_register_valid_device_with_default_thresholds(app, admin_client):
    r = post_device(admin_client, add_default_thresholds="y")
    assert r.status_code == 302
    with app.app_context():
        d = Device.query.one()
        assert (d.device_name, d.ip_address, d.status, d.enabled) == ("Core Switch", "192.168.1.2", "unknown", True)
        assert len(d.thresholds) == 4
        assert AuditLog.query.filter_by(action="device_created", entity_id=d.device_id).count() == 1


@pytest.mark.parametrize("ip,ok", [("10.0.0.1", True), ("router.office.local", True), ("::1", True),
                                   ("999.1.1.1", False), ("-f", False), ("1.2.3.4; rm -rf /", False),
                                   ("", False), ("a" * 300, False)])
def test_address_validation(app, admin_client, ip, ok):
    r = post_device(admin_client, ip_address=ip)
    assert (r.status_code == 302) is ok
    with app.app_context():
        assert Device.query.count() == (1 if ok else 0)


@pytest.mark.parametrize("interval", ["5", "100000", "abc", ""])
def test_polling_interval_validation(app, admin_client, interval):
    r = post_device(admin_client, polling_interval=interval)
    assert r.status_code == 400
    with app.app_context():
        assert Device.query.count() == 0


def test_missing_name_rejected(admin_client):
    r = post_device(admin_client, device_name="")
    assert r.status_code == 400 and b"This field is required" in r.data


def test_duplicate_device_name_rejected_case_insensitive(app, admin_client):
    assert post_device(admin_client).status_code == 302
    r = post_device(admin_client, device_name="core switch", ip_address="10.0.0.9")
    assert r.status_code == 400 and b"already exists" in r.data


def test_snmp_requires_community(admin_client):
    r = post_device(admin_client, snmp_enabled="y")
    assert r.status_code == 400 and b"community" in r.data


def test_edit_device(app, admin_client):
    did = make_device(app)
    r = post_device(admin_client, f"/devices/{did}/edit", device_name="Edge Router", ip_address="10.1.1.1",
                    polling_interval="120", device_type="router")
    assert r.status_code == 302
    with app.app_context():
        d = db.session.get(Device, did)
        assert (d.device_name, d.ip_address, d.polling_interval) == ("Edge Router", "10.1.1.1", 120)


def test_edit_page_never_echoes_snmp_secret(app, admin_client):
    did = make_device(app, snmp_enabled=True, snmp_community="s3cret-community")
    assert b"s3cret-community" not in admin_client.get(f"/devices/{did}/edit").data


def test_disable_and_enable_device_closes_alerts(app, admin_client):
    did = make_device(app)
    with app.app_context():
        db.session.add(Alert(device_id=did, alert_type="device_down", severity="critical", message="down"))
        db.session.commit()
    token = csrf(admin_client, "/devices/")
    assert admin_client.post(f"/devices/{did}/toggle", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        d = db.session.get(Device, did)
        assert d.enabled is False and d.display_status == "disabled"
        assert Alert.query.one().status == "resolved"
    admin_client.post(f"/devices/{did}/toggle", data={"csrf_token": token})
    with app.app_context():
        assert db.session.get(Device, did).enabled is True


def test_delete_device_cascades_history(app, admin_client):
    did = make_device(app, thresholds=[("latency_ms", ">", 100, "warning")])
    with app.app_context():
        r = MonitoringResult(device_id=did, reachable=True, latency_ms=1, packet_loss_percent=0)
        db.session.add(r)
        db.session.flush()
        db.session.add(Alert(device_id=did, result_id=r.result_id, alert_type="threshold", severity="warning",
                             message="x"))
        db.session.commit()
    token = csrf(admin_client, "/devices/")
    assert admin_client.post(f"/devices/{did}/delete", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        assert Device.query.count() == MonitoringResult.query.count() == Alert.query.count() == 0
        assert Threshold.query.count() == 0


def test_nonexistent_ids_return_404(admin_client):
    token = csrf(admin_client, "/devices/")
    assert admin_client.get("/devices/999").status_code == 404
    assert admin_client.get("/devices/999/edit").status_code == 404
    assert admin_client.post("/devices/999/delete", data={"csrf_token": token}).status_code == 404
    assert admin_client.get("/api/devices/999/series").status_code == 404
    assert admin_client.get("/alerts/999").status_code == 404


def test_viewer_cannot_modify_devices(app, viewer_client):
    did = make_device(app)
    token = csrf(viewer_client, "/devices/")
    assert viewer_client.post(f"/devices/{did}/delete", data={"csrf_token": token}).status_code == 403
    assert viewer_client.post(f"/devices/{did}/toggle", data={"csrf_token": token}).status_code == 403
    with app.app_context():
        assert db.session.get(Device, did) is not None


def test_search_filter_sort_and_paginate(app, admin_client):
    for i in range(25):
        make_device(app, name=f"Switch {i:02d}", ip=f"10.0.0.{i + 1}", device_type="switch")
    make_device(app, name="Lobby AP", ip="10.9.9.9", device_type="access_point", status="down")
    html = admin_client.get("/devices/?q=lobby").get_data(as_text=True)
    assert "Lobby AP" in html and "Switch 00" not in html
    html = admin_client.get("/devices/?q=10.0.0.7").get_data(as_text=True)
    assert "Switch 06" in html and "Lobby AP" not in html
    html = admin_client.get("/devices/?type=access_point").get_data(as_text=True)
    assert "Lobby AP" in html and "Switch 01" not in html
    html = admin_client.get("/devices/?status=down").get_data(as_text=True)
    assert "Lobby AP" in html and "Switch 01" not in html
    html = admin_client.get("/devices/?type=switch&sort=name&order=desc").get_data(as_text=True)
    assert html.index("Switch 24") < html.index("Switch 23")
    page1 = admin_client.get("/devices/?type=switch&per_page=10").get_data(as_text=True)
    page3 = admin_client.get("/devices/?type=switch&per_page=10&page=3").get_data(as_text=True)
    assert "Showing 1–10 of 25" in page1 and "Showing 21–25 of 25" in page3
    assert "Switch 00" in page1 and "Switch 00" not in page3
    # junk parameters degrade gracefully
    assert admin_client.get("/devices/?page=abc&per_page=-5&sort=evil&order=x").status_code == 200


# --------------------------------------------------------------- thresholds
def add_rule(client, did, **data):
    payload = {"metric_name": "latency_ms", "comparison_operator": ">", "threshold_value": "100",
               "severity": "warning", "enabled": "y", "csrf_token": csrf(client, f"/devices/{did}")}
    payload.update(data)
    return client.post(f"/devices/{did}/thresholds", data=payload)


def test_threshold_crud(app, admin_client):
    did = make_device(app)
    assert add_rule(admin_client, did).status_code == 302
    add_rule(admin_client, did)  # duplicate metric+severity ignored with a warning
    add_rule(admin_client, did, metric_name="packet_loss_percent", threshold_value="150")  # invalid %
    add_rule(admin_client, did, threshold_value="-1")  # negative
    with app.app_context():
        assert Threshold.query.count() == 1
        tid = Threshold.query.one().threshold_id
    token = csrf(admin_client, f"/devices/thresholds/{tid}/edit")
    r = admin_client.post(f"/devices/thresholds/{tid}/edit", data={
        "metric_name": "latency_ms", "comparison_operator": ">=", "threshold_value": "250", "severity": "critical",
        "enabled": "y", "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        t = db.session.get(Threshold, tid)
        assert (t.comparison_operator, t.threshold_value, t.severity) == (">=", 250, "critical")
    token = csrf(admin_client, f"/devices/{did}")
    assert admin_client.post(f"/devices/thresholds/{tid}/delete", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        assert Threshold.query.count() == 0


@pytest.mark.parametrize("op,value,expected", [(">", 101, True), (">", 100, False), (">=", 100, True),
                                               ("<", 99, True), ("<=", 100, True), ("<", 100, False)])
def test_threshold_comparison(op, value, expected):
    t = Threshold(metric_name="latency_ms", comparison_operator=op, threshold_value=100)
    assert t.is_breached(value) is expected
    assert t.is_breached(None) is False


def test_database_constraint_blocks_invalid_rows(app):
    """NFR8 — constraints hold even if application validation were bypassed."""
    from sqlalchemy.exc import IntegrityError
    did = make_device(app)
    with app.app_context():
        db.session.add(MonitoringResult(device_id=did, reachable=True, packet_loss_percent=150))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        db.session.add(MonitoringResult(device_id=9999, reachable=True, checked_at=utcnow()))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        db.session.add(Device(device_name="Router", ip_address="1.1.1.1"))
        with pytest.raises(IntegrityError):
            db.session.commit()
