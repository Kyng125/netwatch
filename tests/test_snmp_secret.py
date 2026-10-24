"""§3.12 — the SNMP community string is stored encrypted, never in plain text."""
from netwatch.extensions import db
from netwatch.models import Device
from netwatch.services import collector, monitor, secrets_box

from conftest import make_device
from test_devices import post_device


def _stored(app, device_id):
    with app.app_context():
        return db.session.get(Device, device_id).snmp_community


def test_community_saved_through_form_is_encrypted_at_rest(app, admin_client):
    r = post_device(admin_client, snmp_enabled="y", snmp_community="s3cret-community")
    assert r.status_code == 302
    with app.app_context():
        raw = Device.query.one().snmp_community
        assert raw.startswith("enc:v1:") and "s3cret-community" not in raw
        assert secrets_box.decrypt(raw) == "s3cret-community"


def test_blank_community_on_edit_keeps_stored_secret(app, admin_client):
    post_device(admin_client, snmp_enabled="y", snmp_community="keep-me")
    with app.app_context():
        did = Device.query.one().device_id
    before = _stored(app, did)
    r = post_device(admin_client, f"/devices/{did}/edit", snmp_enabled="y", snmp_community="")
    assert r.status_code == 302
    assert _stored(app, did) == before


def test_legacy_plaintext_is_readable_and_upgraded_on_next_save(app, admin_client):
    did = make_device(app, snmp_enabled=True, snmp_community="old-plain")
    with app.app_context():
        assert secrets_box.decrypt("old-plain") == "old-plain"
    r = post_device(admin_client, f"/devices/{did}/edit", device_name="Router", ip_address="127.0.0.1",
                    snmp_enabled="y", snmp_community="")
    assert r.status_code == 302
    stored = _stored(app, did)
    assert stored.startswith("enc:v1:") and "old-plain" not in stored


def test_probe_receives_the_decrypted_community(app, monkeypatch):
    with app.app_context():
        token = secrets_box.encrypt("probe-secret")
    did = make_device(app, snmp_enabled=True, snmp_community=token)
    seen = {}
    monkeypatch.setattr(collector, "probe", lambda *a, **k: collector.ProbeResult(True, 1.0, 0.0, "icmp"))

    def fake_snmp(host, community, timeout_s=2.0):
        seen["community"] = community
        return 10.0, 20.0, None
    monkeypatch.setattr(collector, "snmp_probe", fake_snmp)
    with app.app_context():
        res = monitor.run_probe(db.session.get(Device, did))
    assert seen["community"] == "probe-secret"
    assert (res.cpu_percent, res.memory_percent) == (10.0, 20.0)


def test_unreadable_secret_is_reported_and_never_replaced_by_public(app, monkeypatch):
    with app.app_context():
        token = secrets_box.encrypt("x")
    did = make_device(app, snmp_enabled=True, snmp_community=token[:-4] + "AAAA")  # corrupted token
    monkeypatch.setattr(collector, "probe", lambda *a, **k: collector.ProbeResult(True, 1.0, 0.0, "icmp"))
    called = []
    monkeypatch.setattr(collector, "snmp_probe", lambda *a, **k: called.append(a) or (1.0, 1.0, None))
    with app.app_context():
        res = monitor.run_probe(db.session.get(Device, did))
    assert not called
    assert "could not be read" in res.error
    assert res.reachable is True  # ICMP result is kept; only SNMP data is missing
