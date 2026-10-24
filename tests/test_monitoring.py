"""FR4/FR6/FR8/FR9/NFR2 — scheduled checks, storage, uptime, alert lifecycle and email."""
import threading
import time
from datetime import timedelta

import pytest

from netwatch import create_app
from netwatch.extensions import db
from netwatch.models import Alert, Device, MonitoringResult, utcnow
from netwatch.services import collector, monitor, scheduler, stats
from netwatch.services import settings as app_settings
from netwatch.services.collector import ProbeResult

from conftest import csrf, make_config, make_device

LAT_RULES = [("latency_ms", ">", 100, "warning"), ("latency_ms", ">", 500, "critical"),
             ("packet_loss_percent", ">", 25, "warning")]


class FakeNet:
    """Scripted probe outcomes per device address."""
    def __init__(self, monkeypatch):
        self.script = {}
        monkeypatch.setattr(collector, "probe", self.probe)

    def set(self, host, *results):
        self.script[host] = list(results)

    def probe(self, host, **kw):
        q = self.script.get(host)
        if not q:
            raise AssertionError(f"unexpected probe of {host}")
        return q.pop(0) if len(q) > 1 else q[0]


def up(lat=5.0, loss=0.0):
    return ProbeResult(True, lat, loss, "icmp")


def down():
    return ProbeResult(False, None, 100.0, "icmp", "No echo replies received")


@pytest.fixture
def net(monkeypatch):
    return FakeNet(monkeypatch)


def run(app, did, now=None):
    with app.app_context():
        r = monitor.check_device(did, now=now)
        return None if r is None else (r.reachable, r.latency_ms, r.packet_loss_percent, r.uptime_percent)


def alerts(app, **f):
    with app.app_context():
        return [(a.alert_type, a.severity, a.status) for a in Alert.query.filter_by(**f).order_by(Alert.alert_id)]


# ------------------------------------------------------------ real probes, end to end
def test_real_check_of_reachable_endpoint_is_stored(app, listening_port):
    app.config["MONITOR_METHOD"] = "tcp"
    app.config["TCP_PROBE_PORTS"] = [listening_port]
    did = make_device(app, ip="127.0.0.1")
    reachable, lat, loss, uptime = run(app, did)
    assert reachable and lat is not None and loss == 0.0 and uptime == 100.0
    with app.app_context():
        d = db.session.get(Device, did)
        r = MonitoringResult.query.one()
        assert d.status == "up" and d.last_checked_at is not None and r.method == "tcp"


def test_real_check_of_unreachable_endpoint_times_out_safely(app):
    app.config["MONITOR_METHOD"] = "tcp"
    app.config["TCP_PROBE_PORTS"] = [22]
    app.config["PING_TIMEOUT_SECONDS"] = 1
    did = make_device(app, ip="203.0.113.9")  # TEST-NET-3, never a real host
    t = time.monotonic()
    reachable, lat, loss, _ = run(app, did)
    if reachable:
        pytest.skip("this network answers unroutable addresses (firewall/proxy RST)")
    assert not reachable and lat is None and loss == 100.0
    assert time.monotonic() - t < 5
    with app.app_context():
        assert MonitoringResult.query.one().error_message


# ------------------------------------------------------------ device down / recovery
def test_device_marked_down_only_after_consecutive_failures_and_one_alert(app, net):
    did = make_device(app, ip="10.0.0.1")
    net.set("10.0.0.1", up())
    run(app, did)
    net.set("10.0.0.1", down())
    run(app, did)
    with app.app_context():
        assert db.session.get(Device, did).status == "up"  # 1 failure < threshold of 2
    assert alerts(app) == []
    run(app, did)
    run(app, did)
    run(app, did)
    with app.app_context():
        assert db.session.get(Device, did).status == "down"
    assert alerts(app) == [("device_down", "critical", "open")]  # exactly one record

    net.set("10.0.0.1", up())
    run(app, did)
    with app.app_context():
        assert db.session.get(Device, did).status == "up"
        a = Alert.query.one()
        assert a.status == "resolved" and a.resolved_at and a.resolved_by is None


def test_failure_threshold_setting_is_respected(app, net):
    with app.app_context():
        app_settings.set_value("failure_threshold", 1)
        db.session.commit()
    did = make_device(app, ip="10.0.0.1")
    net.set("10.0.0.1", down())
    run(app, did)
    assert alerts(app) == [("device_down", "critical", "open")]


# ------------------------------------------------------------ thresholds
def test_threshold_breach_creates_single_alert_and_auto_resolves(app, net):
    did = make_device(app, ip="10.0.0.2", thresholds=LAT_RULES)
    net.set("10.0.0.2", up(150))
    run(app, did)
    run(app, did)
    run(app, did)
    assert alerts(app) == [("threshold", "warning", "open")]
    net.set("10.0.0.2", up(650))  # now also critical
    run(app, did)
    assert sorted(alerts(app)) == [("threshold", "critical", "open"), ("threshold", "warning", "open")]
    net.set("10.0.0.2", up(20))
    run(app, did)
    assert {s for _t, _s, s in alerts(app)} == {"resolved"}
    with app.app_context():
        msg = Alert.query.filter_by(severity="critical").one().message
        assert "650" in msg and "> 500" in msg


def test_packet_loss_threshold(app, net):
    did = make_device(app, ip="10.0.0.3", thresholds=LAT_RULES)
    net.set("10.0.0.3", up(5, 50.0))
    run(app, did)
    with app.app_context():
        a = Alert.query.one()
        assert a.metric_name == "packet_loss_percent" and a.status == "open"


def test_thresholds_not_evaluated_while_unreachable(app, net):
    did = make_device(app, ip="10.0.0.4", thresholds=LAT_RULES)
    net.set("10.0.0.4", down())
    for _ in range(3):
        run(app, did)
    assert alerts(app) == [("device_down", "critical", "open")]


def test_disabled_threshold_is_ignored(app, net):
    did = make_device(app, ip="10.0.0.5", thresholds=LAT_RULES)
    with app.app_context():
        for t in db.session.get(Device, did).thresholds:
            t.enabled = False
        db.session.commit()
    net.set("10.0.0.5", up(999))
    run(app, did)
    assert alerts(app) == []


# ------------------------------------------------------------ uptime / calculations
def test_uptime_matches_stored_results(app, net):
    did = make_device(app, ip="10.0.0.6")
    t0 = utcnow() - timedelta(hours=2)
    pattern = [up(), up(), down(), up(), down(), up(), up(), up()]
    for i, p in enumerate(pattern):
        net.set("10.0.0.6", p)
        run(app, did, now=t0 + timedelta(minutes=i))
    with app.app_context():
        assert stats.uptime_percent(did, t0 - timedelta(minutes=1)) == round(6 / 8 * 100, 2)
        last = MonitoringResult.query.order_by(MonitoringResult.checked_at.desc()).first()
        assert last.uptime_percent == 75.0
        s = stats.device_summary(did, t0 - timedelta(minutes=1), utcnow())
        assert (s["checks"], s["successful"], s["failed"], s["uptime"]) == (8, 6, 2, 75.0)
        assert s["latency_min"] == s["latency_max"] == 5.0


# ------------------------------------------------------------ reliability (NFR2)
def test_one_failing_device_does_not_stop_others(app, monkeypatch):
    a = make_device(app, name="A", ip="10.0.1.1")
    b = make_device(app, name="B", ip="10.0.1.2")

    def flaky_probe(host, **kw):
        if host == "10.0.1.1":
            raise RuntimeError("driver crashed")
        return up()
    monkeypatch.setattr(collector, "probe", flaky_probe)
    scheduler.tick(app)
    with app.app_context():
        ra = MonitoringResult.query.filter_by(device_id=a).one()
        rb = MonitoringResult.query.filter_by(device_id=b).one()
        assert ra.reachable is False and "Collector error" in ra.error_message
        assert rb.reachable is True


def test_database_error_during_check_is_contained(app, net, monkeypatch):
    did = make_device(app, ip="10.0.0.7")
    net.set("10.0.0.7", up())
    from netwatch.services import alerting

    def boom(*a, **k):
        raise RuntimeError("db went away")
    monkeypatch.setattr(alerting, "evaluate", boom)
    assert run(app, did) is None  # no exception propagates
    with app.app_context():
        assert MonitoringResult.query.count() == 0  # rolled back, not half-written


# ------------------------------------------------------------ scheduler
def test_scheduler_checks_only_due_and_enabled_devices(app, net):
    due = make_device(app, name="Due", ip="10.0.2.1")
    fresh = make_device(app, name="Fresh", ip="10.0.2.2", last_checked_at=utcnow())
    off = make_device(app, name="Off", ip="10.0.2.3", enabled=False)
    net.set("10.0.2.1", up())
    scheduler.tick(app)
    with app.app_context():
        counts = {d: MonitoringResult.query.filter_by(device_id=d).count() for d in (due, fresh, off)}
    assert counts == {due: 1, fresh: 0, off: 0}
    scheduler.tick(app)  # immediately again: not yet due
    with app.app_context():
        assert MonitoringResult.query.filter_by(device_id=due).count() == 1


def test_same_device_is_never_checked_twice_concurrently(app, monkeypatch):
    did = make_device(app, ip="10.0.3.1")
    gate = threading.Event()

    def slow(host, **kw):
        gate.wait(2)
        return up()
    monkeypatch.setattr(collector, "probe", slow)
    out = []
    t = threading.Thread(target=lambda: out.append(run(app, did)))
    t.start()
    time.sleep(0.2)
    second = run(app, did)  # lock held by the first
    gate.set()
    t.join()
    assert second is None and out[0] is not None
    with app.app_context():
        assert MonitoringResult.query.count() == 1


def test_real_background_scheduler_runs_and_has_single_job(db_path, tmp_path, listening_port):
    cfg = make_config(db_path, SCHEDULER_ENABLED=True, SCHEDULER_TICK_SECONDS=1, MONITOR_METHOD="tcp",
                      TCP_PROBE_PORTS=[listening_port])
    app = create_app(cfg, start_scheduler=False)
    app.instance_path = str(tmp_path)
    did = make_device(app, ip="127.0.0.1", polling_interval=10)
    try:
        sched = scheduler.start(app)
        assert sched is not None
        # a second start (reloader / second worker) must not create another scheduler
        assert scheduler.start(app) is sched
        assert scheduler._acquire_process_lock(tmp_path / "scheduler.lock") is None
        st = scheduler.status()
        assert st["running"] and st["poll_jobs"] == 1
        deadline = time.time() + 10
        while time.time() < deadline:
            with app.app_context():
                n = MonitoringResult.query.filter_by(device_id=did).count()
            if n:
                break
            time.sleep(0.3)
        assert n >= 1, "scheduler did not store a result within 10 s"
    finally:
        scheduler.shutdown()


# ------------------------------------------------------------ alert handling via UI
def test_acknowledge_and_close_alert(app, admin_client):
    did = make_device(app)
    with app.app_context():
        a = Alert(device_id=did, alert_type="device_down", severity="critical", message="Device unreachable")
        db.session.add(a)
        db.session.commit()
        aid = a.alert_id
    token = csrf(admin_client, f"/alerts/{aid}")
    r = admin_client.post(f"/alerts/{aid}/acknowledge", data={"csrf_token": token, "note": "on it"})
    assert r.status_code == 302
    with app.app_context():
        a = db.session.get(Alert, aid)
        assert a.status == "acknowledged" and a.acknowledged_by and a.acknowledged_at
    admin_client.post(f"/alerts/{aid}/acknowledge", data={"csrf_token": token})  # no double-ack
    r = admin_client.post(f"/alerts/{aid}/resolve", data={"csrf_token": token, "note": "cable replaced"})
    assert r.status_code == 302
    with app.app_context():
        a = db.session.get(Alert, aid)
        assert a.status == "resolved" and a.resolution_note == "cable replaced"
    html = admin_client.get("/alerts/?status=resolved").get_data(as_text=True)
    assert "Device unreachable" in html
    assert "Device unreachable" not in admin_client.get("/alerts/?status=active").get_data(as_text=True)


def test_viewer_may_acknowledge_but_not_close(app, viewer_client):
    did = make_device(app)
    with app.app_context():
        a = Alert(device_id=did, alert_type="device_down", severity="critical", message="x")
        db.session.add(a)
        db.session.commit()
        aid = a.alert_id
    token = csrf(viewer_client, f"/alerts/{aid}")
    assert viewer_client.post(f"/alerts/{aid}/resolve", data={"csrf_token": token}).status_code == 403
    assert viewer_client.post(f"/alerts/{aid}/acknowledge", data={"csrf_token": token}).status_code == 302


def test_check_now_button_runs_a_real_check(app, admin_client, listening_port):
    app.config["MONITOR_METHOD"] = "tcp"
    app.config["TCP_PROBE_PORTS"] = [listening_port]
    did = make_device(app, ip="127.0.0.1")
    token = csrf(admin_client, f"/devices/{did}")
    r = admin_client.post(f"/devices/{did}/check", data={"csrf_token": token}, follow_redirects=True)
    assert b"Reachable via TCP" in r.data
    with app.app_context():
        assert MonitoringResult.query.count() == 1


# ------------------------------------------------------------ email (FR9)
def configure_smtp(app, sink):
    app.config.update(MAIL_SERVER="127.0.0.1", MAIL_PORT=sink.server_address[1], MAIL_USE_TLS=False,
                      MAIL_USE_SSL=False, MAIL_FROM="netwatch@example.com", MAIL_USERNAME="")


def test_email_sent_on_new_alert_suppressed_on_repeat_and_sent_on_recovery(app, net, smtp_sink):
    from conftest import make_user
    make_user(app, "ops", email="ops@example.com")
    configure_smtp(app, smtp_sink)
    did = make_device(app, ip="10.0.4.1")
    net.set("10.0.4.1", down())
    t0 = utcnow()
    for i in range(4):
        run(app, did, now=t0 + timedelta(minutes=i))
    assert len(smtp_sink.messages) == 1
    msg = smtp_sink.messages[0]
    assert "ALERT" in msg and "10.0.4.1" in msg and "ops@example.com" in msg
    with app.app_context():
        a = Alert.query.one()
        assert a.email_status == "sent" and a.notification_count == 1
    # reminder after the reminder interval (default 60 min)
    run(app, did, now=t0 + timedelta(minutes=65))
    assert len(smtp_sink.messages) == 2 and "REMINDER" in smtp_sink.messages[1]
    net.set("10.0.4.1", up())
    run(app, did, now=t0 + timedelta(minutes=66))
    assert len(smtp_sink.messages) == 3 and "RESOLVED" in smtp_sink.messages[2]


def test_acknowledged_alert_gets_no_reminders(app, net, smtp_sink):
    from conftest import make_user
    make_user(app, "ops")
    configure_smtp(app, smtp_sink)
    did = make_device(app, ip="10.0.4.2")
    net.set("10.0.4.2", down())
    t0 = utcnow()
    run(app, did, now=t0)
    run(app, did, now=t0 + timedelta(minutes=1))
    with app.app_context():
        Alert.query.one().status = "acknowledged"
        db.session.commit()
    run(app, did, now=t0 + timedelta(minutes=120))
    assert len(smtp_sink.messages) == 1


def test_email_failure_does_not_break_monitoring(app, net):
    from conftest import make_user
    make_user(app, "ops")
    app.config.update(MAIL_SERVER="127.0.0.1", MAIL_PORT=1, MAIL_FROM="x@example.com", MAIL_USE_TLS=False,
                      MAIL_TIMEOUT_SECONDS=1)
    did = make_device(app, ip="10.0.4.3")
    net.set("10.0.4.3", down())
    run(app, did)
    run(app, did)
    with app.app_context():
        a = Alert.query.one()
        assert a.status == "open" and a.email_status == "failed"
        assert MonitoringResult.query.count() == 2


def test_no_smtp_configured_keeps_in_app_alert(app, net):
    did = make_device(app, ip="10.0.4.4")
    net.set("10.0.4.4", down())
    run(app, did)
    run(app, did)
    with app.app_context():
        assert Alert.query.one().email_status == "not_configured"


def test_test_email_button(app, admin_client, smtp_sink):
    configure_smtp(app, smtp_sink)
    token = csrf(admin_client, "/settings/")
    r = admin_client.post("/settings/test-email", data={"csrf_token": token}, follow_redirects=True)
    assert b"Test email sent" in r.data and len(smtp_sink.messages) == 1


def test_email_message_flags_simulated_devices(app, net, smtp_sink):
    from conftest import make_user
    make_user(app, "ops")
    configure_smtp(app, smtp_sink)
    did = make_device(app, ip="10.0.4.5", is_simulated=True, sim_profile="flaky")
    with app.app_context():
        a = Alert(device_id=did, alert_type="device_down", severity="critical", message="x", opened_at=utcnow())
        db.session.add(a)
        db.session.commit()
        from netwatch.services import notifier
        from netwatch.utils import fmt_dt
        _s, body = notifier.alert_email(a, "new", fmt_dt)
        assert "SIMULATED" in body


def test_status_reports_running_when_another_process_owns_scheduler(tmp_path, monkeypatch):
    """Regression: gunicorn workers without the scheduler must not report 'stopped'."""
    lock_path = tmp_path / "scheduler.lock"
    owner = scheduler._acquire_process_lock(lock_path)  # stands in for the owning worker
    assert owner is not None
    monkeypatch.setitem(scheduler._state, "scheduler", None)
    monkeypatch.setitem(scheduler._state, "lock_path", lock_path)
    try:
        assert scheduler.status()["running"] is True
        assert scheduler.status()["in_this_process"] is False
    finally:
        owner.close()
    assert scheduler.status()["running"] is False  # nobody holds it any more
