"""Cloud demonstration data: real public targets + clearly labelled simulated devices, safe to run on every start."""
import os
import subprocess
import sys
from pathlib import Path

from netwatch.models import Device, MonitoringResult, Threshold, User
from netwatch.services import demo

ROOT = Path(__file__).resolve().parent.parent


def test_seed_public_creates_real_and_simulated_devices(app):
    with app.app_context():
        out = demo.seed_public("AdminPass2026", "ViewerPass2026", hours=1)
        assert out["devices"] == len(demo.PUBLIC_DEVICES) + len(demo.SIM_DEVICES)
        real = Device.query.filter_by(is_simulated=False).all()
        sim = Device.query.filter_by(is_simulated=True).all()
        assert {d.ip_address for d in real} == {ip for _n, ip, *_ in demo.PUBLIC_DEVICES}
        assert len(sim) == len(demo.SIM_DEVICES)
        assert all(d.polling_interval == 120 and d.enabled for d in real)
        # real devices have no stored results until the collector measures them (nothing is faked)
        assert MonitoringResult.query.filter(MonitoringResult.device_id.in_([d.device_id for d in real])).count() == 0
        assert MonitoringResult.query.filter(MonitoringResult.method != "simulated").count() == 0
        # looser Internet latency rule on real targets, normal LAN rule on simulated ones
        assert Threshold.query.filter_by(device_id=real[0].device_id, metric_name="latency_ms",
                                         severity="warning").one().threshold_value == 300
        assert {u.username: u.role for u in User.query.all()} == {"admin": "admin", "viewer": "viewer"}
        assert User.query.filter_by(username="admin").one().check_password("AdminPass2026")
        assert User.query.filter_by(username="viewer").one().check_password("ViewerPass2026")


def test_seed_public_is_a_no_op_when_users_exist(app):
    with app.app_context():
        assert demo.seed_public("AdminPass2026", "ViewerPass2026", hours=1) is not None
        before = (User.query.count(), Device.query.count(), MonitoringResult.query.count())
        assert demo.seed_public("Other2026Pass", "Other2026Pass", hours=1) is None
        assert (User.query.count(), Device.query.count(), MonitoringResult.query.count()) == before
        assert User.query.filter_by(username="admin").one().check_password("AdminPass2026")


def _manage(tmp_path, **env_extra):
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp_path / 'cli.db'}", SECRET_KEY="test-secret",
               LOG_FILE=str(tmp_path / "cli.log"), SCHEDULER_ENABLED="false")
    env.pop("ADMIN_PASSWORD", None)
    env.pop("VIEWER_PASSWORD", None)
    env.update(env_extra)
    return subprocess.run([sys.executable, str(ROOT / "manage.py"), "seed-public", "--if-empty", "--hours", "1"],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)


def test_seed_public_command_as_run_on_render(tmp_path):
    missing = _manage(tmp_path)
    assert missing.returncode == 1 and "ADMIN_PASSWORD" in missing.stdout
    weak = _manage(tmp_path, ADMIN_PASSWORD="short", VIEWER_PASSWORD="ViewerPass2026")
    assert weak.returncode == 1 and "ADMIN_PASSWORD" in weak.stdout
    first = _manage(tmp_path, ADMIN_PASSWORD="AdminPass2026", VIEWER_PASSWORD="ViewerPass2026")
    assert first.returncode == 0 and "Public demo data loaded" in first.stdout
    assert "AdminPass2026" not in first.stdout + first.stderr  # passwords are never printed
    again = _manage(tmp_path, ADMIN_PASSWORD="AdminPass2026", VIEWER_PASSWORD="ViewerPass2026")
    assert again.returncode == 0 and "already has users" in again.stdout
