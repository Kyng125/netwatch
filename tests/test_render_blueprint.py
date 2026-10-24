"""render.yaml stays consistent with the code it deploys (cannot call Render itself, so this checks the wiring)."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def blueprint():
    return yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))


def test_service_and_database_are_wired_together(blueprint):
    (db,) = blueprint["databases"]
    (svc,) = blueprint["services"]
    env = {e["key"]: e for e in svc["envVars"]}
    assert env["DATABASE_URL"]["fromDatabase"]["name"] == db["name"]
    assert env["DATABASE_URL"]["fromDatabase"]["property"] == "connectionString"
    assert db["region"] == svc["region"]  # the internal connection string only works inside one region
    assert svc["plan"] == "free" and db["plan"] == "free"


def test_start_and_build_commands_use_real_files(blueprint):
    (svc,) = blueprint["services"]
    assert (ROOT / svc["buildCommand"].split("-r ")[1]).is_file()
    start = svc["startCommand"]
    assert "manage.py init-db" in start and "seed-public --if-empty" in start and "--workers 1" in start
    assert "$PORT" in start  # Render tells the app which port to bind
    assert svc["healthCheckPath"] == "/healthz"
    assert "psycopg" in (ROOT / "requirements-cloud.txt").read_text()


def test_no_secret_values_are_written_in_the_file(blueprint):
    (svc,) = blueprint["services"]
    env = {e["key"]: e for e in svc["envVars"]}
    for key in ("ADMIN_PASSWORD", "VIEWER_PASSWORD"):
        assert env[key].get("sync") is False and "value" not in env[key]
    assert env["SECRET_KEY"].get("generateValue") is True and "value" not in env["SECRET_KEY"]
    assert env["MONITOR_METHOD"]["value"] == "tcp" and env["SESSION_COOKIE_SECURE"]["value"] == "true"


def test_python_version_is_pinned_to_the_tested_series():
    assert (ROOT / ".python-version").read_text().strip() == "3.13"
