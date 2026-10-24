"""Shared fixtures. Each test gets its own SQLite file database (so threads and
restarts behave like the real application) and CSRF protection stays ON."""
import os
import re
import socket
import sys
import socketserver
import threading

import pytest

from netwatch import create_app
from netwatch.config import TestConfig, normalize_database_url
from netwatch.extensions import db
from netwatch.models import Device, Threshold, User

PASSWORD = "Passw0rd123"

# Linux/macOS report a refused TCP connection (closed port) instantly. Windows takes about
# 2 seconds to do so, so tests that rely on "refused = the host answered" need a longer timeout there.
REFUSAL_TIMEOUT_S = 5 if sys.platform.startswith("win") else 1


# Run the whole suite against a real PostgreSQL server instead of SQLite:
#   NETWATCH_TEST_DB_URL=postgresql://user:pass@localhost/netwatch_test python -m pytest --ignore=tests/test_ui.py
# (the database is emptied before every test, so use a throw-away one)
PG_URL = os.environ.get("NETWATCH_TEST_DB_URL", "").strip()


def make_config(db_path, **overrides):
    uri = normalize_database_url(PG_URL) if PG_URL else f"sqlite:///{db_path}"
    attrs = {"SQLALCHEMY_DATABASE_URI": uri, **overrides}
    return type("Cfg", (TestConfig,), attrs)


@pytest.fixture(autouse=True)
def _empty_postgres_between_tests():
    """Only active with NETWATCH_TEST_DB_URL: every test starts from empty tables."""
    if PG_URL:
        from sqlalchemy import create_engine
        eng = create_engine(normalize_database_url(PG_URL))
        db.metadata.drop_all(eng)
        db.metadata.create_all(eng)
        eng.dispose()
    yield


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture
def app(db_path):
    app = create_app(make_config(db_path))
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, url="/login"):
    html = client.get(url).get_data(as_text=True)
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html) or re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    assert m, f"no CSRF token on {url}"
    return m.group(1)


def make_user(app, username="admin", role="admin", email=None, password=PASSWORD):
    with app.app_context():
        u = User(username=username, email=email or f"{username}@example.com", role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        return u.user_id


def login(client, username="admin", password=PASSWORD):
    token = csrf(client, "/login")
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


@pytest.fixture
def admin_client(app, client):
    make_user(app)
    r = login(client)
    assert r.status_code == 302
    return client


@pytest.fixture
def viewer_client(app):
    make_user(app, "boss")  # an admin must exist
    make_user(app, "viewer", role="viewer")
    c = app.test_client()
    assert login(c, "viewer").status_code == 302
    return c


def make_device(app, name="Router", ip="127.0.0.1", thresholds=(), **kw):
    with app.app_context():
        d = Device(device_name=name, ip_address=ip, device_type=kw.pop("device_type", "router"), **kw)
        db.session.add(d)
        db.session.flush()
        for metric, op, val, sev in thresholds:
            db.session.add(Threshold(device_id=d.device_id, metric_name=metric, comparison_operator=op,
                                     threshold_value=val, severity=sev))
        db.session.commit()
        return d.device_id


# ----------------------------------------------------------- tiny SMTP sink
class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        self.wfile.write(b"220 sink ESMTP\r\n")
        data_mode, buf = False, []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            if data_mode:
                if line in (b".\r\n", b".\n"):
                    srv.messages.append(b"".join(buf).decode("utf-8", "replace"))
                    buf, data_mode = [], False
                    self.wfile.write(b"250 queued\r\n")
                else:
                    buf.append(line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                self.wfile.write(b"250-sink\r\n250 OK\r\n")
            elif cmd == b"DATA":
                data_mode = True
                self.wfile.write(b"354 go\r\n")
            elif cmd == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class SMTPSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _SMTPHandler)
        self.messages = []


@pytest.fixture
def smtp_sink():
    srv = SMTPSink()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def listening_port():
    """A real TCP listener on localhost (a 'reachable device')."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    stop = threading.Event()

    def accept():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = s.accept()
                c.close()
            except OSError:
                pass
    t = threading.Thread(target=accept, daemon=True)
    t.start()
    yield s.getsockname()[1]
    stop.set()
    s.close()
