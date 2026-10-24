"""FR1/FR2/NFR1 — authentication, authorisation, account management."""
import pytest

from netwatch.extensions import db
from netwatch.models import AuditLog, User

from conftest import PASSWORD, csrf, login, make_user

PROTECTED = ["/", "/devices/", "/devices/new", "/alerts/", "/history/", "/history/export.csv", "/reports/",
             "/reports/export.csv", "/reports/export.pdf", "/users/", "/settings/", "/settings/audit", "/profile",
             "/api/dashboard", "/api/devices/1/series"]
ADMIN_ONLY = ["/devices/new", "/users/", "/users/new", "/settings/", "/settings/audit"]


def test_first_run_redirects_to_setup_and_creates_admin(app, client):
    assert client.get("/login").headers["Location"].endswith("/setup")
    token = csrf(client, "/setup")
    r = client.post("/setup", data={"username": "chief", "email": "chief@example.com", "password": PASSWORD,
                                    "confirm": PASSWORD, "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        u = User.query.one()
        assert u.role == "admin" and u.password_hash != PASSWORD and u.check_password(PASSWORD)
    # setup page is closed once a user exists
    assert client.get("/setup").status_code == 302


def test_setup_rejects_weak_password(client):
    token = csrf(client, "/setup")
    r = client.post("/setup", data={"username": "chief", "email": "chief@example.com", "password": "short",
                                    "confirm": "short", "csrf_token": token})
    assert r.status_code == 200 and b"at least 8 characters" in r.data


@pytest.mark.parametrize("url", PROTECTED)
def test_protected_pages_require_login(app, client, url):
    make_user(app)
    r = client.get(url)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_success_and_logout(app, client):
    make_user(app)
    r = login(client)
    assert r.status_code == 302
    assert client.get("/").status_code == 200
    # logout must be POST with CSRF
    assert client.get("/logout").status_code == 405
    token = csrf(client, "/profile")
    assert client.post("/logout", data={"csrf_token": token}).status_code == 302
    assert client.get("/").status_code == 302


def test_invalid_credentials_rejected_with_generic_message(app, client):
    make_user(app)
    r = login(client, password="wrongpass1")
    assert r.status_code == 401 and b"Invalid username or password" in r.data
    r = login(client, username="nobody")
    assert r.status_code == 401 and b"Invalid username or password" in r.data
    with app.app_context():
        assert AuditLog.query.filter_by(action="login_failed").count() == 2


def test_account_lockout_after_repeated_failures(app, client):
    make_user(app)
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, password="wrongpass1")
    r = login(client)  # correct password, but locked
    assert r.status_code == 429


def test_deactivated_account_cannot_login(app, client):
    uid = make_user(app)
    with app.app_context():
        db.session.get(User, uid).is_active_account = False
        db.session.commit()
    assert login(client).status_code == 403


def test_open_redirect_blocked(app, client):
    make_user(app)
    token = csrf(client, "/login")
    r = client.post("/login?next=https://evil.example.com/", data={"username": "admin", "password": PASSWORD,
                                                                  "csrf_token": token})
    assert r.headers["Location"] == "/"


def test_post_without_csrf_token_is_rejected(admin_client):
    r = admin_client.post("/devices/new", data={"device_name": "X", "ip_address": "10.0.0.1",
                                                "device_type": "router", "polling_interval": 60})
    assert r.status_code == 302  # CSRF handler redirects with an error flash
    assert b"form session expired" in admin_client.get("/devices/").data.lower()
    with admin_client.application.app_context():
        from netwatch.models import Device
        assert Device.query.count() == 0


@pytest.mark.parametrize("url", ADMIN_ONLY)
def test_viewer_cannot_open_admin_pages(viewer_client, url):
    assert viewer_client.get(url).status_code == 403


def test_viewer_can_read_dashboard(viewer_client):
    assert viewer_client.get("/").status_code == 200
    assert viewer_client.get("/devices/").status_code == 200


def test_admin_creates_edits_and_deletes_user(app, admin_client):
    token = csrf(admin_client, "/users/new")
    r = admin_client.post("/users/new", data={"username": "ops", "email": "ops@example.com", "role": "viewer",
                                              "password": PASSWORD, "is_active_account": "y", "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        uid = User.query.filter_by(username="ops").one().user_id
    # duplicate username rejected
    token = csrf(admin_client, "/users/new")
    r = admin_client.post("/users/new", data={"username": "OPS", "email": "x@example.com", "role": "viewer",
                                              "password": PASSWORD, "csrf_token": token})
    assert r.status_code == 400 and b"taken" in r.data
    token = csrf(admin_client, f"/users/{uid}/edit")
    r = admin_client.post(f"/users/{uid}/edit", data={"username": "ops", "email": "ops2@example.com", "role": "admin",
                                                      "is_active_account": "y", "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        assert db.session.get(User, uid).email == "ops2@example.com"
    token = csrf(admin_client, "/users/")
    assert admin_client.post(f"/users/{uid}/delete", data={"csrf_token": token}).status_code == 302
    with app.app_context():
        assert db.session.get(User, uid) is None


def test_cannot_delete_self_or_demote_last_admin(app, admin_client):
    with app.app_context():
        me = User.query.filter_by(username="admin").one().user_id
    token = csrf(admin_client, "/users/")
    admin_client.post(f"/users/{me}/delete", data={"csrf_token": token})
    token = csrf(admin_client, f"/users/{me}/edit")
    r = admin_client.post(f"/users/{me}/edit", data={"username": "admin", "email": "admin@example.com",
                                                     "role": "viewer", "is_active_account": "y", "csrf_token": token})
    assert r.status_code == 400
    with app.app_context():
        u = db.session.get(User, me)
        assert u is not None and u.role == "admin"


def test_profile_password_change_requires_current_password(app, admin_client):
    token = csrf(admin_client, "/profile")
    r = admin_client.post("/profile", data={"email": "admin@example.com", "current_password": "nope",
                                            "new_password": "NewPass999", "confirm": "NewPass999", "csrf_token": token})
    assert r.status_code == 400
    token = csrf(admin_client, "/profile")
    r = admin_client.post("/profile", data={"email": "admin@example.com", "current_password": PASSWORD,
                                            "new_password": "NewPass999", "confirm": "NewPass999", "csrf_token": token})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.filter_by(username="admin").one().check_password("NewPass999")
