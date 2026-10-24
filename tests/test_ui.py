"""User-interface tests in a real Chromium browser (Playwright).

Covers: login page, every navigation link, forms, filters, confirm dialog, charts
render from data, no JavaScript console errors, and no horizontal overflow on
desktop/tablet/mobile widths."""
import threading

import pytest

pw = pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from netwatch import create_app  # noqa: E402
from netwatch.extensions import db  # noqa: E402
from netwatch.models import Device, MonitoringResult  # noqa: E402
from netwatch.services import demo  # noqa: E402

from conftest import REFUSAL_TIMEOUT_S, make_config  # noqa: E402

PW = "UiTest2026"
pytestmark = pytest.mark.ui


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ui")
    app = create_app(make_config(tmp / "ui.db", MONITOR_METHOD="tcp", TCP_PROBE_PORTS=[1],
                                 PING_TIMEOUT_SECONDS=REFUSAL_TIMEOUT_S), start_scheduler=False)
    with app.app_context():
        demo.seed("admin", "admin@example.com", PW, hours=6)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield app, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"Chromium not available: {exc}")
        yield b
        b.close()


@pytest.fixture
def page(browser, live):
    ctx = browser.new_context(viewport={"width": 1366, "height": 860})
    pg = ctx.new_page()
    pg.errors = []  # JavaScript errors and server errors (5xx). Intentional 4xx validation replies are allowed.
    pg.on("console", lambda m: pg.errors.append(m.text)
          if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("response", lambda r: pg.errors.append(f"{r.status} {r.url}") if r.status >= 500 else None)
    yield pg
    ctx.close()


def sign_in(pg, base, user="admin"):
    pg.goto(base + "/login")
    pg.fill("#username", user)
    pg.fill("#password", PW)
    pg.click("button[type=submit]")
    pg.wait_for_url(base + "/")


def test_login_page_and_bad_password(page, live):
    _app, base = live
    page.goto(base + "/")
    assert page.url.startswith(base + "/login")
    page.fill("#username", "admin")
    page.fill("#password", "wrong-password1")
    page.click("button[type=submit]")
    assert page.locator(".alert-danger").inner_text().strip() == "Invalid username or password."
    # labels are attached to inputs (accessibility)
    assert page.get_by_label("Username").count() == 1 and page.get_by_label("Password").count() == 1


def test_every_nav_link_opens_correct_page(page, live):
    _app, base = live
    sign_in(page, base)
    expected = {"Dashboard": "Network overview", "Devices": "Devices", "Alerts": "Alerts",
                "History": "Monitoring history", "Reports": "Performance report", "Users": "User accounts",
                "Audit log": "Audit log", "Settings": "Settings"}
    for link, heading in expected.items():
        page.locator(".nw-nav a", has_text=link).first.click()
        page.wait_for_load_state("networkidle")
        assert page.locator("main h1").first.inner_text().strip().startswith(heading), link
    assert page.errors == []


def test_dashboard_renders_live_data_and_chart(page, live):
    _app, base = live
    sign_in(page, base)
    page.wait_for_function("document.getElementById('dash-updated').textContent.startsWith('Updated')")
    assert page.locator(".dev-tile").count() == 9
    assert page.locator(".sim-badge").count() >= 6
    assert not page.locator("#fleet-chart-box").evaluate("e => e.classList.contains('is-empty')")
    n = page.evaluate("Chart.getChart('fleet-chart').data.datasets.length")
    assert n >= 1
    page.click("#dash-refresh")
    page.wait_for_function("document.getElementById('dash-updated').textContent.startsWith('Updated')")
    assert page.errors == []


def test_register_check_and_delete_device_through_ui(page, live):
    app, base = live
    sign_in(page, base)
    page.goto(base + "/devices/new")
    page.fill("#polling_interval", "")
    page.click("main button[type=submit]")  # invalid submit -> validation messages
    assert page.locator(".invalid-feedback").count() >= 1
    page.fill("#device_name", "UI Loopback")
    page.fill("#ip_address", "127.0.0.1")
    page.select_option("#device_type", "server")
    page.fill("#polling_interval", "30")
    page.click("main button[type=submit]")
    page.wait_for_url("**/devices/*")
    assert "registered" in page.locator(".toast-zone").inner_text()
    page.click("button:has-text('Check now')")
    page.wait_for_load_state("networkidle")
    assert "Reachable via TCP" in page.locator(".toast-zone").inner_text()
    with app.app_context():
        d = Device.query.filter_by(device_name="UI Loopback").one()
        assert MonitoringResult.query.filter_by(device_id=d.device_id).count() == 1
    # chart range buttons load real data
    page.click("#range-seg button[data-range='1h']")
    page.wait_for_function("document.getElementById('chart-note').textContent.includes('1 stored result')")
    # delete via the confirm dialog: cancel first, then confirm
    page.click("main .page-head form[action$='/delete'] button")
    page.locator("#confirmModal").wait_for(state="visible")
    page.click("#confirmModal button:has-text('Cancel')")
    page.locator("#confirmModal").wait_for(state="hidden")
    with app.app_context():
        assert Device.query.filter_by(device_name="UI Loopback").count() == 1
    page.click("main .page-head form[action$='/delete'] button")
    page.click("#confirmGo")
    page.wait_for_url(base + "/devices/")
    with app.app_context():
        assert Device.query.filter_by(device_name="UI Loopback").count() == 0
    assert page.errors == []


def test_filters_change_results(page, live):
    _app, base = live
    sign_in(page, base)
    page.goto(base + "/devices/")
    all_rows = page.locator("tbody tr").count()
    page.select_option("#f-src", "simulated")  # auto-submits
    page.wait_for_url("**source=simulated**")
    assert page.locator("tbody tr").count() == 6 < all_rows
    page.fill("#f-q", "printer")
    page.click("button:has-text('Apply')")
    page.wait_for_url("**q=printer**")
    assert page.locator("tbody tr").count() == 1
    page.goto(base + "/alerts/?status=all")
    total = page.locator("tbody tr").count()
    page.select_option("#a-sev", "critical")
    page.wait_for_url("**severity=critical**")
    assert 0 < page.locator("tbody tr").count() <= total
    assert all("critical" in t.lower() for t in page.locator("tbody tr td:first-child").all_inner_texts())


def test_acknowledge_alert_through_ui(page, live):
    app, base = live
    from netwatch.models import Alert
    with app.app_context():
        d = Device.query.filter_by(device_name="Core Switch (demo)").one()
        a = Alert(device_id=d.device_id, alert_type="device_down", severity="critical", message="UI test alert")
        db.session.add(a)
        db.session.commit()
        aid = a.alert_id
    sign_in(page, base)
    page.goto(base + "/alerts/?status=open&q=UI+test")
    page.locator("button:has-text('Acknowledge')").first.click()
    page.wait_for_load_state("networkidle")
    assert "acknowledged" in page.locator(".toast-zone").inner_text()
    with app.app_context():
        assert db.session.get(Alert, aid).status == "acknowledged"


def test_exports_download(page, live):
    _app, base = live
    sign_in(page, base)
    page.goto(base + "/reports/")
    with page.expect_download() as d:
        page.click("a:has-text('Download PDF')")
    assert d.value.suggested_filename.endswith(".pdf")
    page.goto(base + "/history/")
    with page.expect_download() as d:
        page.click("a:has-text('Export CSV')")
    assert d.value.suggested_filename.endswith(".csv")


@pytest.mark.parametrize("width,height", [(1440, 900), (820, 1180), (390, 844)])
def test_responsive_layout_no_horizontal_overflow(browser, live, width, height):
    _app, base = live
    ctx = browser.new_context(viewport={"width": width, "height": height})
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    sign_in(pg, base)
    for url in ["/", "/devices/", "/devices/1", "/alerts/?status=all", "/history/", "/reports/", "/users/",
                "/settings/", "/settings/audit", "/devices/new", "/profile"]:
        pg.goto(base + url)
        pg.wait_for_load_state("networkidle")
        overflow = pg.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        assert overflow <= 0, f"{url} overflows by {overflow}px at {width}px"
        broken_icons = pg.evaluate("[...document.querySelectorAll('.bi')].filter(i => "
                                   "getComputedStyle(i, '::before').content === 'none').length")
        assert broken_icons == 0, url
    if width < 992:  # mobile navigation opens and closes
        pg.click("#sidebar-toggle")
        assert pg.locator("#sidebar").evaluate("e => e.classList.contains('show')")
        pg.keyboard.press("Escape")
        assert not pg.locator("#sidebar").evaluate("e => e.classList.contains('show')")
    assert errors == []
    ctx.close()


def test_viewer_sees_no_admin_controls(browser, live):
    _app, base = live
    ctx = browser.new_context()
    pg = ctx.new_page()
    sign_in(pg, base, "viewer")
    assert pg.locator(".nw-nav a", has_text="Settings").count() == 0
    pg.goto(base + "/devices/")
    assert pg.locator("a:has-text('Register device')").count() == 0
    assert pg.locator("form[action$='/delete']").count() == 0
    ctx.close()


def test_keyboard_navigation_reaches_main_controls(page, live):
    _app, base = live
    page.goto(base + "/login")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.id") == "username"
    page.keyboard.type("admin")
    page.keyboard.press("Tab")
    page.keyboard.type(PW)
    page.keyboard.press("Enter")
    page.wait_for_url(base + "/")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.classList.contains('skip-link')")
