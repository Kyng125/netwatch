#!/usr/bin/env python3
"""Netwatch local verification — collects the evidence that cannot be produced in a cloud sandbox.

Run this on the laptop that will be used for the defence (inside the project's virtual
environment, from anywhere):

    python tools/verify_local.py --target 192.168.1.1 --email-to you@gmail.com

What it does
  1. TESTS    runs the whole pytest suite, including the 12 browser tests and the real-`ping`
              test that are skipped in the sandbox.  (--install-browser fetches Chromium.)
  2. DEVICE   checks a REAL device (your router) over ICMP, several rounds, and prints
              min / average / max latency and packet loss.  Then checks an address that
              cannot answer (192.0.2.1, reserved for documentation) to prove timeout handling.
  3. PIPELINE registers that device in a throw-away database, runs a real check through the
              application's own monitor, confirms the result was stored, and confirms a
              threshold rule raises exactly one alert.
  4. EMAIL    sends a real test message through the SMTP settings in your .env, using the
              application's own notifier.

Every step is optional and clearly reports PASS / FAIL / SKIPPED.  The results are also
written to docs/local_verification_<timestamp>.md so you can paste them into Chapter 4.

Nothing here touches your real Netwatch database (a temporary one is used) and no
passwords or secrets are printed or written to the evidence file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

UNREACHABLE_TEST_ADDRESS = "192.0.2.1"  # RFC 5737 TEST-NET-1: never routed, so it must time out

results: list[tuple[str, str, str]] = []  # (status, step, detail)


def record(status, step, detail=""):
    results.append((status, step, detail))
    print(f"  [{status:<7}] {step}" + (f" - {detail}" if detail else ""))


def heading(text):
    print(f"\n=== {text} " + "=" * max(3, 66 - len(text)))


def mask_email(addr):
    name, _, domain = addr.partition("@")
    return (name[:1] + "***@" + domain) if domain else "***"


# --------------------------------------------------------------------------- 1. tests
def run_tests(install_browser):
    heading("1. Automated test suite (backend + browser)")
    junit = Path(tempfile.mkdtemp(prefix="nw_verify_")) / "junit.xml"
    cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rs", f"--junitxml={junit}"]

    def run():
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)

    proc = run()
    if _browser_missing(proc.stdout + proc.stderr) and install_browser:
        print("  Chromium is missing - installing it (one-time download)...")
        inst = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], cwd=ROOT)
        if inst.returncode == 0:
            proc = run()
        else:
            record("FAIL", "Install Chromium for browser tests", "playwright install failed")
    try:
        suite = ET.parse(junit).getroot()
        suite = suite if suite.tag == "testsuite" else suite.find("testsuite")
        total, failed = int(suite.get("tests")), int(suite.get("failures")) + int(suite.get("errors"))
        skipped = int(suite.get("skipped"))
    except Exception:
        print((proc.stdout + proc.stderr)[-1500:])
        record("FAIL", "Run pytest", "could not read the test results (see output above)")
        return
    passed = total - failed - skipped
    detail = f"{passed} passed, {failed} failed, {skipped} skipped of {total}"
    if failed:
        record("FAIL", "Automated tests", detail)
        print("  Failed tests:")
        for tc in suite.iter("testcase"):
            bad = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            if bad is None:
                continue
            name = f"{tc.get('classname', '').replace('tests.', '')}::{tc.get('name')}"
            msg = " ".join((bad.get("message") or "").split())[:240]
            print(f"    - {name}\n        {msg}")
            record("FAIL", f"  test: {name}", msg)
        print("  (full details: python -m pytest -p no:cacheprovider -q --tb=short -rf)")
    elif skipped:
        reasons = [ln.strip() for ln in proc.stdout.splitlines() if ln.startswith("SKIPPED")]
        for ln in reasons[:3]:
            print("    " + ln[:150])
        hint = " - run again with --install-browser" if _browser_missing(proc.stdout) else ""
        record("PARTIAL", "Automated tests", detail + hint)
    else:
        record("PASS", "Automated tests", detail)


def _browser_missing(text):
    return "Chromium not available" in text or "Executable doesn't exist" in text


# --------------------------------------------------------------------------- 2. real device
def parse_gateway(system, output):
    """Pull the default-gateway IPv4 address out of ipconfig / `ip route` / `route` output."""
    import re
    ipv4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
    if system == "Windows":
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "gateway" in line.lower():
                for cand in lines[i:i + 3]:  # the IPv4 may sit on a following line
                    m = re.search(ipv4, cand)
                    if m and m.group(1) != "0.0.0.0":
                        return m.group(1)
        return None
    m = re.search(r"default via " + ipv4, output) or re.search(r"gateway:\s*" + ipv4, output)
    return m.group(1) if m else None


def default_gateway():
    system = platform.system()
    cmd = {"Windows": ["ipconfig"], "Linux": ["ip", "route", "show", "default"],
           "Darwin": ["route", "-n", "get", "default"]}.get(system)
    if not cmd or not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_gateway(system, out)


def check_device_over_network(target, method, rounds):
    heading(f"2. Real device check: {target}")
    from netwatch.services import collector
    try:
        host = collector.validate_host(target)
    except ValueError as exc:
        record("FAIL", "Target address", str(exc))
        return
    ping = shutil.which("ping")
    print(f"  ping command: {ping or 'NOT FOUND'}   method requested: {method}   rounds: {rounds} x 4 probes")
    lat, loss, methods, errors, last_raw = [], [], set(), set(), ""
    for i in range(rounds):
        r = collector.probe(host, method=method, count=4, timeout_s=2.0)
        last_raw = (r.raw or {}).get("output", last_raw)
        methods.add(r.method)
        if r.error:
            errors.add(r.error)
        if r.reachable and r.latency_ms is not None:
            lat.append(r.latency_ms)
        if r.packet_loss_percent is not None:
            loss.append(r.packet_loss_percent)
        print(f"    round {i + 1}: reachable={r.reachable} latency={r.latency_ms} ms loss={r.packet_loss_percent}% via {r.method}")
        if i < rounds - 1:
            time.sleep(1)
    if not lat:
        record("FAIL", f"Reachability of {target}", "; ".join(sorted(errors)) or "no reply in any round")
        if last_raw:
            print("  What the operating system's ping said:")
            for ln in [x for x in last_raw.strip().splitlines() if x.strip()][-6:]:
                print("    | " + ln.strip()[:120])
        gw = default_gateway()
        if gw and gw != host:
            print(f"  Hint: your computer's default gateway is {gw}, not {host}. "
                  f"Try:  python tools/verify_local.py --target {gw}")
        print("  Hint: also try `ping " + host + "` yourself. If that works but this fails, tell me; if it fails "
              "too, the address is wrong, you are on a different network, or the router ignores ping.")
    else:
        summary = (f"latency min/avg/max = {min(lat):.2f}/{sum(lat) / len(lat):.2f}/{max(lat):.2f} ms, "
                   f"mean loss {sum(loss) / len(loss):.1f}% , method {'/'.join(sorted(methods))}")
        if method == "icmp" and "icmp" not in methods:
            record("FAIL", f"ICMP check of {target}", "ICMP not available on this computer")
        else:
            record("PASS", f"Reachable device {target}", summary)
        if host not in ("127.0.0.1", "::1") and max(lat) < 0.05:
            record("WARNING", "Latency looks implausibly low", "below 0.05 ms for a non-loopback device")

    start = time.perf_counter()
    r = collector.probe(UNREACHABLE_TEST_ADDRESS, method=method, count=2, timeout_s=1.0)
    took = time.perf_counter() - start
    if (r.error or "").startswith("ICMP unavailable"):
        record("SKIPPED", "Unreachable-address test", "ICMP is not available on this computer, so nothing was tested")
    elif r.reachable:
        record("WARNING", "Unreachable-address test",
               f"{UNREACHABLE_TEST_ADDRESS} answered (a proxy or captive network may be intercepting traffic)")
    else:
        record("PASS", "Unreachable device times out cleanly", f"reported down after {took:.1f}s: {r.error}")


# --------------------------------------------------------------------------- 3. pipeline
def _temp_app():
    """The real application, but on a throw-away database with the scheduler off."""
    from netwatch import create_app
    from netwatch.config import Config
    tmp = Path(tempfile.mkdtemp(prefix="nw_verify_db_"))
    cfg = type("VerifyCfg", (Config,), {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp / 'verify.db'}",
                                        "SCHEDULER_ENABLED": False, "LOG_FILE": ""})
    return create_app(cfg, start_scheduler=False), tmp


def check_pipeline(target, method):
    heading("3. Application pipeline with the real device (temporary database)")
    from netwatch.config import Config
    from netwatch.extensions import db
    from netwatch.models import Alert, Device, MonitoringResult, Threshold
    from netwatch.services import monitor
    app, tmp = _temp_app()
    try:
        app.config["MONITOR_METHOD"] = method
        with app.app_context():
            d = Device(device_name="Verification device", ip_address=target, device_type="router")
            db.session.add(d)
            db.session.flush()
            # A deliberately impossible rule, so a REAL latency reading must breach it.
            db.session.add(Threshold(device_id=d.device_id, metric_name="latency_ms", comparison_operator=">",
                                     threshold_value=0.0001, severity="warning"))
            db.session.commit()
            did = d.device_id
            first = monitor.check_device(did)
            if first is None:
                record("FAIL", "Run a check through the monitor", "check did not complete")
                return
            stored = MonitoringResult.query.filter_by(device_id=did).count()
            record("PASS" if stored == 1 else "FAIL", "Result stored in the database",
                   f"{stored} row, reachable={first.reachable}, latency={first.latency_ms} ms, "
                   f"loss={first.packet_loss_percent}%, method={first.method}, uptime={first.uptime_percent}%")
            if first.reachable and first.latency_ms:
                monitor.check_device(did)
                n = Alert.query.filter_by(device_id=did, alert_type="threshold").count()
                record("PASS" if n == 1 else "FAIL", "Threshold breach raises exactly one alert",
                       f"{n} alert after 2 breaching checks")
            else:
                record("SKIPPED", "Threshold alert test", "device was not reachable, so no latency to breach")
            db.session.remove()
            db.engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- 4. email
def check_email(to_addr):
    heading("4. Email alert delivery (real SMTP)")
    from netwatch.services import notifier
    app, tmp = _temp_app()
    try:
        with app.app_context():
            if not notifier.smtp_configured():
                record("FAIL", "SMTP settings", "MAIL_SERVER / MAIL_FROM not set in .env (see README section 2)")
                return
            cfg = app.config
            print(f"  server={cfg['MAIL_SERVER']}:{cfg['MAIL_PORT']}  tls={cfg['MAIL_USE_TLS']}  "
                  f"from={mask_email(cfg['MAIL_FROM'])}  to={mask_email(to_addr)}")
            status = notifier.send_email(
                "[Netwatch] Verification test email",
                "This message was sent by tools/verify_local.py to confirm that Netwatch email alerts work.\n",
                to=[to_addr])
            from netwatch.extensions import db
            db.session.remove()
            db.engine.dispose()
        if status == "sent":
            record("PASS", "SMTP accepted the message", f"to {mask_email(to_addr)} - now confirm it arrived (check spam)")
        else:
            record("FAIL", "Send test email", f"status '{status}' (see instance/netwatch.log for the technical reason)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- report
def write_evidence(args):
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = ROOT / "docs" / f"local_verification_{stamp}.md"
    lines = [f"# Netwatch local verification - {dt.datetime.now():%d %b %Y %H:%M}", "",
             f"Computer: {platform.system()} {platform.release()}, Python {platform.python_version()}",
             f"Real device tested: {args.target or 'none'}  |  method: {args.method}", "",
             "| Result | Step | Detail |", "|---|---|---|"]
    lines += [f"| {s} | {step} | {detail.replace('|', '/')} |" for s, step, detail in results]
    lines += ["", "PARTIAL / SKIPPED / WARNING rows mean the item is NOT yet verified."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


APP_MODULES = [("flask", "Flask"), ("flask_sqlalchemy", "Flask-SQLAlchemy"), ("sqlalchemy", "SQLAlchemy"),
               ("flask_login", "Flask-Login"), ("flask_wtf", "Flask-WTF"), ("dotenv", "python-dotenv"),
               ("apscheduler", "APScheduler"), ("cryptography", "cryptography"), ("reportlab", "reportlab")]
TEST_MODULES = [("pytest", "pytest"), ("playwright", "playwright"), ("pytest_playwright", "pytest-playwright")]


def preflight(need_tests):
    """Stop with plain instructions (not a traceback) if the packages are not installed."""
    import importlib.util
    missing_app = [pkg for mod, pkg in APP_MODULES if importlib.util.find_spec(mod) is None]
    missing_test = [pkg for mod, pkg in TEST_MODULES if importlib.util.find_spec(mod) is None] if need_tests else []
    if not (missing_app or missing_test):
        return
    print("Netwatch's Python packages are not installed for this Python:")
    print(f"  Python in use: {sys.executable}  ({platform.python_version()})")
    for pkg in missing_app + missing_test:
        print(f"  - missing: {pkg}")
    print("\nFix (run from the project folder, in the same window):")
    if os.environ.get("VIRTUAL_ENV") is None:
        print("  python -m venv venv")
        print("  venv\\Scripts\\activate            (macOS/Linux: source venv/bin/activate)")
    print(f"  python -m pip install -r {'requirements-dev.txt' if need_tests else 'requirements.txt'}")
    print("  python tools/verify_local.py ...      (run the script again)")
    print("\nIf pip says 'No matching distribution found ... (from versions: none)', pip could not reach the")
    print("package index (network, VPN, proxy or antivirus). Retry with:")
    print("  python -m pip install --upgrade pip")
    print("  python -m pip install --default-timeout 120 --retries 10 -r requirements-dev.txt")
    print("or switch network (e.g. a phone hotspot) and try again. Use --skip-tests to avoid the test packages.")
    sys.exit(2)


def main():
    p = argparse.ArgumentParser(description="Collect real-world verification evidence for Netwatch.")
    p.add_argument("--target", help="IP or hostname of a REAL device you are authorised to monitor (e.g. your router); "
                                    "use 'gateway' to auto-detect your router's address")
    p.add_argument("--method", choices=["icmp", "tcp", "auto"], default="icmp",
                   help="probe method for steps 2-3 (default icmp, the method named in the report)")
    p.add_argument("--rounds", type=int, default=5, help="number of check rounds against the target (default 5)")
    p.add_argument("--email-to", help="address to receive a real test email")
    p.add_argument("--skip-tests", action="store_true", help="do not run the pytest suite")
    p.add_argument("--install-browser", action="store_true", help="download Chromium if the browser tests need it")
    args = p.parse_args()

    preflight(need_tests=not args.skip_tests)
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")

    print("Netwatch local verification")
    print("Only monitor devices you are authorised to monitor.")
    if args.target is None and sys.stdin.isatty():
        args.target = input("Router/device IP to check, or 'gateway' to detect it (Enter to skip): ").strip() or None
    if args.email_to is None and sys.stdin.isatty():
        args.email_to = input("Email address for the test message (Enter to skip): ").strip() or None

    if args.skip_tests:
        record("SKIPPED", "Automated tests", "--skip-tests")
    else:
        run_tests(args.install_browser)
    if args.target and args.target.lower() == "gateway":
        gw = default_gateway()
        if gw:
            print(f"\nDetected your computer's default gateway (usually the router): {gw}")
        else:
            record("FAIL", "Detect default gateway", "not found - pass your router's IP with --target instead")
        args.target = gw
    if args.target:
        check_device_over_network(args.target, args.method, max(1, args.rounds))
        check_pipeline(args.target, args.method)
    else:
        record("SKIPPED", "Real device checks", "no --target given")
    if args.email_to:
        check_email(args.email_to)
    else:
        record("SKIPPED", "Email test", "no --email-to given")

    heading("Summary")
    for s, step, detail in results:
        print(f"  [{s:<7}] {step}")
    out = write_evidence(args)
    print(f"\nEvidence saved to {out}")
    bad = any(s == "FAIL" for s, *_ in results)
    unverified = any(s in ("PARTIAL", "SKIPPED", "WARNING") for s, *_ in results)
    print("RESULT:", "FAILURES FOUND" if bad else ("OK, but some items were not verified" if unverified else "ALL CHECKS PASSED"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
