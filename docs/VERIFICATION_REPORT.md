# Netwatch — Final Verification Report

Date of verification: 16 October 2026. Environment: Linux container, Python 3.13.16,
Chromium (Playwright 1.56), SQLite. Every result below was produced by actually running
the code; nothing is estimated.

## 1. Project summary

A working Flask web application implementing the system specified in the seminar report:
Table 3.4 schema, Table 3.5 technology stack, the layered architecture of Figure 3.1, the
use cases of Figure 3.3, the data flow of Figure 3.4, the system flow of Figure 3.6, the alert
logic of §3.8.1 and the acceptance criteria of Table 3.6.

Report gap found: **Table 3.2 (Functional Requirements) is missing from the PDF** — §3.5.1 has a
heading but no table. A reconstructed table is in `REQUIREMENTS_CHECKLIST.md`; insert it
into the report.

## 2. Technology stack

Python 3 · Flask 3 · Flask-SQLAlchemy / SQLAlchemy 2 · Flask-Login · Flask-WTF (CSRF) ·
APScheduler · OS `ping` (ICMP) with TCP-connect fallback · pysnmp (optional SNMP v2c) ·
SMTP (smtplib) · ReportLab (PDF) · Bootstrap 5, Chart.js 4, Bootstrap Icons, IBM Plex fonts
(all served locally — the UI works offline) · SQLite (demo) / PostgreSQL / MySQL 8 · gunicorn.

## 3. Test results

| Suite | Tests | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| `test_auth.py` — login, lockout, roles, CSRF, user management | 32 | 32 | 0 | 0 |
| `test_devices.py` — CRUD, validation, injection, search/filter/sort/paginate, thresholds, DB constraints | 31 | 31 | 0 | 0 |
| `test_collector.py` — ping parsing (Linux/BusyBox/macOS/Windows), ICMP path, TCP probes, timeouts, SNMP failure, simulation | 32 | 31 | 0 | 1 |
| `test_monitoring.py` — real checks, down/recovery, thresholds, uptime maths, NFR2, scheduler, locks, alerts, email | 24 | 24 | 0 | 0 |
| `test_reports_history.py` — dashboard numbers, series API, history, CSV/PDF, statistics, settings | 10 | 10 | 0 | 0 |
| `test_security_reliability.py` — headers, cookies, SQLi, XSS, secrets, DB failure, restart persistence, performance | 11 | 11 | 0 | 0 |
| `test_ui.py` — Chromium: nav links, forms, confirm dialog, filters, charts, exports, 3 screen sizes, keyboard | 12 | 12 | 0 | 0 |
| **Total** | **152** | **151** | **0** | **1** |

Skipped: `test_build_ping_command_is_argument_list` — the `ping` binary is not installed in
this container. The ICMP code path (running `ping`, parsing output, permission errors,
unknown hosts) is still exercised by four tests that use a stand-in `ping` executable.
Run the suite on your laptop to execute it against the real `ping`.

Manual / system checks also performed:

* Fresh virtual-env install following the README word for word → app starts, `/healthz` OK.
* Real scheduled checks stored by the running server (loopback and an Internet host).
* Server restart → all devices, users and results still present.
* gunicorn with 3 workers → exactly one scheduler started, two workers declined; all
  workers report the collector as running.
* Server logs: no tracebacks during normal operation.
* NFR3 timing with 20,000 stored results: dashboard 0.06 s, dashboard API 0.04 s,
  history 0.03 s, reports 0.06 s, 7-day chart 0.01 s.

## 4. Defects found by testing and fixed

| # | Defect | Fix | Regression test |
|---|---|---|---|
| 1 | Windows ping replies of `time<1ms` were counted as 1 ms, inflating average latency | Use Windows' own reported average | `test_parse_ping_output[WINDOWS_OK]` |
| 2 | "SNMP needs a community string" validation never ran (stopped by `Optional()`) | Removed `Optional()` from that field | `test_snmp_requires_community` |
| 3 | Tables overflowed the page width on phones (hidden header text escaped the scroll container) | Scroll container made the positioning context | `test_responsive_layout_no_horizontal_overflow` |
| 4 | With several gunicorn workers, workers without the scheduler reported "Collector stopped" | Status checks the shared scheduler lock | `test_status_reports_running_when_another_process_owns_scheduler` |
| 5 | Simulated profiles produced constant alert flapping (single 25 % loss sample) | Recommended loss rule set to > 25 % / ≥ 75 %, profiles retuned | demo seed inspected |
| 6 | Chart time axis labels overlapped | Limited tick count, no rotation | visual check |

## 5. Known issues and external dependencies

* This container's network answers some unroutable addresses with a TCP reset or via a proxy,
  so real Internet checks here (e.g. 8.8.8.8 at ~0.2–0.5 ms) are not representative. Expect
  tens of milliseconds on a real network. Two real-network timeout tests adapt to this and
  were run against an address that genuinely times out.
* SNMP was not tested against a real agent. Email was tested against a local SMTP test server
  only. Configure `.env` and use **Settings → Send a test email** to verify your provider.
* Not deployed to a public cloud host from here; follow README §4.
* TCP fallback limitation and cloud-to-private-LAN reachability: see README §8.

### Addendum — 22 October 2026 (follow-up changes)

* SNMP community strings are now encrypted at rest (`services/secrets_box.py`); 5 new tests in
  `tests/test_snmp_secret.py`. Re-run in a sandbox without Chromium or `ping`:
  **144 passed, 0 failed, 13 skipped** (157 total). The 13 skips are the 12 browser tests and the
  real-`ping` test; run `tools/verify_local.py` on a real computer to execute them.
* The release zip no longer contains `instance/` (secret key, database, logs).
* The figures in section 3 above are from the original 16 October run and predate these changes.

## 6. Report alignment — objectives → features → tests

| Objective (§1.4) | Implemented feature | Evidence (tests) |
|---|---|---|
| 1. Design architecture, database, workflow, UI, alerting | Layered modules (`services/collector` → `monitor` → `alerting` → `notifier`; `blueprints` presentation); Table 3.4 schema with FKs, indexes, CHECK/UNIQUE constraints | `test_database_constraint_blocks_invalid_rows`, `test_delete_device_cascades_history` |
| 2. Register devices; collect reachability, latency, loss, uptime | Device CRUD; ICMP/TCP/SNMP collector; scheduler; uptime from stored results | `test_register_valid_device…`, `test_real_check_of_reachable_endpoint_is_stored`, `test_real_check_of_unreachable_endpoint_times_out_safely`, `test_uptime_matches_stored_results`, `test_real_background_scheduler_runs_and_has_single_job` |
| 3. Dashboard, history, reports, automated email alerts | Live dashboard + charts; history with filters/CSV; reports with min/mean/max, CSV/PDF; threshold & device-down alerts with SMTP email | `test_dashboard_api_reflects_stored_data`, `test_history_filters_sort_and_pagination`, `test_report_statistics_match_stored_data`, `test_report_pdf_export`, `test_threshold_breach_creates_single_alert_and_auto_resolves`, `test_email_sent_on_new_alert_suppressed_on_repeat_and_sent_on_recovery` |
| 4. Test against functional, reliability, security, usability criteria | 152 automated tests; this report | whole suite |

### Table 3.6 acceptance criteria

| Area | Result | Test |
|---|---|---|
| Authentication | Pass | `test_login_success_and_logout`, `test_invalid_credentials_rejected…`, `test_protected_pages_require_login` |
| Device management (add, edit, enable, disable, remove) | Pass | `test_register_valid_device…`, `test_edit_device`, `test_disable_and_enable_device_closes_alerts`, `test_delete_device_cascades_history` |
| Monitoring (correct status, timestamped results) | Pass | `test_device_marked_down_only_after_consecutive_failures_and_one_alert`, `test_real_check_of_reachable_endpoint_is_stored` |
| Metrics (latency, loss recorded) | Pass | `test_parse_ping_output`, `test_icmp_probe_runs_os_ping_and_parses`, `test_packet_loss_threshold` |
| Dashboard | Pass | `test_dashboard_api_reflects_stored_data`, `test_dashboard_renders_live_data_and_chart` |
| History / report for device and period | Pass | `test_history_filters_sort_and_pagination`, `test_report_statistics_match_stored_data` |
| Alerts — one record + notification behaviour | Pass | `test_threshold_breach_creates_single_alert…`, `test_email_sent_on_new_alert…`, `test_acknowledged_alert_gets_no_reminders` |
| Resilience — failed check does not stop others | Pass | `test_one_failing_device_does_not_stop_others`, `test_database_error_during_check_is_contained`, `test_email_failure_does_not_break_monitoring` |
| Security — hashed passwords, secrets outside code | Pass | `test_passwords_are_hashed`, `test_secrets_not_exposed`, `test_sql_injection_in_search_is_harmless`, `test_stored_xss_is_escaped` |
| Usability | Partly automated (keyboard, labels, responsive, empty states); the user-rating checklist in §3.11 must be done with real participants | `test_keyboard_navigation…`, `test_responsive_layout…` |
