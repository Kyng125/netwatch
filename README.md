# Netwatch — Cloud-Based Network Monitoring System for a Small Organisation

HND Computer Science (NCC) project, Yaba College of Technology — Osamhanze Wisdom,
Abdulrauf Ridwan Akande, Olajide Samuel. Supervisor: Dr. Mrs. Akinade A. O.

Netwatch registers network devices, checks them on a schedule (ICMP ping, with optional
SNMP), stores every time-stamped result, calculates latency, packet loss and uptime, shows
everything on a live dashboard, raises alerts when a device fails or a threshold is crossed,
emails the administrator, and produces exportable reports — exactly the system described in
Chapters 1–3 of the seminar report.

---

## 1. Run it on a Windows laptop (step by step)

1. Install **Python 3.11 or newer** from <https://www.python.org/downloads/>.
   On the first installer screen tick **“Add python.exe to PATH”**.
2. Unzip `netwatch.zip` (e.g. to `Documents\netwatch`).
3. Open the folder in File Explorer, click the address bar, type `cmd` and press Enter.
4. Run these commands one at a time:

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py init-db
python manage.py seed-demo --password Demo2026pass
python app.py
```

5. Open <http://localhost:5000> and sign in as **admin** / **Demo2026pass**
   (a read-only account **viewer** uses the same password).

Next time you only need `venv\Scripts\activate` then `python app.py`.
Stop the server with **Ctrl + C**.

> Want an empty system instead of demo data? Skip `seed-demo`; the first visit shows a
> one-time page to create the administrator account.

### macOS / Linux

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python manage.py init-db
python manage.py seed-demo --password Demo2026pass
python app.py
```

## 2. Configuration (`.env`)

Copy `.env.example` to `.env` and edit. Everything is optional for a laptop demo.

| Setting | Purpose |
|---|---|
| `SECRET_KEY` | Session signing key. If empty, one is generated once into `instance/.secret_key`. |
| `DATABASE_URL` | Empty = SQLite file `instance/netwatch.db`. Use PostgreSQL or MySQL 8 in the cloud (Table 3.5). |
| `MONITOR_METHOD` | `auto` (ICMP, fall back to TCP if the host blocks ICMP), `icmp`, or `tcp`. |
| `PING_COUNT`, `PING_TIMEOUT_SECONDS` | Probes per check and per-probe timeout. |
| `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM` | SMTP for email alerts. |
| `DISPLAY_TIMEZONE` | Default `Africa/Lagos`. |

**Gmail for alerts:** turn on 2-step verification, create an *App password*
(Google Account → Security → App passwords), then set `MAIL_SERVER=smtp.gmail.com`,
`MAIL_PORT=587`, `MAIL_USE_TLS=true`, `MAIL_USERNAME=you@gmail.com`,
`MAIL_PASSWORD=<16-character app password>`, `MAIL_FROM=you@gmail.com`. Restart, then use
**Settings → Send a test email**.

Monitoring parameters that the report calls configurable (§3.8.1) — consecutive failures
before “down”, reminder interval, default polling interval, retention — are edited on the
**Settings** page and stored in the database.

## 3. Management commands

```
python manage.py init-db                       create tables
python manage.py create-admin                  create an administrator (prompts)
python manage.py seed-demo --password ...      demo users, devices, 24 h of SIMULATED history
python manage.py check-all                     check every enabled device once and print results
python manage.py reset-db --yes                delete ALL data and recreate empty tables
```

## 4. Deploy to the cloud (Render.com)

A ready-made blueprint (`render.yaml`) hosts Netwatch on Render's free plan with a PostgreSQL database,
**real public targets** (Google/Cloudflare/Quad9 DNS, GitHub, Wikipedia, example.com) and the clearly
labelled **simulated** devices. Follow **`docs/DEPLOY_RENDER.md`**: push to GitHub, create a Blueprint in
Render, enter the two passwords it asks for, and wait for the first deploy.

Manual setup instead: install `requirements-cloud.txt` (it adds the PostgreSQL driver), set `DATABASE_URL`
(Render's `postgres://...` form is accepted), `SECRET_KEY`, `SESSION_COOKIE_SECURE=true`, `MONITOR_METHOD=tcp`,
and start with `gunicorn "app:app" --workers 1 --threads 4 --timeout 60 --bind 0.0.0.0:$PORT`.
`python manage.py seed-public --if-empty` loads the cloud demonstration data (needs `ADMIN_PASSWORD` and
`VIEWER_PASSWORD` in the environment) and does nothing if users already exist. Health check path: `/healthz`.
Only one process ever runs the monitoring scheduler, even with several gunicorn workers (a lock file guarantees it).

**Important:** a cloud server can only reach devices that are reachable from the Internet, and it measures them
with TCP connections because cloud hosts do not allow ICMP ping. Private LAN devices (192.168.x.x) are monitored
from the laptop copy (Section 7).

## 5. Run the tests

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium      # once, for the browser tests
python -m pytest                           # everything (about 1.5 minutes)
python -m pytest --ignore=tests/test_ui.py # backend only, no browser needed
```

### Collect real-world evidence (run on your own computer)

Some checks cannot run in a cloud sandbox: the 12 browser tests, the real `ping` test, a real
router and a real mailbox. One script does them all and writes the results to
`docs/local_verification_<timestamp>.md`:

```bash
venv\Scripts\activate                          # Windows (macOS/Linux: source venv/bin/activate)
python -m pip install -r requirements-dev.txt  # app packages + pytest + Playwright (once)
python tools/verify_local.py --install-browser --target 192.168.1.1 --email-to you@gmail.com
```

If the script says packages are missing, you are not inside the virtual environment from section 1
(the prompt should start with `(venv)`). If pip reports `No matching distribution found ...
(from versions: none)`, pip cannot reach the package index: upgrade pip, retry with
`python -m pip install --default-timeout 120 --retries 10 -r requirements-dev.txt`, or change network.

* `--target` is a device you are authorised to monitor (your router). It is checked over ICMP,
  then run through the application's own monitor and alert logic in a temporary database.
* `--email-to` sends a real test message using the `MAIL_*` values in `.env`.
* Anything marked PARTIAL, SKIPPED or WARNING in the output is **not** verified yet.
* Your real Netwatch database is never touched, and no secrets are printed.

## 6. What is implemented

| Area | Features |
|---|---|
| Authentication | Login/logout, first-run admin setup, hashed passwords, 5-attempt lockout, session protection, CSRF on every form, admin vs viewer roles |
| Devices | Register, edit, enable/disable, delete (with confirmation), search, filter by type/status/source, sortable columns, pagination, “Check now”; SNMP community strings are stored encrypted (key derived from `SECRET_KEY`) |
| Monitoring | Scheduled checks at each device's own interval; ICMP via the OS `ping` command (Table 3.5) with TCP fallback; optional SNMP v2c CPU/memory; per-device lock + single scheduler |
| Private LANs | **Sites & on-site agents**: a dependency-free agent (`agent/netwatch_agent.py`) runs inside the LAN, checks private addresses and reports to the cloud over HTTPS with a per-site key; agent-offline detection and alerts; “Check now” works through the agent ([docs/LAN_AGENT.md](docs/LAN_AGENT.md)) |
| Metrics | Reachability, latency, packet loss, 24 h rolling uptime, stored per check with the method used |
| Thresholds | Per-device rules (>, ≥, <, ≤) on latency, loss, uptime, CPU, memory; warning or critical |
| Alerts | Device-down after N consecutive failures; one alert per condition; auto-resolve on recovery; acknowledge / close with notes; reminder suppression |
| Email | SMTP alerts, reminders and recovery notices; test-email button; failures logged, never crash monitoring |
| Dashboard | Stat cards, device status tiles, 6-hour latency chart, active alerts, recent activity; auto-refresh every 15 s |
| History | Every result, filter by device / dates / outcome / method, sort, paginate, CSV export |
| Reports | Min / mean / max latency and loss, uptime, alert counts per device and period (§3.10); CSV and PDF export |
| Users & audit | User management (Fig 3.3), audit log of significant actions with filters |
| Settings | Monitoring/alert parameters, SMTP status, collector status, platform info |

### Demonstration (simulated) devices

`seed-demo` adds six devices marked **SIMULATED** (purple badge everywhere, “simulated” in
CSV/PDF exports and emails). Their values are synthetic and pass through the same storage,
threshold and alert engine as real devices, so alerts, outages and reports can be shown
without a lab network. Three **real** devices are also added: the Netwatch server itself
(`127.0.0.1`), Google Public DNS (`8.8.8.8`) and a disabled “Office Gateway” — edit its
address to your router's IP and enable it.

## 7. Demonstration guide (suggested order, ~10 minutes)

1. **Login** — show the sign-in page; mention hashing, lockout and roles (NFR1).
2. **Dashboard** — status tiles, uptime, active alerts, latency chart; point out SIMULATED vs real.
3. **Register a real device** — Devices → Register device → your router's IP (e.g. `192.168.1.1`)
   with recommended thresholds → **Check now** → real latency appears (Objective 2).
4. **Device page** — chart range buttons, availability strip, threshold rules, latest results.
5. **Trigger an alert live** — add a rule *Latency > 0.1 ms* (warning) on the real device →
   Check now → alert opens; show it on Alerts and in your inbox if SMTP is set (Objective 3).
6. **Acknowledge and close** it; show the audit log entries.
7. **Device failure** — register an address with nothing on it (e.g. `192.168.1.250`) and
   Check now twice → device goes **Down** and a critical alert opens. Disable it afterwards.
8. **History** — filter by that device and *Failed*, export CSV.
9. **Reports** — last 7 days, download the PDF (descriptive statistics, §3.10).
10. **Settings / Users** — configurable parameters, SMTP test, viewer account.
11. **Tests** — run `python -m pytest` to show the automated test evidence (Objective 4).

**Private LAN from the cloud (on-site agent, ~5 minutes extra)** — on the hosted copy:

1. *Sites & agents → New site* (“Lab LAN”); copy the agent key shown once.
2. *Add device to this site*: the router's private address from `ipconfig` (Default Gateway), plus an
   address with nothing on it (e.g. `192.168.1.250`) to show a failure.
3. On a laptop connected to that network: download the agent from the site page, then
   `python netwatch_agent.py --server https://… --key nwa_… --save` and `python netwatch_agent.py`.
4. Within seconds the router shows **Up** with real LAN latency and the empty address goes **Down** with
   a critical alert — measured inside the private network, displayed in the cloud.
5. Close the agent window: after the offline limit the site shows **Agent offline**, its devices
   **Pending**, and agent-offline alerts open. Start it again and they resolve.

## 8. Known limitations

* **ICMP in the cloud.** Many cloud hosts block raw ICMP; Netwatch then uses TCP-connect
  probes (ports 80/443/22) and records `tcp` on each result. A TCP probe treats an immediate
  refusal (RST) as “host is up”; a firewall that answers on behalf of a missing host can
  therefore make a down device look up. Use ICMP where available.
* **TCP probes on Windows.** Windows takes about 2 seconds to report a refused connection, which is
  close to the default 2-second probe timeout. On Windows Netwatch uses real `ping` (ICMP), so this only
  matters if you force `MONITOR_METHOD=tcp` there; raise `PING_TIMEOUT_SECONDS` to 4 or more if you do.
  The two tests that depend on this behaviour use a longer timeout on Windows.
* **Cloud vs private LAN.** A cloud server cannot reach private addresses (192.168.x.x, 10.x.x.x) by
  itself. Netwatch solves this with an **on-site agent** (`agent/netwatch_agent.py`) that runs on a
  computer inside the LAN and reports to the cloud over HTTPS — see [docs/LAN_AGENT.md](docs/LAN_AGENT.md).
  The agent computer must stay on; agents do not yet collect SNMP.
* **SNMP** is implemented (v2c; HOST-RESOURCES-MIB CPU, UCD-SNMP-MIB memory) but was only
  tested for graceful failure — no SNMP-enabled device was available. Vendor MIBs differ.
* **Email** was tested against a local SMTP test server, not a real provider; use the test
  button once your `.env` is set.
* **Keep `SECRET_KEY` stable.** It also protects the stored SNMP community strings: if it changes,
  those strings cannot be read and must be re-entered on each device. Never share the `instance/`
  folder or commit `.env` — build a release zip without them.
* SQLite suits a demo or a handful of devices; the cloud deployment uses PostgreSQL. The full backend test
  suite also passes against PostgreSQL 16 (`NETWATCH_TEST_DB_URL=postgresql://... python -m pytest --ignore=tests/test_ui.py`);
  MySQL has not been tested.
* **Email from the free Render plan:** outbound SMTP ports are blocked there, so email alerts cannot be sent from
  the hosted copy; in-app alerts work. Demonstrate email from the laptop.
* Usability evaluation with real users (§3.11 item 7) is a human activity and is not automated.

## 9. Project layout

```
app.py                     entry point (python app.py / gunicorn app:app)
manage.py                  database and demo commands
netwatch/
  __init__.py              application factory, error pages, security headers
  config.py                environment-driven configuration
  models.py                Table 3.4 schema (Users, Devices, Monitoring_Results, Thresholds, Alerts, Audit_Log)
  forms.py                 server-side validation
  blueprints/              auth, dashboard, devices, sites, alerts, history, reports, users, settings,
                           api, agent_api (key-authenticated API for on-site agents)
  migrations.py            adds new columns to databases created by an earlier version
  services/                collector (ICMP/TCP/SNMP/simulated), monitor, agents, alerting, notifier,
                           scheduler, stats, series, audit, settings, demo
agent/netwatch_agent.py    on-site agent for private LANs (standard library only)
  templates/, static/      Jinja2 pages, CSS, JS, vendored Bootstrap / Chart.js / fonts (works offline)
tests/                     pytest suite (backend, security, browser UI)
docs/                      requirements checklist, verification report, Render and LAN-agent guides
```
