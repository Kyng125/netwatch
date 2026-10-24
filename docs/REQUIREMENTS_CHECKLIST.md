# Requirements Checklist — derived from the seminar report

Source: *Design and Implementation of a Cloud-Based Network Monitoring System for a
Small Organisation* (Osamhanze Wisdom, Abdulrauf Ridwan Akande, Olajide Samuel —
Yaba College of Technology, HND Computer Science, July 2026). Supervisor: Dr. Mrs. Akinade A. O.

> **Note on the report.** Section 3.5.1 *Functional Requirements* has a heading and a
> List-of-Tables entry (Table 3.2) but the table itself is missing from the PDF. The
> functional requirements below (FR1–FR12) were therefore reconstructed from §1.7 Scope,
> §3.5.5 Use-Case Model, §3.5.8 System Flow, §3.8.1 Monitoring and Alert Logic and
> Table 3.6 Acceptance Criteria. You should insert this table into the report as Table 3.2.

## Functional requirements (reconstructed Table 3.2)

| Code | Requirement | Report source | Implemented in |
|---|---|---|---|
| FR1 | Administrator authentication (login/logout); protected pages | §1.7, Fig 3.3 "Login", Table 3.6 | `blueprints/auth.py` |
| FR2 | Manage user accounts | Fig 3.3 "Manage User Accounts", Users table `role` | `blueprints/users.py` |
| FR3 | Register, edit, enable, disable and remove devices | §1.7, Table 3.6 "Device management" | `blueprints/devices.py` |
| FR4 | Periodic reachability checks at each device's polling interval | §3.5.8, §3.8.1, scheduler actor | `services/scheduler.py` |
| FR5 | Collect latency, packet loss (ICMP); optional SNMP CPU/memory | Obj. 2, §2.2.6, Table 3.5 | `services/collector.py` |
| FR6 | Calculate uptime from stored observations | §1.7, §1.9 "Uptime" | `services/stats.py` |
| FR7 | Configure thresholds per device | §1.7, Thresholds table | `blueprints/devices.py` |
| FR8 | Generate alerts on device failure / threshold breach, with status-change logic, consecutive-failure confirmation and repeat suppression | §2.2.7, §3.8.1 | `services/alerting.py` |
| FR9 | Email alert notification via SMTP | Obj. 3, Fig 3.2, Fig 3.6 | `services/notifier.py` |
| FR10 | Central dashboard (current status, recent results, trends, alerts) | Obj. 3, §1.9 "Dashboard" | `blueprints/dashboard.py` |
| FR11 | Historical records for a selected device and period | Table 3.6 "History/report" | `blueprints/history.py` |
| FR12 | Report generation (descriptive statistics min/max/avg, §3.10) | Obj. 3, Fig 3.4 process 5.0 | `blueprints/reports.py` |
| FR13 | Audit log of significant administrator actions | Audit_Log table | `services/audit.py` |
| FR14 | Acknowledge and manage alerts | Fig 3.3 "Receive Alerts", Alerts `acknowledged_at`, `status` | `blueprints/alerts.py` |

## Non-functional requirements (Table 3.3)

| Code | How it is met |
|---|---|
| NFR1 Security | Werkzeug PBKDF2/scrypt hashing; `login_required` + role checks; CSRF on every form; secrets from env vars; login lockout; security headers |
| NFR2 Reliability | Each device check runs in its own try/except and DB session; one failure never stops the scheduler |
| NFR3 Performance | Indexed `(device_id, checked_at)`; dashboard JSON endpoint; response time measured in tests |
| NFR4 Scalability | Thread-pool collector; any number of devices; SQLite → MySQL/PostgreSQL via `DATABASE_URL` |
| NFR5 Usability | Colour + text status labels, plain-language alerts, help text on forms |
| NFR6 Maintainability | Blueprints + services modules; README; docstrings |
| NFR7 Availability | gunicorn `Procfile`, log file, scheduler restarts with the app, data persists |
| NFR8 Data integrity | DB constraints (unique, FK, NOT NULL, CHECK) + server-side validation |
| NFR9 Portability | Pure Python, runs on Linux (cloud) and Windows (laptop demo) |

## Database (Table 3.4) — implemented exactly, plus support columns
Users, Devices, Monitoring_Results, Thresholds, Alerts, Audit_Log (+ `system_settings`
for the configurable values the report mentions in §3.8.1: consecutive failures,
reminder interval).

## Explicitly out of scope (§1.7) — NOT implemented
Deep-packet inspection, SIEM, intrusion detection, AI/ML fault prediction, automatic
remediation, multi-tenant enterprise monitoring, traffic engineering.

## Assumptions made where the report is silent
1. A device is marked **down** after 2 consecutive failed checks (configurable; §3.8.1 says "may require a defined number").
2. Repeat ("reminder") notifications every 60 minutes while a condition persists (configurable).
3. Uptime on the dashboard is the 24-hour rolling proportion of successful checks (§1.9).
4. Each ICMP check sends 4 echo requests; packet loss = lost / sent.
5. Where raw ICMP is unavailable (many cloud hosts block it), the collector falls back to a
   TCP-connect probe and **records the method used** on every result.
6. Simulated (demonstration) devices are flagged in the database and labelled
   "SIMULATED" everywhere they appear; they are never mixed silently with real results.
7. Two roles: `admin` (full control) and `viewer` (read-only + acknowledge alerts).
