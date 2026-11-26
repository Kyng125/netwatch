# Monitoring a private network (LAN) with the on-site agent

The hosted Netwatch runs in the cloud (Render). A cloud server **cannot** reach private addresses such
as `192.168.1.1`, `10.150.121.187` or `172.16.0.10`: those addresses only exist inside one local
network, and the internet has no route to them. To monitor the equipment of a small organisation — its
router, switches, access points, printers and PCs — Netwatch uses a small **on-site agent**.

```
 Private LAN (e.g. 10.150.121.0/24)                             Cloud (Render)
 ┌──────────────────────────────────────────┐                 ┌──────────────────────────────┐
 │ router 10.150.121.187   printer .50      │                 │ Netwatch web app + PostgreSQL│
 │        ▲  ping / TCP      ▲              │   HTTPS (out)   │                              │
 │        └──────── agent PC ┘  ────────────┼───────────────► │ /api/agent/v1/jobs           │
 │              netwatch_agent.py           │ ◄────────────── │   "check these devices"      │
 │                                          │ ───────────────►│ /api/agent/v1/results        │
 └──────────────────────────────────────────┘                 │ stored → thresholds → alerts │
                                                              └──────────────────────────────┘
```

* The agent only makes **outgoing** HTTPS requests. No router configuration, port forwarding, VPN or
  public IP address is needed; it works behind a mobile hotspot, a school network or a home router.
* Results from the agent go through **exactly the same** storage, uptime calculation, threshold rules,
  alerting, email, history and reports as checks made by the server (`monitor.record_probe`).
* The agent is one Python file with **no dependencies** beyond the standard library (Python 3.9+).

## Setting it up (about 5 minutes)

1. **Create a site.** In Netwatch: *Sites & agents → New site*, e.g. “Yabatech Lab LAN”. The next page
   shows the site's **agent key once** — copy it. Only a SHA-256 hash of the key is stored. If you lose
   it, press *New key* (the old key stops working immediately).
2. **Register the devices** with their private addresses and choose the site under **Checked from**
   (or use *Add device to this site* on the site page). To find addresses, run `ipconfig` on Windows
   (the router is the *Default Gateway*) or `python netwatch_agent.py --scan` on the agent computer.
3. **Start the agent** on any computer connected to that network (the site page shows these commands
   with your server address and key filled in):

   ```
   python netwatch_agent.py --server https://YOUR-NETWATCH.onrender.com --key nwa_... --save
   python netwatch_agent.py --once      # one round of checks, printed in the window
   python netwatch_agent.py             # keep running; leave the window open
   ```

   `--save` stores the server and key in `netwatch-agent.ini` next to the script (keep that file
   private), so later you only run `python netwatch_agent.py`.

Within one polling interval the devices show **Up/Down** on the dashboard with real latency and packet
loss, a *site badge*, and “Checked from: On-site agent”.

## How a check works

1. Every `AGENT_POLL_SECONDS` (default 10 s) the agent asks `/api/agent/v1/jobs` which of its site's
   enabled devices are **due** (their polling interval has passed, or someone pressed *Check now*).
   That request is also the agent's heartbeat.
2. It checks those devices in parallel: **ICMP ping** first (`ping` is available on every Windows PC).
   If ping gets no reply — many Windows PCs and phones block ping — it confirms with a **TCP-connect**
   probe on ports 80, 443, 22, 3389, 53 and 9100 before reporting the device as unreachable.
3. It posts the results to `/api/agent/v1/results`. The server checks each one belongs to that site,
   validates every value, stores it with the server's time, updates the device status and runs the
   alert rules — a device is marked **down** after the configured number of consecutive failures.

### If the agent stops

If a site's agent sends nothing for **Agent offline after** minutes (Settings; default 3), the site is
shown **Agent offline**, its devices are shown **Pending** — not *down*, because the devices themselves
may be fine — and an *agent-offline* alert is raised for each device (one email per site). When the
agent reports again, those alerts resolve automatically and a recovery email is sent.

## Security

| Concern | How it is handled |
|---|---|
| Who can submit results | Only a holder of the site's key (`Authorization: Bearer nwa_…`). Wrong key → 401; disabled site → 403. |
| Key storage | Only a SHA-256 hash is stored; the key is shown once. *New key* revokes the old one. |
| Cross-site tampering | An agent can only report devices assigned to **its** site; others are rejected. |
| Bad data | `reachable` must be a boolean, latency 0–600 000 ms, loss 0–100 %, method `icmp`/`tcp`; at most 500 results and 512 KB per request. |
| Command injection on the agent PC | Addresses from the server are re-validated before `ping` runs (list arguments, no shell). |
| CSRF | The agent API is exempt (it uses a key, not a browser session); every browser form still has CSRF protection. |
| Audit | Site creation, edits, key rotation, deletion, agent offline/online are written to the audit log. |
| Firewalls that fake replies | Some firewalls/VPN/security tools refuse *every* connection themselves, which would make a missing device look up over TCP. The agent detects this once at start-up with a reserved address that cannot exist (`203.0.113.1`, RFC 5737) and then counts only completed connections. |

## Limitations

* The agent computer must stay on and connected; if it sleeps, monitoring of that site pauses (and an
  agent-offline alert says so). On Windows, set *Power & sleep* to “Never” while monitoring.
* **SNMP** (CPU/memory) is collected by the server only, not yet by agents. Agent devices report
  reachability, latency, packet loss and uptime.
* Results are timestamped when the server receives them (no clock-skew issues); results that could not
  be delivered while the internet connection was down are not re-sent.
* On Render's free plan the web service sleeps after ~15 minutes without visits. The agent's requests
  keep it awake while the agent is running; the first request after a sleep can take up to a minute,
  which the agent waits for.

## Settings (environment variables, all optional)

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_POLL_SECONDS` | `10` | How often agents ask for due checks. |
| `AGENT_MONITOR_METHOD` | `auto` | `auto` = ping then TCP confirmation; `icmp` or `tcp` to force one. |
| `AGENT_TCP_PORTS` | `80,443,22,3389,53,9100` | Ports for the TCP probe (web, SSH, RDP, DNS, printers). |

These are separate from `MONITOR_METHOD` / `TCP_PROBE_PORTS`, which the Render blueprint sets to TCP for
the server's own checks (cloud hosts cannot send ICMP); inside a LAN, ping normally works.
