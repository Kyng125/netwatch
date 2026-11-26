# Hosting Netwatch on Render (free plan)

This puts a working copy of Netwatch on the Internet with **real public targets** (measured live) and
clearly labelled **simulated devices**. Everything is defined in `render.yaml`, so Render builds it for you.

## What the hosted copy shows

| Devices | What they are | How they are measured |
|---|---|---|
| Google Public DNS, Cloudflare DNS, Quad9 DNS, GitHub, Wikipedia, Example.com | **Real** public services | TCP connection to port 443 (then 80) every 2 minutes, from the Render server |
| Core Switch, Main Router, File Server, Accounts Wi-Fi AP, Branch VPN Firewall, Reception Printer (all marked "demo") | **Simulated** | Synthetic values, purple SIMULATED badge everywhere, 12 hours of history pre-loaded |

Two honest points for your supervisor:

* **TCP, not ICMP.** A cloud host cannot send ICMP ping, so the hosted copy times a TCP connection instead and
  records `tcp` on every result. The report's ICMP method is demonstrated on your laptop
  (`python tools/verify_local.py`). Netwatch chooses the method automatically.
* **The cloud server cannot see your office LAN by itself.** Private addresses such as 192.168.x.x are only
  reachable from inside your network. To monitor them from this hosted copy, create a *site* and run the
  on-site agent on a computer in that LAN — it reports to Render over HTTPS, no router changes needed.
  See [LAN_AGENT.md](LAN_AGENT.md). Existing data is kept when you deploy this version: the start command's
  `init-db` adds the two new `devices` columns automatically.

## Before you start

1. A GitHub account and a Render account (<https://render.com>).
2. The project folder **without** `instance/` and `.env` (the `.gitignore` already excludes them, and the zip does not contain them).
3. Choose two passwords (at least 8 characters, letters and a number): one for `admin`, one for the read-only `viewer`.

## Steps

1. **Put the project on GitHub.** In the project folder:
   ```bash
   git init
   git add .
   git status        # check: no .env, no instance/ folder in the list
   git commit -m "Netwatch"
   git branch -M main
   git remote add origin https://github.com/<your-username>/netwatch.git
   git push -u origin main
   ```
   (A private repository is fine.)
2. In Render choose **New → Blueprint**, connect GitHub, and select the repository. Render reads `render.yaml`.
3. Render asks for **ADMIN_PASSWORD** and **VIEWER_PASSWORD**. Type the two passwords you chose.
4. Click **Apply**. Render creates the database (`netwatch-db`) and the web service (`netwatch`) in Frankfurt
   and starts the first deploy. The first start takes a few minutes: it installs packages, creates the tables
   and loads the demonstration data.
5. When the service shows **Live**, open its `https://netwatch-xxxx.onrender.com` address and sign in as `admin`.

## Check that it works

* `https://<your-address>/healthz` shows `{"database":"ok","scheduler":"running","status":"ok"}`.
* **Devices**: the six real targets show method **TCP**. Press **Check now** on one to see a reading immediately.
* **Dashboard**: the purple banner says demonstration mode is active for 6 devices; the other 6 are real.
* Sign in as `viewer` in a private window to show the read-only role.

## Limits of the free plan (read before the defence)

These come from Render's documentation ([Deploy for Free](https://render.com/docs/free)); check it again
close to your defence date because plans change.

* **Sleeps after 15 minutes without visitors; waking takes about a minute.** While asleep nothing is
  monitored, so the history has gaps. Open the site a few minutes before presenting. A free uptime pinger
  that requests `/healthz` every 5 minutes keeps it awake; the free plan gives 750 instance hours a month,
  which is enough for one service running all month.
* **The free database expires 30 days after it was created** (then a 14-day grace period before deletion),
  holds 1 GB and has no backups. Create it close to your defence. If it expires, delete the Blueprint
  resources, apply the Blueprint again, and the demonstration data is recreated.
* **No shell access.** That is why the demonstration data is loaded automatically on the first start
  (`seed-public --if-empty`) and never again once users exist.
* **Email cannot be sent from the free plan.** Render blocks outbound SMTP ports 25, 465 and 587 on free
  web services, so Gmail alerts will not leave the server. In-app alerts work normally. Show email alerts from
  your laptop (`python tools/verify_local.py --email-to ...`), and say so.
* The free web service is a single small instance (0.1 CPU, 512 MB): fine for a demonstration, not for load.

## If something goes wrong

| Symptom | Cause and fix |
|---|---|
| Deploy fails; log says `ADMIN_PASSWORD is missing or too weak` | Service → **Environment**, set the password (8+ characters, letters and a number), then **Manual Deploy**. |
| Deploy fails on `pip install` | Open the build log; usually a temporary download failure. **Manual Deploy → Clear build cache & deploy**. |
| Pages say "Database unavailable" | The database is still starting or has expired. Check the `netwatch-db` page. |
| Every real target shows Down | Wait one polling cycle (2 minutes) after waking; if it persists, open **Settings** and read the collector status. |
| You forgot a password | Passwords are only set when the database is empty. Sign in with the other account, or recreate the database. |
| Changed the passwords in Render but the old ones still work | Expected: they are read only when the database is empty. Change them on the **Profile** page. |

## Costs and cleanup

Both resources use the `free` plan in `render.yaml`. Render's pricing and account requirements can change, so
check what it shows on the Blueprint review screen before you click Apply. When you are finished, delete the
Blueprint resources in Render so the database and service stop existing.
