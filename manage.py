"""Netwatch management commands (works the same on Windows, macOS and Linux).

    python manage.py init-db                      create all tables
    python manage.py create-admin                 create an administrator (prompts)
    python manage.py seed-demo --password ...     demo users, devices and 24h of SIMULATED history
    python manage.py seed-public --if-empty       cloud demo: REAL public targets + SIMULATED devices
                                                  (passwords come from ADMIN_PASSWORD / VIEWER_PASSWORD)
    python manage.py check-all                    run one check of every enabled device now
    python manage.py reset-db --yes               DELETE all data and recreate empty tables
"""
import argparse
import getpass
import re
import sys

from dotenv import load_dotenv

load_dotenv()

from netwatch import create_app  # noqa: E402
from netwatch.extensions import db  # noqa: E402
from netwatch.models import Device, User  # noqa: E402


def _password_ok(pw):
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def main(argv=None):
    p = argparse.ArgumentParser(description="Netwatch management commands")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db", help="create database tables")
    ca = sub.add_parser("create-admin", help="create an administrator account")
    ca.add_argument("--username")
    ca.add_argument("--email")
    sd = sub.add_parser("seed-demo", help="load demonstration data")
    sd.add_argument("--username", default="admin")
    sd.add_argument("--email", default="admin@example.com")
    sd.add_argument("--password", help="password for the demo accounts (admin and viewer)")
    sd.add_argument("--hours", type=int, default=24, help="hours of simulated history (default 24)")
    sp = sub.add_parser("seed-public", help="cloud demo data: real public targets + simulated devices")
    sp.add_argument("--if-empty", action="store_true", help="do nothing if any user already exists (safe on every start)")
    sp.add_argument("--hours", type=int, default=12, help="hours of simulated history (default 12)")
    sub.add_parser("check-all", help="check every enabled device once, now")
    rs = sub.add_parser("reset-db", help="drop and recreate all tables")
    rs.add_argument("--yes", action="store_true")
    args = p.parse_args(argv)

    app = create_app(start_scheduler=False)
    with app.app_context():
        if args.cmd == "init-db":
            db.create_all()
            print(f"Database ready: {db.engine.url.render_as_string(hide_password=True)}")

        elif args.cmd == "reset-db":
            if not args.yes:
                print("Refusing to delete data without --yes")
                return 1
            db.drop_all()
            db.create_all()
            print("All tables dropped and recreated (empty).")

        elif args.cmd == "create-admin":
            username = args.username or input("Username: ").strip()
            email = args.email or input("Email: ").strip()
            pw = getpass.getpass("Password (min 8 chars, letters + a number): ")
            if not _password_ok(pw):
                print("Password too weak.")
                return 1
            if User.query.filter((User.username == username) | (User.email == email.lower())).first():
                print("A user with that username or email already exists.")
                return 1
            u = User(username=username, email=email.lower(), role="admin")
            u.set_password(pw)
            db.session.add(u)
            db.session.commit()
            print(f"Administrator '{username}' created.")

        elif args.cmd == "seed-demo":
            from netwatch.services import demo
            pw = args.password or getpass.getpass("Password for demo accounts: ")
            if not _password_ok(pw):
                print("Password too weak (min 8 chars, letters + a number).")
                return 1
            out = demo.seed(args.username, args.email, pw, hours=args.hours)
            print(f"Demo data loaded: {out['devices']} devices, {out['simulated_results']} simulated results, "
                  f"{out['alerts']} alerts.")
            print(f"Sign in as '{out['admin']}' (administrator) or 'viewer' (read-only) with the password you gave.")

        elif args.cmd == "seed-public":
            import os
            from netwatch.services import demo
            if args.if_empty and User.query.count() > 0:
                print("Database already has users - public demo data not loaded (nothing changed).")
                return 0
            admin_pw, viewer_pw = os.environ.get("ADMIN_PASSWORD", ""), os.environ.get("VIEWER_PASSWORD", "")
            for label, pw in (("ADMIN_PASSWORD", admin_pw), ("VIEWER_PASSWORD", viewer_pw)):
                if not _password_ok(pw):
                    print(f"{label} is missing or too weak: set it (min 8 characters, letters and a number) in the "
                          "environment, then start again.")
                    return 1
            out = demo.seed_public(admin_pw, viewer_pw, admin_email=os.environ.get("ADMIN_EMAIL", "admin@example.com"),
                                   hours=args.hours)
            if out is None:
                print("Database already has users - public demo data not loaded (nothing changed).")
            else:
                print(f"Public demo data loaded: {out['devices']} devices, {out['simulated_results']} simulated "
                      f"results, {out['alerts']} alerts. Sign in as 'admin' (administrator) or 'viewer' (read-only).")

        elif args.cmd == "check-all":
            from netwatch.services import monitor
            for d in Device.query.filter_by(enabled=True).order_by(Device.device_name).all():
                r = monitor.check_device(d.device_id)
                if r is None:
                    print(f"  {d.device_name:32} skipped")
                    continue
                lat = f"{r.latency_ms:.2f} ms" if r.latency_ms is not None else "-"
                print(f"  {d.device_name:32} {'UP  ' if r.reachable else 'DOWN'} {lat:>10}  "
                      f"loss {r.packet_loss_percent if r.packet_loss_percent is not None else '-'}%  "
                      f"[{r.method}] {r.error_message or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
