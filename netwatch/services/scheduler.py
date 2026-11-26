"""Background scheduling (internal 'scheduler' actor, §3.5.5).

One APScheduler job ticks every few seconds and checks the devices whose own
polling interval has elapsed. Safeguards against duplicate monitoring:
  * max_instances=1 + coalesce — a slow tick never overlaps the next one;
  * a per-device lock in monitor.check_device;
  * an OS-level file lock so only ONE process runs the scheduler
    (Flask debug reloader or several gunicorn workers).
"""
import atexit
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from ..extensions import db
from . import monitor
from . import settings as app_settings

log = logging.getLogger(__name__)

_state = {"scheduler": None, "lock_file": None, "lock_path": None, "last_tick": None, "last_tick_checked": 0}


def _acquire_process_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def tick(app):
    """Check every due device in parallel (each in its own app context + DB session)."""
    from ..models import utcnow
    with app.app_context():
        try:
            from . import agents
            agents.check_sites()
        except Exception:
            db.session.rollback()
            log.exception("Scheduler could not check on-site agents")
        try:
            ids = monitor.due_device_ids()
        except Exception:
            log.exception("Scheduler could not read the device list")
            db.session.remove()
            return
        db.session.remove()
    _state["last_tick"] = utcnow()
    _state["last_tick_checked"] = len(ids)
    if not ids:
        return

    def work(device_id):
        with app.app_context():
            try:
                monitor.check_device(device_id)
            finally:
                db.session.remove()

    with ThreadPoolExecutor(max_workers=app.config["MAX_PARALLEL_CHECKS"]) as pool:
        list(pool.map(work, ids))


def purge(app):
    with app.app_context():
        try:
            n = monitor.purge_old_results(app_settings.get("retention_days"))
            log.info("Retention purge removed %d old results", n)
        finally:
            db.session.remove()


def start(app):
    if _state["scheduler"] is not None:
        return _state["scheduler"]
    # Debug reloader: only the child process (WERKZEUG_RUN_MAIN=true) should schedule.
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return None
    lock_path = Path(app.instance_path) / "scheduler.lock"
    _state["lock_path"] = lock_path
    lock = _acquire_process_lock(lock_path)
    if lock is None:
        log.info("Another process already runs the monitoring scheduler; not starting a second one")
        return None
    _state["lock_file"] = lock
    sched = BackgroundScheduler(daemon=True, timezone="UTC",
                                job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 30})
    sched.add_job(tick, "interval", seconds=app.config["SCHEDULER_TICK_SECONDS"], args=[app],
                  id="poll_devices", replace_existing=True,
                  next_run_time=datetime.now(timezone.utc) + timedelta(seconds=2))
    sched.add_job(purge, "interval", hours=24, args=[app], id="retention_purge", replace_existing=True)
    sched.start()
    _state["scheduler"] = sched
    atexit.register(shutdown)
    log.info("Monitoring scheduler started (tick every %ss)", app.config["SCHEDULER_TICK_SECONDS"])
    return sched


def shutdown():
    sched = _state.get("scheduler")
    if sched is not None:
        try:
            sched.shutdown(wait=False)
        except Exception:
            pass
        _state["scheduler"] = None
    if _state.get("lock_file"):
        try:
            _state["lock_file"].close()
        except Exception:
            pass
        _state["lock_file"] = None


def _running_elsewhere():
    """True when another process (e.g. a different gunicorn worker) holds the scheduler lock."""
    path = _state.get("lock_path")
    if path is None or _state.get("scheduler") is not None:
        return False
    fh = _acquire_process_lock(path)
    if fh is None:
        return True
    fh.close()  # nobody holds it: release immediately
    return False


def status():
    sched = _state.get("scheduler")
    job = sched.get_job("poll_devices") if sched else None
    here = bool(sched and sched.running)
    return {
        "running": here or _running_elsewhere(),
        "in_this_process": here,
        "jobs": len(sched.get_jobs()) if sched else 0,
        "poll_jobs": sum(1 for j in sched.get_jobs() if j.id == "poll_devices") if sched else 0,
        "next_run": job.next_run_time if job else None,
        "last_tick": _state.get("last_tick"),
        "last_tick_checked": _state.get("last_tick_checked"),
    }
