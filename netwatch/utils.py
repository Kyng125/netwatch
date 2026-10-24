"""Small shared helpers: time-zone display, date-range parsing, pagination args."""
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import current_app, request

from .models import utcnow


def local_tz():
    try:
        return ZoneInfo(current_app.config.get("DISPLAY_TIMEZONE", "UTC"))
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def to_local(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(local_tz())


def fmt_dt(dt, fmt="%d %b %Y, %H:%M:%S"):
    loc = to_local(dt)
    return loc.strftime(fmt) if loc else "—"


def iso_utc(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat() if dt else None


def time_ago(dt):
    if dt is None:
        return "never"
    secs = int((utcnow() - dt).total_seconds())
    if secs < 5:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"


def parse_local_date(value):
    """'YYYY-MM-DD' in the display time zone -> date or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def local_day_bounds_utc(start_date, end_date):
    """Convert an inclusive local date range to naive-UTC [start, end] datetimes."""
    tz = local_tz()
    start = datetime.combine(start_date, time.min, tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)
    end = datetime.combine(end_date, time.max, tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)
    return start, end


def date_range_from_args(default_days=1, max_days=366):
    """Read ?start=YYYY-MM-DD&end=YYYY-MM-DD; return (start_utc, end_utc, start_date, end_date, error)."""
    today = to_local(utcnow()).date()
    start_d = parse_local_date(request.args.get("start"))
    end_d = parse_local_date(request.args.get("end"))
    error = None
    if request.args.get("start") and start_d is None or request.args.get("end") and end_d is None:
        error = "Dates must be in YYYY-MM-DD format; showing the default range instead."
        start_d = end_d = None
    end_d = end_d or today
    start_d = start_d or (end_d - timedelta(days=default_days - 1))
    if start_d > end_d:
        error = "The start date was after the end date, so the two were swapped."
        start_d, end_d = end_d, start_d
    if (end_d - start_d).days > max_days:
        error = f"Ranges are limited to {max_days} days; the start date was adjusted."
        start_d = end_d - timedelta(days=max_days)
    s, e = local_day_bounds_utc(start_d, end_d)
    return s, e, start_d, end_d, error


def int_arg(name, default, lo=None, hi=None):
    try:
        v = int(request.args.get(name, default))
    except (TypeError, ValueError):
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def per_page_arg(default=20):
    v = int_arg("per_page", default)
    return v if v in (10, 20, 50, 100) else default
