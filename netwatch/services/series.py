"""Time-series shaping for charts — always built from stored Monitoring_Results."""
import calendar
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from ..models import MonitoringResult, utcnow
from ..utils import iso_utc

RANGES = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24),
          "7d": timedelta(days=7), "30d": timedelta(days=30)}
BUCKETS = {"1h": 0, "6h": 120, "24h": 600, "7d": 3600, "30d": 4 * 3600}  # seconds; 0 = raw points


def _epoch(naive_utc):
    return calendar.timegm(naive_utc.timetuple())


def bucket_rows(rows, bucket):
    """rows: iterable of (checked_at, reachable, latency, loss). Returns averaged points per bucket."""
    groups = defaultdict(list)
    for row in rows:
        groups[_epoch(row[0]) // bucket * bucket].append(row)
    pts = []
    for key in sorted(groups):
        g = groups[key]
        lats = [r[2] for r in g if r[2] is not None]
        losses = [r[3] for r in g if r[3] is not None]
        ups = sum(1 for r in g if r[1])
        pts.append({
            "t": datetime.fromtimestamp(key, timezone.utc).isoformat(),
            "latency": round(sum(lats) / len(lats), 2) if lats else None,
            "loss": round(sum(losses) / len(losses), 1) if losses else None,
            "up": ups == len(g),
            "uptime": round(ups / len(g) * 100, 1),
            "n": len(g),
        })
    return pts


def device_series(device_id, range_key="24h"):
    range_key = range_key if range_key in RANGES else "24h"
    bucket = BUCKETS[range_key]
    since = utcnow() - RANGES[range_key]
    rows = (MonitoringResult.query.with_entities(MonitoringResult.checked_at, MonitoringResult.reachable,
                                                 MonitoringResult.latency_ms, MonitoringResult.packet_loss_percent)
            .filter(MonitoringResult.device_id == device_id, MonitoringResult.checked_at >= since)
            .order_by(MonitoringResult.checked_at).all())
    if not bucket:
        pts = [{"t": iso_utc(t), "latency": lat, "loss": loss, "up": bool(ok), "n": 1} for t, ok, lat, loss in rows]
    else:
        pts = bucket_rows(rows, bucket)
    return {"range": range_key, "bucket_seconds": bucket, "points": pts, "count": len(rows),
            "since": iso_utc(since), "until": iso_utc(utcnow())}
