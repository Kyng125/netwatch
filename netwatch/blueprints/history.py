"""Historical records (FR11): filter, sort, paginate and export stored monitoring results."""
import csv
import io

from flask import Blueprint, Response, flash, render_template, request
from flask_login import login_required

from ..models import Device, MonitoringResult
from ..utils import date_range_from_args, fmt_dt, int_arg, per_page_arg

bp = Blueprint("history", __name__, url_prefix="/history")

SORTS = {"time": MonitoringResult.checked_at, "latency": MonitoringResult.latency_ms,
         "loss": MonitoringResult.packet_loss_percent, "device": Device.device_name,
         "uptime": MonitoringResult.uptime_percent}


def _filtered():
    s, e, sd, ed, err = date_range_from_args(default_days=1)
    device_id = int_arg("device", 0)
    outcome = request.args.get("outcome", "")
    method = request.args.get("method", "")
    sort = request.args.get("sort", "time")
    order = request.args.get("order", "desc")
    q = MonitoringResult.query.join(Device).filter(MonitoringResult.checked_at >= s, MonitoringResult.checked_at <= e)
    if device_id:
        q = q.filter(MonitoringResult.device_id == device_id)
    if outcome == "up":
        q = q.filter(MonitoringResult.reachable.is_(True))
    elif outcome == "down":
        q = q.filter(MonitoringResult.reachable.is_(False))
    if method in MonitoringResult.METHODS:
        q = q.filter(MonitoringResult.method == method)
    col = SORTS.get(sort, MonitoringResult.checked_at)
    q = q.order_by(col.desc() if order == "desc" else col.asc(), MonitoringResult.result_id.desc())
    params = {"device": device_id, "outcome": outcome, "method": method, "sort": sort, "order": order,
              "start": sd.isoformat(), "end": ed.isoformat()}
    return q, params, err


@bp.route("/")
@login_required
def index():
    q, params, err = _filtered()
    if err:
        flash(err, "warning")
    page = q.paginate(page=int_arg("page", 1, 1), per_page=per_page_arg(50), error_out=False)
    return render_template("history/index.html", page=page, p=params,
                           devices=Device.query.order_by(Device.device_name).all())


@bp.route("/export.csv")
@login_required
def export_csv():
    q, params, _err = _filtered()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["result_id", "device", "ip_address", "checked_at_local", "checked_at_utc", "reachable",
                "latency_ms", "packet_loss_percent", "uptime_24h_percent", "cpu_percent", "memory_percent",
                "method", "data_source", "error"])
    for r in q.limit(100_000):
        w.writerow([r.result_id, r.device.device_name, r.device.ip_address, fmt_dt(r.checked_at),
                    r.checked_at.isoformat() + "Z", "yes" if r.reachable else "no", r.latency_ms,
                    r.packet_loss_percent, r.uptime_percent, r.cpu_percent, r.memory_percent, r.method,
                    "SIMULATED" if r.method == "simulated" else "measured", r.error_message or ""])
    name = f"netwatch-history-{params['start']}_to_{params['end']}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
