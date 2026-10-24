"""Report generation (FR12, Fig 3.4 process 5.0) — descriptive statistics per §3.10,
exportable as CSV and PDF."""
import csv
import io

from flask import Blueprint, Response, current_app, flash, render_template, request
from flask_login import current_user, login_required

from ..models import Alert, Device, utcnow
from ..services import audit, stats
from ..utils import date_range_from_args, fmt_dt

bp = Blueprint("reports", __name__, url_prefix="/reports")


def _build():
    s, e, sd, ed, err = date_range_from_args(default_days=7)
    ids = [int(x) for x in request.args.getlist("device") if x.isdigit()]
    devices = Device.query.order_by(Device.device_name)
    if ids:
        devices = devices.filter(Device.device_id.in_(ids))
    rows = [(d, stats.device_summary(d.device_id, s, e)) for d in devices.all()]
    measured = [r for _d, r in rows if r["checks"]]
    total_checks = sum(r["checks"] for r in measured)
    totals = {
        "devices": len(rows), "checks": total_checks,
        "uptime": round(sum(r["successful"] for r in measured) / total_checks * 100, 2) if total_checks else None,
        "alerts": Alert.query.filter(Alert.opened_at >= s, Alert.opened_at <= e,
                                     Alert.device_id.in_([d.device_id for d, _ in rows] or [-1])).count(),
        "simulated": sum(1 for d, _ in rows if d.is_simulated),
    }
    return {"rows": rows, "totals": totals, "start": sd, "end": ed, "start_utc": s, "end_utc": e,
            "selected": ids, "error": err}


@bp.route("/")
@login_required
def index():
    rep = _build()
    if rep["error"]:
        flash(rep["error"], "warning")
    return render_template("reports/index.html", r=rep, devices=Device.query.order_by(Device.device_name).all(),
                           generated=utcnow())


def _fname(rep, ext):
    return f"netwatch-report-{rep['start'].isoformat()}_to_{rep['end'].isoformat()}.{ext}"


@bp.route("/export.csv")
@login_required
def export_csv():
    rep = _build()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Netwatch network performance report"])
    w.writerow(["Period (local)", rep["start"].isoformat(), rep["end"].isoformat()])
    w.writerow(["Generated", fmt_dt(utcnow())])
    w.writerow([])
    w.writerow(["device", "ip_address", "type", "data_source", "checks", "successful", "failed", "uptime_percent",
                "latency_min_ms", "latency_avg_ms", "latency_max_ms", "loss_min_percent", "loss_avg_percent",
                "loss_max_percent", "alerts_opened", "methods"])
    for d, s in rep["rows"]:
        w.writerow([d.device_name, d.ip_address, d.type_label, "SIMULATED" if d.is_simulated else "measured",
                    s["checks"], s["successful"], s["failed"], s["uptime"], s["latency_min"], s["latency_avg"],
                    s["latency_max"], s["loss_min"], s["loss_avg"], s["loss_max"], s["alerts"],
                    "/".join(s["methods"])])
    audit.record("report_exported", "report", None, f"CSV {rep['start']}–{rep['end']}", commit=True)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{_fname(rep, "csv")}"'})


@bp.route("/export.pdf")
@login_required
def export_pdf():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    rep = _build()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm, title="Netwatch performance report",
                            author=current_user.username)
    ss = getSampleStyleSheet()
    navy = colors.HexColor("#0f2240")
    story = [Paragraph("Netwatch — Network Performance Report", ss["Title"]),
             Paragraph(f"Period: {rep['start']:%d %b %Y} to {rep['end']:%d %b %Y} "
                       f"(times in {current_app.config['DISPLAY_TIMEZONE']}) · "
                       f"Generated {fmt_dt(utcnow())} by {current_user.username}", ss["Normal"]),
             Spacer(1, 6)]
    t = rep["totals"]
    overall = "—" if t["uptime"] is None else f"{t['uptime']:.2f}%"
    story.append(Paragraph(
        f"<b>Devices:</b> {t['devices']} &nbsp; <b>Checks:</b> {t['checks']:,} &nbsp; "
        f"<b>Overall uptime:</b> {overall} &nbsp; <b>Alerts opened:</b> {t['alerts']}", ss["Normal"]))
    if t["simulated"]:
        story.append(Paragraph(f"<font color='#6b3fa0'><b>Note:</b> {t['simulated']} device(s) in this report "
                               "are SIMULATED demonstration devices; their figures are synthetic and are not real "
                               "network observations.</font>", ss["Normal"]))
    story.append(Spacer(1, 8))

    def f(v, suf=""):
        return "—" if v is None else f"{v:,.2f}{suf}"

    data = [["Device", "Address", "Source", "Checks", "Uptime", "Latency min / avg / max (ms)",
             "Loss avg / max (%)", "Alerts"]]
    for d, s in rep["rows"]:
        data.append([Paragraph(d.device_name, ss["BodyText"]), d.ip_address,
                     "Simulated" if d.is_simulated else "Measured", f"{s['checks']:,}", f(s["uptime"], "%"),
                     f"{f(s['latency_min'])} / {f(s['latency_avg'])} / {f(s['latency_max'])}",
                     f"{f(s['loss_avg'])} / {f(s['loss_max'])}", str(s["alerts"])])
    if len(data) == 1:
        data.append(["No devices match the selection", "", "", "", "", "", "", ""])
    tbl = Table(data, repeatRows=1, colWidths=[60 * mm, 34 * mm, 22 * mm, 18 * mm, 20 * mm, 52 * mm, 34 * mm,
                                               16 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c9d2de")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
    ]))
    story += [tbl, Spacer(1, 10),
              Paragraph("Uptime = successful checks ÷ total checks in the period. Latency and packet-loss statistics "
                        "are computed from stored monitoring results (minimum, mean, maximum).", ss["Italic"])]
    doc.build(story)
    audit.record("report_exported", "report", None, f"PDF {rep['start']}–{rep['end']}", commit=True)
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{_fname(rep, "pdf")}"'})
