import csv
import io
from flask import Blueprint, Response, render_template
from ..db import get_db
from ..security import login_required

bp = Blueprint("reports", __name__, url_prefix="/reports")


def safe_csv_cell(value):
    """Mitigate spreadsheet formula injection for untrusted string values."""
    if value is None:
        return ""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


@bp.get("/")
@login_required
def index():
    db = get_db()
    severity = db.execute("SELECT severity,COUNT(*) AS total FROM events GROUP BY severity").fetchall()
    status = db.execute("SELECT status,COUNT(*) AS total FROM incidents GROUP BY status").fetchall()
    top_sources = db.execute("SELECT source_ip,COUNT(*) AS total,MAX(risk_score) AS max_risk FROM events GROUP BY source_ip ORDER BY total DESC LIMIT 8").fetchall()
    severity_total = sum(int(row["total"]) for row in severity) or 1
    status_total = sum(int(row["total"]) for row in status) or 1
    return render_template("reports/index.html", title="Reports & analytics", severity=severity, status=status, top_sources=top_sources, severity_total=severity_total, status_total=status_total)


@bp.get("/events.csv")
@login_required
def export_events():
    rows = get_db().execute(
        "SELECT id,event_time,source_ip,destination_ip,event_type,severity,status,description,source,risk_score,detection_reason FROM events ORDER BY event_time DESC"
    ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "event_time", "source_ip", "destination_ip", "event_type", "severity", "status", "description", "source", "risk_score", "detection_reason"])
    for row in rows:
        writer.writerow([safe_csv_cell(row[key]) for key in row.keys()])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=cybernexus-events.csv"})
