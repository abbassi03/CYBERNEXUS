from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template
from ..db import get_db
from ..security import login_required

bp = Blueprint("dashboard", __name__)


@bp.get("/")
@login_required
def index():
    db = get_db()
    metrics = {
        "events": db.execute("SELECT COUNT(*) n FROM events").fetchone()["n"],
        "open_incidents": db.execute("SELECT COUNT(*) n FROM incidents WHERE status NOT IN ('resolved','closed')").fetchone()["n"],
        "critical_events": db.execute("SELECT COUNT(*) n FROM events WHERE severity='critical' AND status!='resolved'").fetchone()["n"],
        "assets": db.execute("SELECT COUNT(*) n FROM assets").fetchone()["n"],
    }
    severities = db.execute("SELECT severity,COUNT(*) AS total FROM events GROUP BY severity").fetchall()
    severity_map = {r["severity"]: r["total"] for r in severities}
    total_severity = max(sum(severity_map.values()), 1)
    severity_rows = [
        {"name": name.title(), "total": severity_map.get(name, 0), "pct": round(severity_map.get(name, 0) * 100 / total_severity)}
        for name in ("critical", "high", "medium", "low")
    ]
    recent_events = db.execute(
        "SELECT e.*,a.name AS asset_name FROM events e LEFT JOIN assets a ON a.id=e.asset_id ORDER BY e.event_time DESC,e.id DESC LIMIT 8"
    ).fetchall()
    recent_incidents = db.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT 6").fetchall()
    trend_rows = db.execute(
        "SELECT substr(event_time,1,10) AS day,COUNT(*) AS total FROM events WHERE event_time>=? GROUP BY day ORDER BY day",
        ((datetime.now(timezone.utc) - timedelta(days=6)).date().isoformat(),),
    ).fetchall()
    trend_map = {r["day"]: r["total"] for r in trend_rows}
    trends = []
    for offset in range(6, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=offset)).date()
        trends.append({"label": day.strftime("%a"), "total": trend_map.get(day.isoformat(), 0)})
    max_trend = max([x["total"] for x in trends] + [1])
    for item in trends:
        item["height"] = max(6, int(item["total"] * 100 / max_trend))
    return render_template("dashboard/index.html", title="Security overview", metrics=metrics,
                           severity_rows=severity_rows, recent_events=recent_events,
                           recent_incidents=recent_incidents, trends=trends)
