import csv
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from ..db import get_db
from ..security import login_required, roles_required, audit
from ..services.events import store_event

bp = Blueprint("events", __name__, url_prefix="/events")


@bp.get("/")
@login_required
def index():
    db = get_db()
    severity = request.args.get("severity", "").lower()
    query = request.args.get("q", "").strip()[:100]
    clauses, params = [], []
    if severity in {"low", "medium", "high", "critical"}:
        clauses.append("e.severity=?")
        params.append(severity)
    if query:
        clauses.append("(e.source_ip LIKE ? OR e.destination_ip LIKE ? OR e.description LIKE ? OR e.event_type LIKE ?)")
        params.extend([f"%{query}%"] * 4)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = db.execute(
        f"SELECT e.*,a.name AS asset_name FROM events e LEFT JOIN assets a ON a.id=e.asset_id{where} ORDER BY e.event_time DESC,e.id DESC LIMIT 200",
        params,
    ).fetchall()
    assets = db.execute("SELECT id,name FROM assets ORDER BY name").fetchall()
    return render_template("events/index.html", title="Security events", events=rows, assets=assets, selected_severity=severity, query=query)


@bp.post("/new")
@roles_required("admin", "analyst")
def create():
    try:
        row = store_event(request.form)
        audit("event_created", "event", row["id"], f"{row['event_type']} / {row['severity']}")
        flash("Security event recorded and evaluated by the detection rules.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("events.index"))


@bp.post("/import")
@roles_required("admin", "analyst")
def import_csv():
    upload = request.files.get("file")
    if not upload or not upload.filename.lower().endswith(".csv"):
        flash("Choose a CSV file to import.", "warning")
        return redirect(url_for("events.index"))
    try:
        stream = io.StringIO(upload.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.DictReader(stream)
        required = {"source_ip", "event_type", "severity", "description"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("CSV must contain: source_ip, event_type, severity, description. Optional: destination_ip, event_time, source.")
        inserted, errors = 0, []
        for number, record in enumerate(reader, start=2):
            if number > 1002:
                errors.append("Import stopped at 1000 rows.")
                break
            try:
                store_event(record)
                inserted += 1
            except ValueError as exc:
                errors.append(f"Row {number}: {exc}")
                if len(errors) >= 8:
                    break
        audit("events_imported", "event", None, f"Imported {inserted} event(s); errors: {len(errors)}")
        flash(f"Imported {inserted} event(s)." + (f" First issues: {' | '.join(errors)}" if errors else ""), "success" if not errors else "warning")
    except (UnicodeDecodeError, ValueError) as exc:
        flash(f"Import failed: {exc}", "danger")
    return redirect(url_for("events.index"))


@bp.get("/<int:event_id>")
@login_required
def detail(event_id):
    row = get_db().execute(
        "SELECT e.*,a.name AS asset_name FROM events e LEFT JOIN assets a ON a.id=e.asset_id WHERE e.id=?", (event_id,)
    ).fetchone()
    if not row:
        abort(404)
    incident = get_db().execute("SELECT id,title,status FROM incidents WHERE event_id=?", (event_id,)).fetchone()
    return render_template("events/detail.html", title=f"Event #{event_id}", event=row, incident=incident)


@bp.post("/<int:event_id>/status")
@roles_required("admin", "analyst")
def update_status(event_id):
    status = request.form.get("status", "")
    if status not in {"new", "investigating", "resolved", "false_positive"}:
        flash("Invalid event status.", "danger")
    else:
        db = get_db()
        cur = db.execute("UPDATE events SET status=? WHERE id=?", (status, event_id))
        db.commit()
        if cur.rowcount == 0:
            abort(404)
        audit("event_status_updated", "event", event_id, status)
        flash("Event status updated.", "success")
    return redirect(url_for("events.detail", event_id=event_id))
