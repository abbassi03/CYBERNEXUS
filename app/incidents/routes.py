from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from ..db import get_db
from ..security import login_required, roles_required, audit, utcnow

bp = Blueprint("incidents", __name__, url_prefix="/incidents")


@bp.get("/")
@login_required
def index():
    status = request.args.get("status", "")
    clauses, params = [], []
    if status in {"open", "investigating", "contained", "resolved", "closed"}:
        clauses.append("i.status=?")
        params.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = get_db().execute(
        f"SELECT i.*,u.full_name AS assignee,e.source_ip FROM incidents i LEFT JOIN users u ON u.id=i.assigned_to LEFT JOIN events e ON e.id=i.event_id{where} ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,i.updated_at DESC LIMIT 200",
        params,
    ).fetchall()
    users = get_db().execute("SELECT id,full_name FROM users WHERE active=1 ORDER BY full_name").fetchall()
    return render_template("incidents/index.html", title="Incident response", incidents=rows, users=users, selected_status=status)


@bp.post("/new")
@roles_required("admin", "analyst")
def create():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    severity = request.form.get("severity", "medium")
    if not title or len(title) > 160 or severity not in {"low", "medium", "high", "critical"}:
        flash("Enter a title (max 160 characters) and valid severity.", "danger")
    else:
        db = get_db()
        cur = db.execute(
            "INSERT INTO incidents(title,description,severity,priority,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (title, description[:2000], severity, severity, "open", utcnow(), utcnow()),
        )
        db.commit()
        audit("incident_created", "incident", cur.lastrowid, title)
        flash("Incident created.", "success")
    return redirect(url_for("incidents.index"))


@bp.post("/<int:incident_id>/update")
@roles_required("admin", "analyst")
def update(incident_id):
    status = request.form.get("status", "")
    priority = request.form.get("priority", "")
    assigned_to = request.form.get("assigned_to") or None
    if status not in {"open", "investigating", "contained", "resolved", "closed"} or priority not in {"low", "medium", "high", "critical"}:
        flash("Invalid incident status or priority.", "danger")
        return redirect(url_for("incidents.index"))
    try:
        assigned_to = int(assigned_to) if assigned_to else None
    except ValueError:
        flash("Invalid assignee.", "danger")
        return redirect(url_for("incidents.index"))
    db = get_db()
    if assigned_to and not db.execute("SELECT id FROM users WHERE id=? AND active=1", (assigned_to,)).fetchone():
        flash("Selected assignee is not active.", "danger")
        return redirect(url_for("incidents.index"))
    closed_at = utcnow() if status in {"resolved", "closed"} else None
    cur = db.execute(
        "UPDATE incidents SET status=?,priority=?,assigned_to=?,updated_at=?,closed_at=? WHERE id=?",
        (status, priority, assigned_to, utcnow(), closed_at, incident_id),
    )
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    audit("incident_updated", "incident", incident_id, f"status={status}; priority={priority}")
    flash("Incident updated.", "success")
    return redirect(url_for("incidents.index"))
