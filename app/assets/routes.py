import ipaddress
from flask import Blueprint, render_template, request, redirect, url_for, flash
from ..db import get_db
from ..security import login_required, roles_required, audit, utcnow

bp = Blueprint("assets", __name__, url_prefix="/assets")


@bp.get("/")
@login_required
def index():
    rows = get_db().execute(
        "SELECT a.*,COUNT(e.id) AS event_count FROM assets a LEFT JOIN events e ON e.asset_id=a.id GROUP BY a.id ORDER BY CASE a.criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,a.name"
    ).fetchall()
    return render_template("assets/index.html", title="Asset inventory", assets=rows)


@bp.post("/new")
@roles_required("admin", "analyst")
def create():
    name = request.form.get("name", "").strip()
    ip = request.form.get("ip_address", "").strip()
    asset_type = request.form.get("asset_type", "server").strip()
    criticality = request.form.get("criticality", "medium")
    owner = request.form.get("owner", "").strip()[:100]
    notes = request.form.get("notes", "").strip()[:500]
    allowed_types = {"server", "workstation", "network", "cloud", "database", "application", "other"}
    if not name or len(name) > 120 or asset_type not in allowed_types or criticality not in {"low", "medium", "high", "critical"}:
        flash("Enter a valid asset name, type, and criticality.", "danger")
    else:
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                flash("Enter a valid IPv4 or IPv6 address.", "danger")
                return redirect(url_for("assets.index"))
        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO assets(name,ip_address,asset_type,criticality,owner,notes,created_at) VALUES(?,?,?,?,?,?,?)",
                (name, ip, asset_type, criticality, owner, notes, utcnow()),
            )
            db.commit()
            audit("asset_created", "asset", cur.lastrowid, name)
            flash("Asset added to inventory.", "success")
        except Exception:
            db.rollback()
            flash("Could not add asset. The asset name may already exist.", "danger")
    return redirect(url_for("assets.index"))
