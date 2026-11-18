from flask import Blueprint, render_template
from ..db import get_db
from ..security import roles_required

bp = Blueprint("audit", __name__, url_prefix="/audit")


@bp.get("/")
@roles_required("admin")
def index():
    rows = get_db().execute(
        "SELECT l.*,u.full_name,u.email FROM audit_logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC,l.id DESC LIMIT 300"
    ).fetchall()
    return render_template("audit/index.html", title="Audit trail", logs=rows)
