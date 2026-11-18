from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, g
from werkzeug.security import check_password_hash, generate_password_hash
from ..db import get_db
from ..security import current_user, audit, login_required, roles_required, utcnow

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:180]
        password = request.form.get("password", "")
        db = get_db()
        ip_address = request.remote_addr or "unknown"
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        attempts = db.execute(
            "SELECT COUNT(*) AS n FROM login_attempts WHERE email=? AND ip_address=? AND attempted_at>=?",
            (email, ip_address, cutoff),
        ).fetchone()["n"]
        if attempts >= 5:
            flash("Too many sign-in attempts. Wait 15 minutes before trying again.", "danger")
            return render_template("auth/login.html", title="Sign in"), 429
        user = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            db.execute("DELETE FROM login_attempts WHERE email=? AND ip_address=?", (email, ip_address))
            db.commit()
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            g._current_user_loaded = False
            g._current_user = None
            audit("login", "user", user["id"], "Successful sign-in")
            if user["must_change_password"]:
                flash("For security, set a new password before continuing.", "warning")
                return redirect(url_for("auth.profile", required=1))
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            flash(f"Welcome back, {user['full_name'].split()[0]}.", "success")
            return redirect(url_for("dashboard.index"))
        db.execute(
            "INSERT INTO login_attempts(email,ip_address,attempted_at) VALUES(?,?,?)",
            (email, ip_address, datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
        )
        db.commit()
        audit("login_failed", "user", None, f"Failed sign-in for {email}")
        flash("Invalid email or password.", "danger")
    return render_template("auth/login.html", title="Sign in")


@bp.post("/logout")
@login_required
def logout():
    audit("logout", "user", current_user()["id"], "Signed out")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        record = get_db().execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
        if not check_password_hash(record["password_hash"], old_password):
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < 12 or not any(c.isalpha() for c in new_password) or not any(c.isdigit() for c in new_password):
            flash("Use at least 12 characters, including letters and numbers.", "warning")
        elif new_password != confirm:
            flash("New password and confirmation do not match.", "danger")
        elif new_password == old_password:
            flash("Choose a password different from the current one.", "warning")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?", (generate_password_hash(new_password), user["id"]))
            db.commit()
            audit("password_changed", "user", user["id"], "Password updated")
            flash("Password updated successfully.", "success")
            return redirect(url_for("dashboard.index"))
    return render_template("auth/profile.html", title="My profile", required=request.args.get("required") == "1")


@bp.route("/admin/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "analyst")
        temp_password = request.form.get("temporary_password", "")
        if not full_name or len(full_name) > 100 or "@" not in email or len(email) > 180:
            flash("Enter a valid name and email address.", "danger")
        elif role not in {"admin", "analyst", "viewer"}:
            flash("Invalid role selected.", "danger")
        elif len(temp_password) < 12 or not any(c.isdigit() for c in temp_password):
            flash("Temporary password must be at least 12 characters and include a number.", "warning")
        else:
            try:
                cur = db.execute(
                    "INSERT INTO users(email,full_name,password_hash,role,active,must_change_password,created_at) VALUES(?,?,?,?,1,1,?)",
                    (email, full_name, generate_password_hash(temp_password), role, utcnow()),
                )
                db.commit()
                audit("user_created", "user", cur.lastrowid, f"Created {email} with role {role}")
                flash("User created. They must change the temporary password at first sign-in.", "success")
                return redirect(url_for("auth.users"))
            except Exception:
                db.rollback()
                flash("Could not create user. The email may already exist.", "danger")
    rows = db.execute("SELECT id,email,full_name,role,active,created_at FROM users ORDER BY created_at DESC").fetchall()
    return render_template("auth/users.html", title="User management", users=rows)
