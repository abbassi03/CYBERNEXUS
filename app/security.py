"""Authentication, authorization, CSRF protection, and audit helpers."""
from functools import wraps
import secrets
from datetime import datetime, timezone
from flask import abort, g, redirect, request, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if request.is_json and not supplied:
        supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400, description="Invalid or missing CSRF token. Refresh the page and try again.")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    if getattr(g, "_current_user_loaded", False):
        return g._current_user
    row = get_db().execute(
        "SELECT id,email,full_name,role,active,must_change_password FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    g._current_user = row if row and row["active"] else None
    g._current_user_loaded = True
    return g._current_user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(action, entity_type, entity_id=None, detail=""):
    user = current_user()
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs(user_id,action,entity_type,entity_id,detail,ip_address,created_at) VALUES(?,?,?,?,?,?,?)",
        (user["id"] if user else None, action, entity_type, entity_id, str(detail)[:500], request.remote_addr or "", utcnow()),
    )
    db.commit()
