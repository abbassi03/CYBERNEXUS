"""CYBERNEXUS application factory."""
from pathlib import Path
from flask import Flask, abort, current_app, g, redirect, request, url_for
from config import Config
from .db import close_db, init_db, get_db
from .security import csrf_token, current_user, validate_csrf, utcnow


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)

    from .auth.routes import bp as auth_bp
    from .dashboard.routes import bp as dashboard_bp
    from .events.routes import bp as events_bp
    from .incidents.routes import bp as incidents_bp
    from .assets.routes import bp as assets_bp
    from .reports.routes import bp as reports_bp
    from .api.routes import bp as api_bp
    from .audit.routes import bp as audit_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(audit_bp)

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
        _ensure_bootstrap_admin()

    @app.before_request
    def protect_requests():
        # API ingestion is authenticated by a separate API key and does not use browser CSRF.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint != "api.ingest_event":
            validate_csrf()
        user = current_user()
        if user and user["must_change_password"] and request.endpoint not in {
            "auth.profile", "auth.logout", "static"
        }:
            return redirect(url_for("auth.profile", required=1))

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        return response

    @app.context_processor
    def inject_globals():
        return {"csrf_token": csrf_token, "current_user": current_user(), "app_name": "CYBERNEXUS"}

    @app.errorhandler(403)
    def forbidden(_error):
        return _error_page("Access denied", "You do not have permission to perform this action.", 403)

    @app.errorhandler(404)
    def not_found(_error):
        return _error_page("Not found", "The page or record you requested does not exist.", 404)

    @app.errorhandler(400)
    def bad_request(error):
        return _error_page("Request rejected", getattr(error, "description", "The request could not be processed."), 400)

    @app.errorhandler(500)
    def internal_error(_error):
        get_db().rollback()
        return _error_page("Something went wrong", "An unexpected error occurred. Check the application log for details.", 500)

    return app


def _ensure_bootstrap_admin():
    from werkzeug.security import generate_password_hash
    db = get_db()
    count = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count == 0:
        password = current_app.config.get("BOOTSTRAP_ADMIN_PASSWORD") or "CyberNexus@2026"
        db.execute(
            "INSERT INTO users(email,full_name,password_hash,role,active,must_change_password,created_at) VALUES(?,?,?,?,?,?,?)",
            ("admin@cybernexus.local", "CYBERNEXUS Administrator", generate_password_hash(password), "admin", 1, 1, utcnow()),
        )
        db.commit()
        current_app.logger.warning("Bootstrap admin created. Change the temporary password after first login.")


def _error_page(title, message, status):
    from flask import render_template
    return render_template("error.html", title=title, message=message, status=status), status
