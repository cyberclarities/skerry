import logging
from flask import Flask, render_template, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from .config import Config, PLACEHOLDER_SECRETS
from .extensions import limiter
from .models import db, User
# Imported for its side effect: registering the Spotlight ingest tables on
# the same metadata, so db.create_all() below creates them. Additive only --
# no existing table is altered. See app/models_spotlight.py.
from . import models_spotlight  # noqa: F401

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Refuse to start on an unset or placeholder signing key. A predictable
    # SECRET_KEY means anyone can forge a session cookie and walk in as admin,
    # so this is a hard stop rather than a warning in the log.
    if str(app.config.get("SECRET_KEY", "")).strip() in PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "SECRET_KEY is unset or still a placeholder. Generate one with:\n"
            "    python -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
            "then set it in your .env before starting the app."
        )

    # Trust one layer of reverse-proxy headers (Caddy sets X-Forwarded-Proto).
    # This makes request.is_secure correct when running behind Caddy.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        # user_id is "<id>:<stamp>" (see User.get_id). A cookie from before a
        # password change carries the old stamp and is refused. Bare ids from
        # before this format existed are refused too: one forced sign-in.
        import hmac
        uid, _, stamp = str(user_id).partition(":")
        if not uid.isdigit() or not stamp:
            return None
        user = db.session.get(User, int(uid))
        if user is None or not hmac.compare_digest(stamp, user.session_stamp()):
            return None
        return user

    # Blueprints
    from .routes.auth_routes import auth_bp
    from .routes.risk_routes import risks_bp
    from .routes.dashboard_routes import dashboard_bp
    from .routes.user_routes import users_bp
    from .routes.report_routes import reports_bp
    from .routes.export_routes import exports_bp
    from .routes.settings_routes import settings_bp
    from .routes.ingest_routes import ingest_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(risks_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(exports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(ingest_bp)

    # Security headers on every response
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Only send HSTS when the connection actually arrived over HTTPS.
        # ProxyFix above makes request.is_secure correct behind Caddy.
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Health endpoint (no auth)
    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("429.html"), 429

    # OIDC (optional)
    if app.config.get("OIDC_CLIENT_ID"):
        _setup_oidc(app)

    # DB init + seed
    with app.app_context():
        db.create_all()
        from .seed import seed_nist_csf, seed_admin, seed_lookup_defaults
        from .models import NISTCSFReference, LookupItem
        seed_nist_csf(db, NISTCSFReference)
        seed_admin(db, User, app)
        seed_lookup_defaults(db, LookupItem)

        # Spotlight queue upkeep: merge duplicate host+CVE rows and drop
        # findings below the configured severities. No-op once clean.
        from .spotlight.maintenance import dedupe_and_prune
        dedupe_and_prune(app.config.get("SPOTLIGHT_SEVERITIES") or ("CRITICAL", "HIGH"))

    # Background scheduler for email notifications and the Spotlight pull
    if app.config.get("SMTP_HOST") or app.config.get("SPOTLIGHT_SYNC_ENABLED"):
        _start_scheduler(app)

    # Template globals
    @app.context_processor
    def inject_globals():
        return {
            "oidc_enabled": bool(app.config.get("OIDC_CLIENT_ID")),
        }

    logging.basicConfig(level=logging.INFO)
    return app


def _setup_oidc(app):
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    oauth.register(
        name="oidc",
        client_id=app.config["OIDC_CLIENT_ID"],
        client_secret=app.config["OIDC_CLIENT_SECRET"],
        server_metadata_url=app.config["OIDC_DISCOVERY_URL"],
        client_kwargs={"scope": "openid email profile"},
    )
    app.extensions["oauth"] = oauth


def _start_scheduler(app):
    """Background jobs: daily notification email, nightly Spotlight pull.

    Each job is added only when its own config says so, so enabling the
    Spotlight sync does not switch on notification email as a side effect,
    and a deployment with neither configured starts no scheduler at all.
    """
    try:
        from apscheduler.schedulers.background import BackgroundScheduler

        scheduler = BackgroundScheduler()

        if app.config.get("SMTP_HOST"):
            from .email_utils import run_daily_notifications
            scheduler.add_job(
                func=run_daily_notifications,
                args=[app],
                trigger="cron",
                hour=7,
                minute=0,
                id="daily_notifications",
                replace_existing=True,
            )

        if app.config.get("SPOTLIGHT_SYNC_ENABLED"):
            from .spotlight.ingest import run_sync_job
            scheduler.add_job(
                func=run_sync_job,
                args=[app],
                trigger="cron",
                hour=int(app.config.get("SPOTLIGHT_SYNC_HOUR", 5)),
                minute=int(app.config.get("SPOTLIGHT_SYNC_MINUTE", 30)),
                id="spotlight_sync",
                replace_existing=True,
                # A pull against a large tenant can outlast its own window.
                # Skip the next fire rather than stacking two syncs writing
                # the same rows.
                max_instances=1,
                coalesce=True,
                misfire_grace_time=3600,
            )
            app.logger.info(
                "Spotlight sync scheduled daily at %02d:%02d",
                app.config.get("SPOTLIGHT_SYNC_HOUR", 5),
                app.config.get("SPOTLIGHT_SYNC_MINUTE", 30),
            )

        if not scheduler.get_jobs():
            return

        scheduler.start()
        import atexit
        atexit.register(lambda: scheduler.shutdown())
    except Exception as exc:
        app.logger.warning("Scheduler failed to start: %s", exc)
