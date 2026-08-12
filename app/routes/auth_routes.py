from datetime import datetime, timezone
from urllib.parse import urlsplit
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, current_app)
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User
from app.extensions import limiter

auth_bp = Blueprint("auth", __name__)


def _safe_next(next_url: str) -> str:
    """Return next_url only if it's a relative path on this host; else dashboard."""
    if not next_url:
        return url_for("dashboard.index")
    parsed = urlsplit(next_url)
    if parsed.scheme or parsed.netloc:
        return url_for("dashboard.index")
    return next_url


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["LOGIN_RATE_LIMIT"],
    methods=["POST"],
    error_message="Too many sign-in attempts.",
)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.password_hash and user.check_password(password):
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            login_user(user, remember=remember)
            next_page = _safe_next(request.args.get("next", ""))
            return redirect(next_page)

        current_app.logger.warning(
            "Failed login for username=%r from %s", username, request.remote_addr
        )
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ── OIDC flow ────────────────────────────────────────────────────────────────

def _role_from_groups(groups: list, cfg) -> str | None:
    admin_grp = cfg.get("OIDC_ADMIN_GROUP", "")
    op_grp = cfg.get("OIDC_OPERATOR_GROUP", "")
    viewer_grp = cfg.get("OIDC_VIEWER_GROUP", "")

    if not any([admin_grp, op_grp, viewer_grp]):
        return "viewer"

    if admin_grp and admin_grp in groups:
        return "admin"
    if op_grp and op_grp in groups:
        return "operator"
    if viewer_grp and viewer_grp in groups:
        return "viewer"

    return None


@auth_bp.route("/auth/oidc/login")
def oidc_login():
    oauth = current_app.extensions.get("oauth")
    if not oauth:
        flash("SSO is not configured.", "danger")
        return redirect(url_for("auth.login"))
    redirect_uri = url_for("auth.oidc_callback", _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/oidc/callback")
def oidc_callback():
    oauth = current_app.extensions.get("oauth")
    if not oauth:
        return redirect(url_for("auth.login"))

    try:
        token = oauth.oidc.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.oidc.userinfo()
    except Exception as exc:
        current_app.logger.error("OIDC callback error: %s", exc)
        flash("SSO login failed. Please try again.", "danger")
        return redirect(url_for("auth.login"))

    sub = userinfo.get("sub")
    email = userinfo.get("email", "").lower()
    name = userinfo.get("name") or email

    groups = userinfo.get("groups") or token.get("groups") or []
    if not groups and "_claim_names" in userinfo and "groups" in userinfo["_claim_names"]:
        current_app.logger.warning(
            "OIDC: groups claim omitted for %s (>150 groups / overage). "
            "Configure a dedicated app group in Azure AD to stay under the limit.",
            email,
        )

    role = _role_from_groups(groups, current_app.config)
    if role is None:
        current_app.logger.warning(
            "OIDC login denied for %s — not a member of any authorised group.", email
        )
        flash(
            "Your account is not authorised to access this application. "
            "Contact an administrator.",
            "danger",
        )
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(oidc_sub=sub).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user:
            user.oidc_sub = sub
        else:
            user = User(email=email, name=name, oidc_sub=sub, role=role, is_active=True)
            db.session.add(user)

    if not user.is_active:
        flash("Your account is disabled. Contact an administrator.", "danger")
        return redirect(url_for("auth.login"))

    if any([
        current_app.config.get("OIDC_ADMIN_GROUP"),
        current_app.config.get("OIDC_OPERATOR_GROUP"),
        current_app.config.get("OIDC_VIEWER_GROUP"),
    ]):
        user.role = role

    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    login_user(user)
    return redirect(url_for("dashboard.index"))
