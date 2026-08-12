from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, current_app)
from flask_login import login_required, current_user
from app.models import db, User
from app.decorators import admin_required

users_bp = Blueprint("users", __name__, url_prefix="/users")

ROLES = ["viewer", "operator", "admin"]


@users_bp.route("/")
@admin_required
def manage():
    users = User.query.order_by(User.name).all()
    return render_template("users/manage.html", users=users, roles=ROLES)


@users_bp.route("/new", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    name = request.form.get("name", "").strip()
    role = request.form.get("role", "viewer")
    password = request.form.get("password", "").strip()

    if not username or not email or not name or not password:
        flash("Username, email, name, and password are required.", "danger")
        return redirect(url_for("users.manage"))

    if len(password) < 12:
        flash("Password must be at least 12 characters.", "danger")
        return redirect(url_for("users.manage"))

    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' is already taken.", "danger")
        return redirect(url_for("users.manage"))

    if User.query.filter_by(email=email).first():
        flash(f"A user with email {email} already exists.", "danger")
        return redirect(url_for("users.manage"))

    if role not in ROLES:
        role = "viewer"

    user = User(username=username, email=email, name=name, role=role, is_active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash(f"User {name} created.", "success")
    return redirect(url_for("users.manage"))


@users_bp.route("/<int:user_id>/edit", methods=["POST"])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    # ── Validate everything before touching the record ───────────────────────
    submitted_role = request.form.get("role", user.role)
    if submitted_role not in ROLES:
        submitted_role = user.role
    submitted_active = request.form.get("is_active") in ("on", "true", "1")

    # An admin loses admin access two ways: the role dropdown, or the active
    # toggle. The old guard only watched the dropdown, so unchecking "active"
    # on the last admin locked everyone out of the application with no way
    # back in short of editing the database by hand. Both paths are covered now.
    losing_admin = user.role == "admin" and (
        submitted_role != "admin" or not submitted_active
    )
    if losing_admin:
        if user.id == current_user.id:
            flash(
                "You cannot remove your own admin access. Ask another admin to do it.",
                "danger",
            )
            return redirect(url_for("users.manage"))
        active_admins = User.query.filter_by(role="admin", is_active=True).count()
        if active_admins <= 1:
            flash("Cannot demote or deactivate the last active admin.", "danger")
            return redirect(url_for("users.manage"))

    new_username = request.form.get("username", "").strip().lower()
    if new_username and new_username != user.username:
        if User.query.filter(User.username == new_username, User.id != user.id).first():
            flash(f"Username '{new_username}' is already taken.", "danger")
            return redirect(url_for("users.manage"))

    new_password = request.form.get("password", "").strip()
    if new_password and len(new_password) < 12:
        flash("Password must be at least 12 characters.", "danger")
        return redirect(url_for("users.manage"))

    # ── Apply ────────────────────────────────────────────────────────────────
    if new_username and new_username != user.username:
        user.username = new_username
    user.name = request.form.get("name", user.name).strip()
    user.role = submitted_role
    user.is_active = submitted_active
    if new_password:
        user.set_password(new_password)

    db.session.commit()
    current_app.logger.info(
        "User %s updated by %s (role=%s, active=%s)",
        user.username or user.email, current_user.username or current_user.email,
        user.role, user.is_active,
    )
    flash(f"User {user.name} updated.", "success")
    return redirect(url_for("users.manage"))


@users_bp.route("/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users.manage"))

    if user.role == "admin" and user.is_active:
        admin_count = User.query.filter_by(role="admin", is_active=True).count()
        if admin_count <= 1:
            flash("Cannot deactivate the last active admin.", "danger")
            return redirect(url_for("users.manage"))

    user.is_active = False  # Soft delete to preserve audit references
    db.session.commit()
    flash(f"User {user.name} deactivated.", "warning")
    return redirect(url_for("users.manage"))
