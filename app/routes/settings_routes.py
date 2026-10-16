import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone

from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, send_file, current_app)
from flask_login import current_user
from app.models import db, LookupItem
from app.decorators import admin_required


def _back(category=None):
    """Redirect to the settings page, landing on the correct tab if known."""
    base = url_for("settings.manage")
    if category:
        return redirect(f"{base}#tab-{category}")
    return redirect(base)

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")

# Human-readable labels for each managed category
LOOKUP_CATEGORIES = {
    "threat_actor_type": "Threat Actor Types",
    "attack_vector":     "Attack Vectors",
    "threat_intel_source": "Threat Intel Sources",
    "risk_owner":        "Risk Owners",
}


@settings_bp.route("/")
@admin_required
def manage():
    items = (
        LookupItem.query
        .filter(LookupItem.category.in_(LOOKUP_CATEGORIES.keys()))
        .order_by(LookupItem.category, LookupItem.display_order, LookupItem.value)
        .all()
    )
    grouped = {cat: [] for cat in LOOKUP_CATEGORIES}
    for item in items:
        grouped[item.category].append(item)

    return render_template(
        "settings/manage.html",
        grouped=grouped,
        labels=LOOKUP_CATEGORIES,
    )


@settings_bp.route("/lookup/add", methods=["POST"])
@admin_required
def add_item():
    category = request.form.get("category", "").strip()
    value = request.form.get("value", "").strip()

    if category not in LOOKUP_CATEGORIES:
        flash("Invalid category.", "danger")
        return _back()

    if not value:
        flash("Value cannot be blank.", "danger")
        return _back(category)

    existing = LookupItem.query.filter_by(category=category, value=value).first()
    if existing:
        if not existing.is_active:
            existing.is_active = True
            db.session.commit()
            flash(f"'{value}' re-enabled.", "success")
        else:
            flash(f"'{value}' already exists in {LOOKUP_CATEGORIES[category]}.", "warning")
        return _back(category)

    max_order = db.session.query(db.func.max(LookupItem.display_order)).filter_by(
        category=category
    ).scalar() or 0

    item = LookupItem(category=category, value=value, display_order=max_order + 1)
    db.session.add(item)
    db.session.commit()
    flash(f"'{value}' added to {LOOKUP_CATEGORIES[category]}.", "success")
    return _back(category)


@settings_bp.route("/lookup/<int:item_id>/edit", methods=["POST"])
@admin_required
def edit_item(item_id):
    item = db.get_or_404(LookupItem, item_id)
    new_value = request.form.get("value", "").strip()

    if not new_value:
        flash("Value cannot be blank.", "danger")
        return _back(item.category)

    conflict = LookupItem.query.filter(
        LookupItem.category == item.category,
        LookupItem.value == new_value,
        LookupItem.id != item.id,
    ).first()
    if conflict:
        flash(f"'{new_value}' already exists in that list.", "warning")
        return _back(item.category)

    item.value = new_value
    db.session.commit()
    flash(f"Updated to '{new_value}'.", "success")
    return _back(item.category)


@settings_bp.route("/lookup/<int:item_id>/delete", methods=["POST"])
@admin_required
def delete_item(item_id):
    item = db.get_or_404(LookupItem, item_id)
    category = item.category
    item.is_active = False  # soft-delete so existing risk records aren't orphaned
    db.session.commit()
    flash(f"'{item.value}' removed from {LOOKUP_CATEGORIES.get(category, category)}.", "warning")
    return _back(category)


@settings_bp.route("/db/download")
@admin_required
def db_download():
    """Stream the live SQLite database as a timestamped file download."""
    from sqlalchemy.engine import make_url
    url = make_url(current_app.config["SQLALCHEMY_DATABASE_URI"])
    db_path = url.database

    if not os.path.isfile(db_path):
        flash("Database file not found on disk.", "danger")
        return _back("database")

    # The file holds password hashes and raw Falcon payloads. Leave a trace.
    current_app.logger.warning(
        "AUDIT database downloaded by %s (user id %s) from %s",
        current_user.username or current_user.email, current_user.id,
        request.remote_addr,
    )
    filename = f"risk_register_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(
        db_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )


@settings_bp.route("/db/import", methods=["POST"])
@admin_required
def db_import():
    """Replace the live database with an uploaded SQLite file."""
    from sqlalchemy.engine import make_url

    current_app.logger.warning(
        "AUDIT database import attempted by %s (user id %s) from %s",
        current_user.username or current_user.email, current_user.id,
        request.remote_addr,
    )
    uploaded = request.files.get("db_file")
    if not uploaded or not uploaded.filename:
        flash("No file selected.", "danger")
        return _back("database")

    if not uploaded.filename.lower().endswith(".db"):
        flash("File must have a .db extension.", "danger")
        return _back("database")

    # Write to a temp file so we can validate before touching anything live.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
    try:
        os.close(tmp_fd)
        uploaded.save(tmp_path)

        # Validate SQLite magic bytes.
        with open(tmp_path, "rb") as f:
            magic = f.read(16)
        if not magic.startswith(b"SQLite format 3"):
            flash("Uploaded file is not a valid SQLite database.", "danger")
            return _back("database")

        # Validate that all expected tables are present.
        conn = sqlite3.connect(tmp_path)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            conn.close()

        required = {
            "users", "risks", "audit_log", "trend_log",
            "vulnerability_findings", "nist_csf_reference", "lookup_items",
        }
        missing = required - tables
        if missing:
            flash(
                f"Database is missing required tables: {', '.join(sorted(missing))}. "
                "This may be from an incompatible version.",
                "danger",
            )
            return _back("database")

        # Back up the current database before replacing it.
        url = make_url(current_app.config["SQLALCHEMY_DATABASE_URI"])
        db_path = url.database
        if os.path.isfile(db_path):
            backup_path = (
                db_path + f".backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            )
            shutil.copy2(db_path, backup_path)
            current_app.logger.info("DB backup created: %s", backup_path)

        # Close all pooled connections, then swap the file.
        db.engine.dispose()
        shutil.move(tmp_path, db_path)
        tmp_path = None  # prevent cleanup in finally block

        # An older export predates the Spotlight tables. Create anything
        # missing now, rather than erroring on the ingest pages until the
        # next restart. create_all only adds; it never alters a table.
        db.create_all()
        current_app.logger.warning(
            "AUDIT database replaced by %s (user id %s)",
            current_user.username or current_user.email, current_user.id,
        )

        flash(
            "Database imported successfully. A backup of the previous database "
            "was saved alongside the data file.",
            "success",
        )

    except Exception as exc:
        current_app.logger.error("DB import failed: %s", exc)
        flash("Import failed. The previous database is unchanged; see the "
              "application log for details.", "danger")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return _back("database")


@settings_bp.route("/lookup/<int:item_id>/reorder", methods=["POST"])
@admin_required
def reorder_item(item_id):
    item = db.get_or_404(LookupItem, item_id)
    direction = request.form.get("direction")
    peers = (
        LookupItem.query
        .filter_by(category=item.category, is_active=True)
        .order_by(LookupItem.display_order, LookupItem.value)
        .all()
    )
    idx = next((i for i, p in enumerate(peers) if p.id == item.id), None)
    if idx is None:
        return _back(item.category)

    swap_idx = idx - 1 if direction == "up" else idx + 1
    if 0 <= swap_idx < len(peers):
        peers[idx].display_order, peers[swap_idx].display_order = (
            peers[swap_idx].display_order,
            peers[idx].display_order,
        )
        db.session.commit()
    return _back(item.category)
