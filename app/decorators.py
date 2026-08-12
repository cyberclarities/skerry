from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user


def role_required(*roles):
    """Restrict a view to users with one of the given roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    return role_required("admin")(f)


def operator_required(f):
    return role_required("operator", "admin")(f)


def log_audit(risk, user, action, changes=None):
    """Write audit log entries for a risk change.

    changes: dict of {field: (old_value, new_value)}
    """
    from app.models import AuditLog, db

    if not changes:
        entry = AuditLog(
            risk_id=risk.id,
            user_id=user.id if user else None,
            action=action,
        )
        db.session.add(entry)
        return

    for field, (old_val, new_val) in changes.items():
        if str(old_val) != str(new_val):
            entry = AuditLog(
                risk_id=risk.id,
                user_id=user.id if user else None,
                action=action,
                field_name=field,
                old_value=str(old_val) if old_val is not None else None,
                new_value=str(new_val) if new_val is not None else None,
            )
            db.session.add(entry)
