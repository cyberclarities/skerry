"""Admin-editable settings, stored in the app_settings table.

This module owns every key and its default. A key with no row in the table
reads as its default, so a fresh install and an upgraded one behave the same
until an admin changes something. Secrets do not belong here: the Settings
page can download the database, so SMTP credentials stay in .env.
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ── Service Desk ticketing ───────────────────────────────────────────────
TICKET_ENABLED = "ticket_enabled"
TICKET_ADDRESS = "ticket_address"
TICKET_AUTO_SEND = "ticket_auto_send"
TICKET_FIELDS = "ticket_fields"

# Auto-send rules for new risks: value -> label. Off is the default; the
# button works either way.
AUTO_SEND_RULES = {
    "off": "Off. Send by hand from the risk page",
    "red": "RED risks only",
    "red_amber": "RED and AMBER risks",
    "all": "Every new risk",
}

# Optional fields for the ticket email, in the order they appear in it:
# key -> (label, sensitive). The always-sent fields are not listed; they are
# what a ticket cannot do without. Sensitive fields are off by default. More
# people can read the service desk than the register, and threat text, hosts
# and CVEs together tell an attacker where to go.
TICKET_OPTIONAL_FIELDS = {
    "category":      ("Category", False),
    "treatment":     ("Treatment", False),
    "nist_csf":      ("NIST CSF mapping", False),
    "asset_system":  ("Asset / system", True),
    "threat":        ("Threat description (also used in the subject)", True),
    "vulnerability": ("Vulnerability detail", True),
    "remediation":   ("Remediation action", True),
    "hosts":         ("Affected hosts (from Spotlight)", True),
    "cves":          ("CVEs", True),
}
DEFAULT_TICKET_FIELDS = [k for k, (_, sensitive) in TICKET_OPTIONAL_FIELDS.items()
                         if not sensitive]

# ── Daily notices ────────────────────────────────────────────────────────
NOTICE_OVERDUE = "notice_overdue"
NOTICE_REVIEW_DUE = "notice_review_due"
NOTICE_ESCALATION = "notice_escalation"

NOTICES = {
    NOTICE_OVERDUE: "Overdue action, to the action owner",
    NOTICE_REVIEW_DUE: "Review due, to the risk owner",
    NOTICE_ESCALATION: "Board escalation, to every admin",
}

# Stored as text. Booleans are "1"/"0"; the field list is comma-separated.
DEFAULTS = {
    TICKET_ENABLED: "0",
    TICKET_ADDRESS: "",
    TICKET_AUTO_SEND: "off",
    TICKET_FIELDS: ",".join(DEFAULT_TICKET_FIELDS),
    # On, because that is how the notices worked before this page existed.
    NOTICE_OVERDUE: "1",
    NOTICE_REVIEW_DUE: "1",
    NOTICE_ESCALATION: "1",
}


def get(key):
    from app.models import AppSetting, db
    if key not in DEFAULTS:
        raise KeyError(key)
    row = db.session.get(AppSetting, key)
    return row.value if row is not None and row.value is not None else DEFAULTS[key]


def get_bool(key):
    return get(key) == "1"


def ticket_fields():
    """The optional fields switched on, as a set of keys."""
    return {f for f in get(TICKET_FIELDS).split(",") if f in TICKET_OPTIONAL_FIELDS}


def set_many(values, user):
    """Save {key: text}. Returns {key: (old, new)} for what changed.

    Every change goes to the application log with who made it. Whoever can
    change the ticket address can change where risk data goes, so a change
    has to leave a trace. The caller commits.
    """
    from app.models import AppSetting, db
    changed = {}
    now = datetime.now(timezone.utc)
    for key, new in values.items():
        if key not in DEFAULTS:
            raise KeyError(key)
        new = "" if new is None else str(new)
        old = get(key)
        if old == new:
            continue
        row = db.session.get(AppSetting, key)
        if row is None:
            row = AppSetting(key=key)
            db.session.add(row)
        row.value = new
        row.updated_at = now
        row.updated_by_id = user.id if user else None
        changed[key] = (old, new)
        log.warning("AUDIT setting %s changed by %s (user id %s): %r -> %r",
                    key, getattr(user, "username", None) or getattr(user, "email", "?"),
                    getattr(user, "id", None), old, new)
    return changed


def last_changed():
    """(when, who) of the most recent settings change, or (None, None)."""
    from app.models import AppSetting
    row = AppSetting.query.order_by(AppSetting.updated_at.desc()).first()
    if row is None:
        return None, None
    return row.updated_at, row.updated_by
