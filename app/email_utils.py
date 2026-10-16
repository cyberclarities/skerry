"""SMTP email helpers. All functions are no-ops when SMTP is not configured."""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app
from jinja2 import Environment
from sqlalchemy import func, or_

log = logging.getLogger(__name__)

# Plain-text bodies. A dedicated environment with autoescape off, because
# these are not HTML: Flask's render_template_string would turn "&" into
# "&amp;" in the inbox. The subject is set on the message, not in the body.
_TEXT = Environment(autoescape=False, keep_trailing_newline=True)  # nosec B701 -- plain-text email, never rendered as HTML

OVERDUE_TEMPLATE = _TEXT.from_string("""\
Risk ID:      {{ risk.risk_id }}
Category:     {{ risk.risk_category }}
Threat:       {{ (risk.threat_description or '')[:120] }}...
Action Owner: {{ risk.action_owner }}
Due Date:     {{ risk.due_date }}
Days Overdue: {{ risk.days_overdue }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
""")

ESCALATION_TEMPLATE = _TEXT.from_string("""\
The following risk is flagged for board reporting and exceeds risk appetite:

Risk ID:    {{ risk.risk_id }}
Category:   {{ risk.risk_category }}
Threat:     {{ (risk.threat_description or '')[:120] }}...
RAG Status: {{ risk.rag_status }}
Owner:      {{ risk.risk_owner }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
""")

REVIEW_DUE_TEMPLATE = _TEXT.from_string("""\
Risk {{ risk.risk_id }} is due for review (frequency: {{ risk.review_frequency }}).

Threat:        {{ (risk.threat_description or '')[:120] }}...
Last Reviewed: {{ risk.last_reviewed or 'Never' }}
Owner:         {{ risk.risk_owner }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
""")


def _send(to_addresses: list[str], subject: str, body: str):
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        log.debug("SMTP not configured; skipping email to %s", to_addresses)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = ", ".join(to_addresses)
    msg.attach(MIMEText(body, "plain"))

    # A verifying context. Without one, smtplib uses an unverified context and
    # the SMTP password goes to whoever answers on the other end.
    context = ssl.create_default_context()
    server = None
    try:
        if cfg.get("SMTP_USE_TLS", True):
            server = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"])
            server.starttls(context=context)
        else:
            server = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"], context=context)

        if cfg.get("SMTP_USER"):
            server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])

        server.sendmail(cfg["SMTP_FROM"], to_addresses, msg.as_string())
        log.info("Email sent to %s: %s", to_addresses, subject)
    except Exception as exc:
        log.error("Failed to send email to %s: %s", to_addresses, exc)
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:  # noqa: BLE001  # nosec B110 -- connection already gone
                pass


def _emails_for_name(name: str) -> list[str]:
    """Resolve an owner field to the email of an active user, or nothing.

    Matches a user's display name or email exactly (case-insensitive). It does
    not mail an arbitrary address typed into the field, and it does not treat
    % or _ as wildcards, so an owner value cannot route risk details outside
    the user list.
    """
    if not name or not name.strip():
        return []
    from app.models import User
    needle = name.strip().lower()
    user = User.query.filter(
        User.is_active.is_(True),
        or_(func.lower(User.name) == needle, func.lower(User.email) == needle),
    ).first()
    if user:
        return [user.email]
    log.warning("Cannot resolve notification recipient '%s' to an active user.", name)
    return []


def notify_overdue(risk, base_url: str):
    recipients = _emails_for_name(risk.action_owner) or _emails_for_name(risk.risk_owner)
    if not recipients:
        return
    body = OVERDUE_TEMPLATE.render(risk=risk, base_url=base_url)
    _send(recipients, f"[Skerry] Overdue Action: {risk.risk_id}", body)


def notify_board_escalation(risk, admin_emails: list[str], base_url: str):
    if not admin_emails:
        return
    body = ESCALATION_TEMPLATE.render(risk=risk, base_url=base_url)
    _send(admin_emails, f"[Skerry] Board Escalation: {risk.risk_id}", body)


def notify_review_due(risk, base_url: str):
    recipients = _emails_for_name(risk.risk_owner)
    if not recipients:
        return
    body = REVIEW_DUE_TEMPLATE.render(risk=risk, base_url=base_url)
    _send(recipients, f"[Skerry] Review Due: {risk.risk_id}", body)


REVIEW_INTERVAL_DAYS = {"Monthly": 30, "Quarterly": 90, "Annually": 365}


def review_due(risk, today):
    """True when a risk is within 7 days of (or past) its next review.

    A risk that has never been reviewed counts from the day it was
    identified, so it is not silently exempt from reminders.
    """
    from datetime import timedelta
    freq_days = REVIEW_INTERVAL_DAYS.get(risk.review_frequency or "", 0)
    anchor = risk.last_reviewed or risk.date_identified
    if not freq_days or not anchor:
        return False
    return today >= anchor + timedelta(days=freq_days) - timedelta(days=7)


def run_daily_notifications(app):
    """Called by the scheduler once per day."""
    with app.app_context():
        from datetime import date
        from app.models import Risk, User

        base_url = app.config.get("BASE_URL", "http://localhost:5000")
        admin_emails = [
            u.email for u in User.query.filter_by(role="admin", is_active=True).all()
        ]
        today = date.today()

        risks = Risk.query.filter(Risk.status.notin_(["Closed", "Accepted"])).all()
        for risk in risks:
            if risk.is_overdue:
                notify_overdue(risk, base_url)
            if risk.board_reporting_flag and risk.exceeds_risk_appetite:
                notify_board_escalation(risk, admin_emails, base_url)
            if review_due(risk, today):
                notify_review_due(risk, base_url)
