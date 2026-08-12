"""SMTP email helpers. All functions are no-ops when SMTP is not configured."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app, render_template_string

log = logging.getLogger(__name__)

OVERDUE_TEMPLATE = """
Subject: [Skerry] Overdue Action — {{ risk.risk_id }}

Risk ID:      {{ risk.risk_id }}
Category:     {{ risk.risk_category }}
Threat:       {{ (risk.threat_description or '')[:120] }}...
Action Owner: {{ risk.action_owner }}
Due Date:     {{ risk.due_date }}
Days Overdue: {{ risk.days_overdue }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
"""

ESCALATION_TEMPLATE = """
Subject: [Skerry] Board Escalation Flag — {{ risk.risk_id }}

The following risk is flagged for board reporting and exceeds risk appetite:

Risk ID:    {{ risk.risk_id }}
Category:   {{ risk.risk_category }}
Threat:     {{ (risk.threat_description or '')[:120] }}...
RAG Status: {{ risk.rag_status }}
Owner:      {{ risk.risk_owner }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
"""

REVIEW_DUE_TEMPLATE = """
Subject: [Skerry] Review Due — {{ risk.risk_id }}

Risk {{ risk.risk_id }} is due for review (frequency: {{ risk.review_frequency }}).

Threat:        {{ (risk.threat_description or '')[:120] }}...
Last Reviewed: {{ risk.last_reviewed or 'Never' }}
Owner:         {{ risk.risk_owner }}

Log in to review: {{ base_url }}/risks/{{ risk.id }}
"""


def _send(to_addresses: list[str], subject: str, body: str):
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        log.debug("SMTP not configured — skipping email to %s", to_addresses)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = ", ".join(to_addresses)
    msg.attach(MIMEText(body, "plain"))

    try:
        if cfg.get("SMTP_USE_TLS", True):
            server = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"])
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"])

        if cfg.get("SMTP_USER"):
            server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])

        server.sendmail(cfg["SMTP_FROM"], to_addresses, msg.as_string())
        server.quit()
        log.info("Email sent to %s: %s", to_addresses, subject)
    except Exception as exc:
        log.error("Failed to send email to %s: %s", to_addresses, exc)


def _emails_for_name(name: str) -> list[str]:
    """Look up a user's email by their display name.
    Falls back gracefully — if no matching user, returns empty list.
    """
    if not name:
        return []
    from app.models import User
    user = User.query.filter(
        User.name.ilike(name.strip()),
        User.is_active == True,  # noqa: E712
    ).first()
    if user:
        return [user.email]
    # If it looks like an email address already, use it directly
    if "@" in name:
        return [name.strip()]
    log.warning("Cannot resolve notification recipient '%s' to a user email.", name)
    return []


def notify_overdue(risk, base_url: str):
    recipients = _emails_for_name(risk.action_owner) or _emails_for_name(risk.risk_owner)
    if not recipients:
        return
    body = render_template_string(OVERDUE_TEMPLATE, risk=risk, base_url=base_url)
    subject = f"[Skerry] Overdue Action — {risk.risk_id}"
    _send(recipients, subject, body)


def notify_board_escalation(risk, admin_emails: list[str], base_url: str):
    if not admin_emails:
        return
    body = render_template_string(ESCALATION_TEMPLATE, risk=risk, base_url=base_url)
    subject = f"[Skerry] Board Escalation — {risk.risk_id}"
    _send(admin_emails, subject, body)


def notify_review_due(risk, base_url: str):
    recipients = _emails_for_name(risk.risk_owner)
    if not recipients:
        return
    body = render_template_string(REVIEW_DUE_TEMPLATE, risk=risk, base_url=base_url)
    subject = f"[Skerry] Review Due — {risk.risk_id}"
    _send(recipients, subject, body)


def run_daily_notifications(app):
    """Called by the scheduler once per day."""
    with app.app_context():
        from datetime import date, timedelta
        from app.models import Risk, User

        base_url = app.config.get("BASE_URL", "http://localhost:5000")
        admin_emails = [
            u.email for u in User.query.filter_by(role="admin", is_active=True).all()
        ]

        risks = Risk.query.filter(Risk.status.notin_(["Closed", "Accepted"])).all()
        for risk in risks:
            # Overdue actions
            if risk.is_overdue:
                notify_overdue(risk, base_url)

            # Board escalations that exceed appetite
            if risk.board_reporting_flag and risk.exceeds_risk_appetite:
                notify_board_escalation(risk, admin_emails, base_url)

            # Review due within 7 days
            if risk.last_reviewed and risk.review_frequency:
                freq_days = {"Monthly": 30, "Quarterly": 90, "Annually": 365}.get(
                    risk.review_frequency, 0
                )
                if freq_days:
                    next_review = risk.last_reviewed + timedelta(days=freq_days)
                    if date.today() >= next_review - timedelta(days=7):
                        notify_review_due(risk, base_url)
