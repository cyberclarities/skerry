"""Send a risk to SolarWinds Service Desk by email.

SWSD opens an incident from any email sent to its dropbox address: the
subject becomes the incident title and the body the description. Email
cannot set priority or assignee; a category dropbox does that on the SWSD
side. SWSD does not match a resend to an existing incident, so every send
is recorded here and a second send has to be confirmed.

What goes in the email is chosen on the Email Settings page
(app/app_settings.py). The body is plain text with plain "Label: value"
lines: SWSD shows the description in a proportional font, so padded
columns come out ragged.
"""
import logging
import re
from datetime import date

from flask import current_app

from app import app_settings as settings
from app.email_utils import deliver, smtp_configured

log = logging.getLogger(__name__)

SUBJECT_SUMMARY_MAX = 90


# ── Readiness ────────────────────────────────────────────────────────────
def status():
    """Where ticketing stands: enabled, address, and whether a send can go.

    reason is None when a send can go, otherwise what is missing, in words
    for the risk page.
    """
    enabled = settings.get_bool(settings.TICKET_ENABLED)
    address = settings.get(settings.TICKET_ADDRESS).strip()
    smtp = smtp_configured()
    reason = None
    if not smtp:
        reason = ("Email is not configured on this server. An administrator "
                  "needs to set SMTP_HOST in .env.")
    elif not address:
        reason = "No Service Desk address is set. An administrator can add one under Email Settings."
    return {"enabled": enabled, "address": address, "smtp": smtp,
            "ready": enabled and reason is None, "reason": reason}


# ── What goes in the email ───────────────────────────────────────────────
def _one_line(text):
    return re.sub(r"\s+", " ", text or "").strip()


def _summary(risk, fields):
    """The subject's description. Threat text only when that field is on;
    the subject is the most widely read line of the ticket."""
    if "threat" in fields and risk.threat_description:
        text = _one_line(risk.threat_description)
        first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
        if len(first) > SUBJECT_SUMMARY_MAX:
            first = first[:SUBJECT_SUMMARY_MAX - 3].rstrip() + "..."
        return first.rstrip(".")
    return f"{risk.risk_category or 'Uncategorized'} risk logged in Skerry"


def _score(value):
    if value is None:
        return "not scored"
    return f"{value:g}"


def _spotlight_facts(risk):
    """Hosts, CVEs, and a one-line source for a risk, from the register's own
    findings and any Spotlight elevation. Counts only in the source line;
    names go in the hosts and CVEs fields, which are sensitive."""
    from app.models_spotlight import SpotlightElevation, SpotlightFinding

    elevations = SpotlightElevation.query.filter_by(risk_id=risk.id).all()
    hosts = sorted({h.strip() for e in elevations
                    for h in (e.scope_hosts or "").split(",") if h.strip()})
    cves = sorted({v.cve_id for v in risk.vulnerability_findings
                   if v.cve_id and v.status != "Remediated"})
    if not cves:
        cves = sorted({c.strip() for e in elevations
                       for c in (e.cve_list or "").split(",") if c.strip()})

    if elevations:
        findings = sum(e.finding_count or 0 for e in elevations)
        kev = SpotlightFinding.query.filter(
            SpotlightFinding.risk_id == risk.id,
            SpotlightFinding.is_cisa_kev.is_(True)).count()
        source = (f"CrowdStrike Spotlight, {len(hosts)} host(s), "
                  f"{findings} finding(s)")
        if kev:
            source += f", {kev} in CISA KEV"
    else:
        source = "Entered in Skerry"
    return {"hosts": hosts, "cves": cves, "source": source}


def compose(risk, fields=None, resend=False, facts=None, link=None):
    """(subject, body) for one risk. fields defaults to the saved choice."""
    if fields is None:
        fields = settings.ticket_fields()
    if facts is None:
        facts = _spotlight_facts(risk)
    if link is None:
        base = current_app.config.get("BASE_URL", "").rstrip("/")
        link = f"{base}/risks/{risk.id}"

    rag = risk.rag_status or "UNKNOWN"
    label = "Resent risk" if resend else "New risk"
    subject = _one_line(f"{risk.risk_id} [{rag}] {label}: {_summary(risk, fields)}")

    appetite = current_app.config.get("RISK_APPETITE_THRESHOLD", 8)
    logged_by = risk.created_by.name if getattr(risk, "created_by", None) else "an unknown user"
    identified = risk.date_identified.isoformat() if risk.date_identified else "an unrecorded date"

    lines = [
        f"Logged in Skerry by {logged_by} on {identified}. The requester on this "
        "ticket is Skerry's system account; the owners below hold the work.",
    ]
    if resend:
        lines.append("This risk was sent before. Check for an earlier incident "
                     f"for {risk.risk_id} before working this one.")
    lines += [
        "",
        f"Risk ID: {risk.risk_id}",
        f"Rating: {rag} (residual {_score(risk.residual_risk_score)}; appetite is {appetite})",
        f"Exceeds appetite: {'Yes' if risk.exceeds_risk_appetite else 'No'}",
        f"Status: {risk.status or 'Open'}",
        f"Action Owner: {risk.action_owner or 'Not assigned'}",
        f"Risk Owner: {risk.risk_owner or 'Not assigned'}",
        f"Due Date: {risk.due_date.isoformat() if risk.due_date else 'Not set'}",
        f"Source: {facts['source']}",
    ]
    if "category" in fields:
        lines.append(f"Category: {risk.risk_category or 'Not set'}")
    if "treatment" in fields:
        lines.append(f"Treatment: {risk.treatment or 'Not set'}")
    if "nist_csf" in fields and risk.nist_csf_subcategory:
        lines.append(f"NIST CSF: {risk.nist_csf_subcategory}")
    if "asset_system" in fields and risk.asset_system:
        lines.append(f"Asset / System: {_one_line(risk.asset_system)}")
    if "hosts" in fields and facts["hosts"]:
        lines.append(f"Affected hosts: {', '.join(facts['hosts'])}")
    if "cves" in fields and facts["cves"]:
        lines.append(f"CVEs: {', '.join(facts['cves'])}")

    for key, heading, text in (
        ("threat", "Threat", risk.threat_description),
        ("vulnerability", "Vulnerability detail", risk.vulnerability_detail),
        ("remediation", "Remediation action", risk.remediation_action),
    ):
        if key in fields and text and text.strip():
            lines += ["", heading, text.strip()]

    lines += [
        "",
        f"Full record: {link}",
        "",
        "--",
        f"Sent by Skerry. Status is tracked in Skerry: closing this ticket "
        f"does not close {risk.risk_id}.",
    ]
    return subject, "\n".join(lines) + "\n"


# ── Sending ──────────────────────────────────────────────────────────────
def previous_sends(risk):
    from app.models import TicketSend
    return TicketSend.query.filter_by(risk_id=risk.id, ok=True).count()


def send_risk(risk, user, trigger="manual"):
    """Send one risk and record the attempt, sent or failed.

    Adds a TicketSend row and an audit entry; the caller commits. Returns
    the TicketSend. Never raises for a mail failure: saving a risk must not
    depend on the mail server.
    """
    from app.decorators import log_audit
    from app.models import TicketSend, db

    st = status()
    resend = previous_sends(risk) > 0
    if st["reason"]:
        error = st["reason"]
    else:
        subject, body = compose(risk, resend=resend)
        error = deliver([st["address"]], subject, body)

    send = TicketSend(risk_id=risk.id, risk_ref=risk.risk_id,
                      sent_by_id=user.id if user else None, trigger=trigger,
                      recipient=st["address"] or None, ok=error is None, error=error)
    db.session.add(send)
    where = st["address"] or "no address"
    log_audit(risk, user, "ticket_sent" if error is None else "ticket_failed", {
        "service_desk": (None, f"{'Sent' if error is None else 'Failed'} to {where} "
                               f"({trigger}{', resend' if resend else ''})"),
    })
    if error:
        log.warning("Service Desk send for %s failed: %s", risk.risk_id, error)
    return send


def auto_send_wanted(risk):
    """True when the auto-send rule covers this new risk."""
    if not settings.get_bool(settings.TICKET_ENABLED):
        return False
    rule = settings.get(settings.TICKET_AUTO_SEND)
    rag = risk.rag_status
    return (rule == "all"
            or (rule == "red" and rag == "RED")
            or (rule == "red_amber" and rag in ("RED", "AMBER")))


def auto_send_new(risk, user):
    """Send a just-created risk when the rule says so. Returns the
    TicketSend, or None when the rule did not apply. The caller commits."""
    if not auto_send_wanted(risk):
        return None
    return send_risk(risk, user, trigger="auto")


def flash_auto_send(send):
    """One line after a save, so the person knows where the risk went."""
    from flask import flash
    if send is None:
        return
    if send.ok:
        flash(f"Sent to the Service Desk at {send.recipient}.", "info")
    else:
        flash(f"Saved, but the Service Desk send failed: {send.error}", "warning")


# ── Test message ─────────────────────────────────────────────────────────
class _SampleRisk:
    """A made-up risk for the test message. A plain object, not a Risk, so
    nothing about it can end up in the database."""
    id = 0
    risk_id = "SKR-TEST"
    rag_status = "RED"
    residual_risk_score = 16.0
    exceeds_risk_appetite = True
    status = "Open"
    action_owner = "Sample Action Owner"
    risk_owner = "Sample Risk Owner"
    risk_category = "Infrastructure"
    treatment = "Mitigate"
    nist_csf_subcategory = "PR.PS-02"
    asset_system = "Sample asset"
    threat_description = ("TEST MESSAGE from Skerry. This is not a real risk; "
                          "close this incident.")
    vulnerability_detail = "Sample vulnerability detail."
    remediation_action = "Sample remediation action."
    created_by = None

    def __init__(self, user):
        self.date_identified = date.today()
        self.due_date = date.today()
        self.created_by = user


def send_test(user):
    """Send a sample risk with the saved field choices. Returns None or the
    reason it did not go."""
    st = status()
    if st["reason"]:
        return st["reason"]
    subject, body = compose(
        _SampleRisk(user),
        facts={"hosts": ["sample-host-01"], "cves": ["CVE-0000-00000"],
               "source": "Sample data"},
        link=current_app.config.get("BASE_URL", ""),
    )
    subject = "[TEST] " + subject
    log.warning("AUDIT Service Desk test message sent by %s to %s",
                getattr(user, "username", None) or getattr(user, "email", "?"),
                st["address"])
    return deliver([st["address"]], subject, body)
