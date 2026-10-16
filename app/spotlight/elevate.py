"""Promote staged Spotlight findings into a Risk in the register.

The copy decision, stated up front: elevation writes ordinary
`VulnerabilityFinding` rows against the new Risk. It does not point the
existing exports at a new table. Every Decision Request, every open/High
count, every "oldest open" line on the executive summary keeps working
exactly as it does today, because from the register's point of view nothing
changed -- findings arrived the same way they always have.

What the staging row keeps is provenance: which elevation it belongs to,
which risk it became, and which VulnerabilityFinding row carries its data.
That is what makes "where did this number come from?" answerable six months
from now.

Two things this module refuses to do:

  * It will not create a risk without a person. The scores are suggestions
    (see scoring.py); the form is pre-filled, not pre-submitted.
  * It will not elevate the same finding twice. A finding already carrying
    an elevation_id is skipped, and the caller is told.
"""

import logging
from datetime import date, datetime, timezone

from ..models import Risk, VulnerabilityFinding, db
from ..models_spotlight import (
    INGEST_DISMISSED,
    INGEST_ELEVATED,
    INGEST_TRIAGED,
    SpotlightElevation,
    SpotlightFinding,
    SpotlightHost,
)
from .scoring import suggest_scores, suggest_velocity

log = logging.getLogger(__name__)

# NIST CSF 2.0 subcategory for identified asset vulnerabilities. Pre-selected
# on the form so CSF Coverage reporting is populated by default rather than
# by whoever remembers to pick it.
DEFAULT_CSF = ("ID", "ID.RA", "ID.RA-01")

MAX_CVES_IN_SUMMARY = 25


def _utcnow():
    return datetime.now(timezone.utc)


def selected_findings(finding_ids):
    """Load staged findings by primary key, preserving nothing but order by CVE."""
    if not finding_ids:
        return []
    return (
        SpotlightFinding.query
        .filter(SpotlightFinding.id.in_(finding_ids))
        .order_by(SpotlightFinding.hostname, SpotlightFinding.cve_id)
        .all()
    )


def hosts_for(findings):
    aids = {f.aid for f in findings if f.aid}
    if not aids:
        return []
    return SpotlightHost.query.filter(SpotlightHost.aid.in_(aids)).all()


def build_proposal(findings):
    """Everything the elevation form needs, with no side effects.

    Returns a dict of suggested Risk field values plus the scoring rationale.
    Nothing is written; call `elevate` with the operator's edited form to
    actually create the risk.
    """
    findings = [f for f in findings if f is not None]
    if not findings:
        return {}

    hosts = hosts_for(findings)
    host_names = sorted({f.hostname or f.aid for f in findings if (f.hostname or f.aid)})
    cves = sorted({f.cve_id for f in findings if f.cve_id})
    likelihood, impact, rationale = suggest_scores(findings, hosts)

    multi = len(host_names) > 1
    if multi and len(cves) == 1:
        label = f"{cves[0]} ({len(host_names)} hosts)"
    elif multi:
        label = f"{len(cves)} CVEs across {len(host_names)} hosts"
    else:
        label = host_names[0] if host_names else "Unknown host"

    return {
        "scope_type": "hosts" if multi else "host",
        "scope_label": label,
        "host_names": host_names,
        "cves": cves,
        "findings": findings,
        "hosts": hosts,
        "suggested_likelihood": likelihood,
        "suggested_impact": impact,
        "suggestion_rationale": rationale,
        "risk_category": "Infrastructure",
        "asset_system": _asset_system(host_names),
        "threat_description": _threat_description(findings, host_names, cves),
        "vulnerability_detail": _vulnerability_detail(findings),
        "threat_intel_source": "CrowdStrike Falcon Spotlight",
        "assurance_source": "Vulnerability Scan",
        "control_type": "Preventive",
        "risk_velocity": suggest_velocity(findings),
        "treatment": "Mitigate",
        "status": "Open",
        "remediation_action": _remediation_action(findings),
        "date_identified": _earliest_found(findings),
        "evidence_links": _evidence_links(findings),
        "nist_csf_function": DEFAULT_CSF[0],
        "nist_csf_category": DEFAULT_CSF[1],
        "nist_csf_subcategory": DEFAULT_CSF[2],
    }


def _asset_system(host_names):
    if not host_names:
        return None
    if len(host_names) == 1:
        return host_names[0][:255]
    if len(host_names) <= 4:
        return ", ".join(host_names)[:255]
    return f"{', '.join(host_names[:3])} and {len(host_names) - 3} more hosts"[:255]


def _earliest_found(findings):
    dates = [f.date_found for f in findings if f.date_found]
    return min(dates) if dates else date.today()


def _threat_description(findings, host_names, cves):
    """Plain-language summary. Written to be read by someone non-technical."""
    open_count = len([f for f in findings if f.is_open])
    kev = [f.cve_id for f in findings if f.is_cisa_kev and f.cve_id]
    exposed = [f for f in findings if (f.exploit_status or 0) >= 90]
    oldest = max((f.days_open for f in findings if f.days_open is not None), default=None)

    if len(host_names) == 1:
        lead = (
            f"CrowdStrike Falcon Spotlight reports {open_count} open "
            f"vulnerability finding(s) on {host_names[0]}."
        )
    else:
        lead = (
            f"CrowdStrike Falcon Spotlight reports {open_count} open "
            f"vulnerability finding(s) covering {len(cves)} CVE(s) across "
            f"{len(host_names)} hosts."
        )

    parts = [lead]
    if kev:
        parts.append(
            f"{len(set(kev))} of these are listed in the CISA Known Exploited "
            f"Vulnerabilities catalog ({', '.join(sorted(set(kev))[:5])}"
            + (", and others" if len(set(kev)) > 5 else "")
            + "), meaning exploitation has been observed in the wild rather "
              "than theorized."
        )
    elif exposed:
        parts.append(
            f"{len(exposed)} finding(s) carry a CrowdStrike exploit status of "
            f"'Actively used'."
        )
    if oldest is not None:
        parts.append(f"The oldest finding in this group has been open {oldest} days.")

    parts.append(
        "Unpatched software on a reachable host is the entry point an attacker "
        "uses first, because it needs no one to make a mistake -- the flaw is "
        "already there."
    )
    return " ".join(parts)


def _vulnerability_detail(findings):
    """One line per CVE, worst-first. This is the technical evidence block."""
    by_cve = {}
    for f in findings:
        if not f.cve_id:
            continue
        current = by_cve.get(f.cve_id)
        if current is None or (f.cve_base_score or 0) > (current.cve_base_score or 0):
            by_cve[f.cve_id] = f

    ordered = sorted(
        by_cve.values(),
        key=lambda f: (f.cve_base_score or 0, f.is_cisa_kev),
        reverse=True,
    )
    lines = []
    for f in ordered[:MAX_CVES_IN_SUMMARY]:
        bits = [f.cve_id]
        if f.cve_base_score:
            bits.append(f"CVSS {f.cve_base_score}")
        if f.cve_severity:
            bits.append(f.severity_title)
        if f.exprt_rating:
            bits.append(f"ExPRT {f.exprt_title}")
        if f.is_cisa_kev:
            bits.append("CISA KEV")
        if f.product_name_version:
            bits.append(f.product_name_version)
        lines.append(" | ".join(str(b) for b in bits))

    if len(ordered) > MAX_CVES_IN_SUMMARY:
        lines.append(f"... and {len(ordered) - MAX_CVES_IN_SUMMARY} further CVE(s); "
                     f"the full list is on the linked findings.")
    lines.append("")
    lines.append("Source: CrowdStrike Falcon Spotlight, "
                 "/spotlight/combined/vulnerabilities/v1.")
    return "\n".join(lines)


def _remediation_action(findings):
    titles = []
    for f in findings:
        if f.remediation_title and f.remediation_title not in titles:
            titles.append(f.remediation_title)
    if not titles:
        return "Apply vendor patches for the CVEs listed in the vulnerability detail."
    body = "\n".join(f"- {t}" for t in titles[:15])
    if len(titles) > 15:
        body += f"\n- ... and {len(titles) - 15} further remediation item(s)."
    return "Apply the remediations Spotlight identifies:\n" + body


def _evidence_links(findings):
    links = []
    for f in findings:
        if f.remediation_link and f.remediation_link not in links:
            links.append(f.remediation_link)
    links.append("CrowdStrike Falcon console > Exposure Management > Vulnerabilities")
    return "\n".join(links[:10])


# -- the write path -----------------------------------------------------------
def elevate(findings, form, user, next_risk_id):
    """Create a Risk from staged findings and copy the findings onto it.

    `form` is the submitted elevation form -- the operator's numbers win over
    the suggestions every time. `next_risk_id` is passed in rather than
    computed here so the existing `_next_risk_id()` in risk_routes stays the
    single place risk IDs are minted.

    Returns (risk, elevation, skipped) where `skipped` lists findings that
    were already elevated and were left alone.
    """
    eligible = [f for f in findings if not f.elevation_id]
    skipped = [f for f in findings if f.elevation_id]
    if not eligible:
        return None, None, skipped

    proposal = build_proposal(eligible)

    risk = Risk(risk_id=next_risk_id, created_by_id=user.id)
    _apply_form(risk, form, proposal)
    db.session.add(risk)
    db.session.flush()  # need risk.id

    host_names = proposal["host_names"]
    cves = proposal["cves"]
    elevation = SpotlightElevation(
        risk_id=risk.id,
        risk_ref=risk.risk_id,
        scope_type=proposal["scope_type"],
        scope_label=(form.get("scope_label") or proposal["scope_label"])[:500],
        scope_hosts=", ".join(host_names)[:4000],
        scope_aids=", ".join(sorted({f.aid for f in eligible if f.aid}))[:4000],
        host_count=len(host_names),
        finding_count=len(eligible),
        cve_list=", ".join(cves)[:4000],
        suggested_likelihood=proposal["suggested_likelihood"],
        suggested_impact=proposal["suggested_impact"],
        suggestion_rationale=proposal["suggestion_rationale"],
        created_by_id=user.id,
    )
    db.session.add(elevation)
    db.session.flush()

    # Copy into the register's own findings table -- one row per staged
    # finding, so the existing counts and exports see real data.
    for staged in eligible:
        copied = VulnerabilityFinding(
            risk_id=risk.id,
            cve_id=staged.cve_id,
            severity=staged.severity_title,
            expert_rating=staged.exprt_title,
            vulnerable_product=_product_label(staged),
            remediation=staged.remediation_title or staged.remediation_action,
            date_found=staged.date_found,
            status="Open" if staged.is_open else "Remediated",
        )
        db.session.add(copied)
        db.session.flush()

        staged.elevation_id = elevation.id
        staged.risk_id = risk.id
        staged.vuln_finding_id = copied.id
        staged.ingest_state = INGEST_ELEVATED

    db.session.flush()
    log.info("Elevated %s finding(s) on %s host(s) to %s",
             len(eligible), len(host_names), risk.risk_id)
    return risk, elevation, skipped


def _product_label(staged):
    """Hostname-qualified product, because a risk can span several hosts.

    On a multi-host risk, "OpenSSL 1.1.1k" repeated eleven times tells the
    reader nothing. "web03 | OpenSSL 1.1.1k" tells them where to go.
    """
    product = staged.product_name_version or "Unspecified product"
    host = staged.hostname or staged.aid
    if host:
        return f"{host} | {product}"[:255]
    return product[:255]


def _apply_form(risk, form, proposal):
    """Map the elevation form onto a Risk. Operator input wins; proposal fills gaps."""

    def text(key, fallback=None):
        value = (form.get(key) or "").strip()
        return value or fallback

    def score(key, fallback=None):
        raw = (form.get(key) or "").strip()
        if raw.isdigit() and int(raw) in range(1, 6):
            return int(raw)
        return fallback if fallback in range(1, 6) else None

    risk.risk_category = text("risk_category", proposal["risk_category"])
    risk.asset_system = text("asset_system", proposal["asset_system"])
    risk.business_process = text("business_process")
    risk.threat_description = text("threat_description", proposal["threat_description"])
    risk.vulnerability_detail = text("vulnerability_detail", proposal["vulnerability_detail"])
    risk.threat_actor_type = text("threat_actor_type")
    risk.attack_vector = text("attack_vector")
    risk.threat_intel_source = text("threat_intel_source", proposal["threat_intel_source"])

    risk.likelihood = score("likelihood", proposal["suggested_likelihood"])
    risk.impact = score("impact", proposal["suggested_impact"])

    risk.existing_controls = text("existing_controls")
    risk.control_type = text("control_type", proposal["control_type"])
    risk.control_effectiveness = score("control_effectiveness")
    risk.assurance_source = text("assurance_source", proposal["assurance_source"])
    risk.risk_velocity = text("risk_velocity", proposal["risk_velocity"])
    risk.detection_capability = text("detection_capability")

    risk.risk_owner = text("risk_owner")
    risk.escalation_path = text("escalation_path")

    risk.treatment = text("treatment", proposal["treatment"])
    risk.remediation_action = text("remediation_action", proposal["remediation_action"])
    risk.action_owner = text("action_owner")

    due = (form.get("due_date") or "").strip()
    if due:
        try:
            risk.due_date = date.fromisoformat(due)
        except ValueError:
            risk.due_date = None

    from app.routes.risk_routes import STATUSES
    status = text("status", proposal["status"])
    risk.status = status if status in STATUSES else proposal["status"]
    risk.date_identified = proposal["date_identified"]
    risk.review_frequency = text("review_frequency", "Monthly")
    risk.board_reporting_flag = form.get("board_reporting_flag") in ("on", "true", "1", "yes")
    risk.evidence_links = text("evidence_links", proposal["evidence_links"])

    note = text("notes_history")
    provenance = (
        f"Elevated from CrowdStrike Spotlight ingest on "
        f"{date.today().isoformat()}. Suggested likelihood "
        f"{proposal['suggested_likelihood']} / impact "
        f"{proposal['suggested_impact']}; rationale:\n"
        f"{proposal['suggestion_rationale']}"
    )
    risk.notes_history = f"{note}\n\n{provenance}" if note else provenance

    risk.nist_csf_function = text("nist_csf_function", proposal["nist_csf_function"])
    risk.nist_csf_category = text("nist_csf_category", proposal["nist_csf_category"])
    risk.nist_csf_subcategory = text("nist_csf_subcategory", proposal["nist_csf_subcategory"])
    risk.updated_at = _utcnow()


# -- triage without elevation -------------------------------------------------
def set_state(findings, state, user, reason=None):
    """Mark findings Triaged or Dismissed without creating a risk.

    Dismissal is a decision, so it records who and why. A queue where things
    disappear with no reason attached is a queue nobody trusts.
    """
    if state not in (INGEST_TRIAGED, INGEST_DISMISSED):
        raise ValueError(f"Cannot set ingest state to {state!r} here.")
    changed = 0
    for finding in findings:
        if finding.elevation_id:
            continue  # already a risk; leave it alone
        finding.ingest_state = state
        if state == INGEST_DISMISSED:
            finding.dismissed_reason = reason
            finding.dismissed_at = _utcnow()
            finding.dismissed_by_id = user.id
        else:
            finding.dismissed_reason = None
            finding.dismissed_at = None
            finding.dismissed_by_id = None
        if reason and state == INGEST_TRIAGED:
            finding.triage_note = reason
        changed += 1
    return changed


def sync_elevated_statuses():
    """Push Spotlight remediation status onto the copied register findings.

    Only ever flips a copied VulnerabilityFinding to Remediated when
    Spotlight says the finding closed. It does not reopen, and it does not
    touch severity, rating, or dates -- an operator may have corrected those
    by hand, and a sync job overwriting a human correction is exactly the
    kind of quiet damage that erodes trust in the register.

    Returns the number of rows updated.
    """
    staged = (
        SpotlightFinding.query
        .filter(SpotlightFinding.vuln_finding_id.isnot(None))
        .filter(SpotlightFinding.spotlight_status.in_(("closed", "expired")))
        .all()
    )
    updated = 0
    for finding in staged:
        copied = db.session.get(VulnerabilityFinding, finding.vuln_finding_id)
        if copied is None:
            continue  # the risk was deleted; nothing to update
        if copied.status != "Remediated":
            copied.status = "Remediated"
            updated += 1
    if updated:
        db.session.commit()
        log.info("Marked %s elevated finding(s) Remediated from Spotlight status", updated)
    return updated
