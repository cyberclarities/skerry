"""Risk Decision Request export.

Builds the docxtpl context for a single Risk record and merges it with the
small set of governance fields (RACI, priority, executive owner, the "ask")
that the register doesn't track because they belong to a specific escalation
event, not the risk itself.

Nothing here is persisted. The generated document is meant to be reviewed,
edited if needed, and manually signed by the risk owner and the Executive
Core Team — the register stays the system of record for the risk; this is
the routing packet for one decision.
"""
from datetime import date
from xml.sax.saxutils import escape as _xml_escape

from app.scoring import LIKELIHOOD_LABELS, IMPACT_LABELS, CONTROL_EFFECTIVENESS_LABELS

DASH = "—"  # em dash, matches the app's existing "—" fallback style

TREATMENT_VERBS = {
    "Mitigate": "approve remediation of",
    "Accept": "formally accept",
    "Transfer": "approve transferring",
    "Avoid": "approve discontinuing the activity behind",
}

# Priority suggested from current RAG status — editable by the preparer.
PRIORITY_FROM_RAG = {"RED": "P1 — Immediate", "AMBER": "P2 — Within quarter", "GREEN": "P3 — Planned"}

# Generic starting text for the three treatment options that are *not* the
# risk's current recommendation. These are boilerplate, not risk-specific —
# the preparer should tighten them before sending.
OPTION_BOILERPLATE = {
    "Accept": dict(
        summary="Take no further action; document the exposure and hold it for a defined period.",
        pros="No immediate spend or disruption.",
        tradeoffs="Exposure to incident, audit findings, or customer impact remains until treated.",
    ),
    "Avoid": dict(
        summary="Stop or remove the activity, asset, or exposure creating the risk.",
        pros="Eliminates the specific exposure outright.",
        tradeoffs="May reduce functionality, delay projects, or impact users.",
    ),
    "Mitigate": dict(
        summary="Reduce likelihood or impact through the remediation action below.",
        pros="Reduces likelihood/impact and aligns with policy.",
        tradeoffs="Requires funding, change windows, and possible user impact.",
    ),
    "Transfer": dict(
        summary="Shift part of the exposure via insurance, contract, or a third party.",
        pros="Offloads some financial impact.",
        tradeoffs="Operational risk and reputational exposure stay with us.",
    ),
}


def _s(val, default=DASH):
    """String-or-dash: never let a None reach the template as 'None'."""
    if val is None or val == "":
        return default
    return str(val)


def _date(val, default=DASH):
    if not val:
        return default
    return val.strftime("%Y-%m-%d")


def _money(val):
    if val is None:
        return None
    return "${:,.0f}".format(val)


def _yesno(val):
    return "Yes" if val else "No"


def suggested_defaults(risk, current_user):
    """Pre-fill values for the export-time form — all editable before generating."""
    due = risk.due_date
    priority = PRIORITY_FROM_RAG.get(risk.rag_status, "P2 — Within quarter")

    treatment = risk.treatment or "Mitigate"
    verb = TREATMENT_VERBS.get(treatment, "decide how to treat")
    subject = (risk.threat_description or "this risk").strip()
    if len(subject) > 110:
        subject = subject[:107].rstrip() + "..."
    ask = f"Executive Core Team: {verb} {subject}"
    if due:
        ask += f" by {due.isoformat()}"
    ask += "."

    return dict(
        requestor_name=current_user.name if current_user else "",
        requestor_role="CISO",
        executive_owner_requested="",
        decision_needed_by=due.isoformat() if due else "",
        priority_level=priority,
        big_ask=ask,
        why_it_matters_lead="",
        impact_operations="",
        impact_customers="",
        impact_legal=risk.regulatory_obligation or "",
        funding_requested="",
        raci_responsible=risk.action_owner or "",
        raci_accountable="",
        raci_consulted="",
        raci_informed="Executive Core Team; affected business units",
        assumptions="",
        dependencies="",
        review_trigger="",
        action2_desc="", action2_owner="", action2_due="", action2_status="",
        action3_desc="", action3_owner="", action3_due="", action3_status="",
    )


def build_context(risk, form_fields):
    """Merge register data (auto-filled) with form_fields (governance data
    collected at export time) into the full docxtpl render context.

    form_fields is a plain dict, typically request.form from the export form —
    every key here is expected to already be present (the form renders all of
    them with the suggested_defaults() above).
    """
    f = form_fields

    inherent = risk.inherent_risk_score
    residual = risk.residual_risk_score

    # Financial exposure: register gives a min/max range; the preparer can
    # add a one-line cost-to-treat note on top of it at export time.
    fin_parts = []
    min_exp, max_exp = _money(risk.min_financial_exposure), _money(risk.max_financial_exposure)
    if min_exp or max_exp:
        fin_parts.append(f"Exposure: {min_exp or DASH}–{max_exp or DASH}")
    cost_note = (f.get("impact_financial_note") or "").strip()
    if cost_note:
        fin_parts.append(cost_note)
    impact_financial = "   ".join(fin_parts) if fin_parts else DASH

    treatment = risk.treatment or ""
    options = {}
    for key in ("Accept", "Avoid", "Mitigate", "Transfer"):
        boiler = OPTION_BOILERPLATE[key]
        summary = boiler["summary"]
        if treatment == key and key == "Mitigate" and risk.remediation_action:
            summary = risk.remediation_action
        if treatment == key:
            summary = f"★ CISO RECOMMENDED — {summary}"
        options[key.lower()] = dict(
            summary=summary,
            pros=boiler["pros"],
            tradeoffs=boiler["tradeoffs"],
        )

    acceptance_signoff = DASH
    if treatment == "Accept":
        by = _s(risk.acceptance_sign_off_by, "[Name]")
        dt = _date(risk.acceptance_sign_off_date, "[YYYY-MM-DD]")
        acceptance_signoff = f"Sign-off by: {by}   Sign-off date: {dt}"

    ctx = dict(
        # Header / meta
        request_id=f"RDR-{risk.risk_id}",
        request_date=date.today().isoformat(),
        requestor_name=_s(f.get("requestor_name"), "[Name]"),
        requestor_role=_s(f.get("requestor_role"), "CISO"),
        executive_owner_requested=_s(f.get("executive_owner_requested"), "[CIO / COO / CEO]"),
        decision_needed_by=_s(f.get("decision_needed_by"), "[Date]"),

        # Source risk record
        risk_id=risk.risk_id,
        risk_category=_s(risk.risk_category),
        asset_system=_s(risk.asset_system),
        business_process=_s(risk.business_process),
        risk_owner=_s(risk.risk_owner, "[Unassigned]"),
        date_identified=_date(risk.date_identified),
        last_reviewed=_date(risk.last_reviewed),
        review_frequency=_s(risk.review_frequency),
        board_reporting_flag=_yesno(risk.board_reporting_flag),
        related_incident_ref=_s(risk.related_incident_ref, "None"),

        # Big ask / why it matters
        big_ask=_s(f.get("big_ask"), "[Write the ask in one sentence.]"),
        why_it_matters_lead=_s(f.get("why_it_matters_lead"), "[What business outcome is at risk, and why this needs an Executive decision.]"),
        impact_operations=_s(f.get("impact_operations"), "[Outage, degraded service, recovery time.]"),
        impact_financial=impact_financial,
        impact_customers=_s(f.get("impact_customers"), "[Affected population, trust, contractual commitment.]"),
        impact_legal=_s(f.get("impact_legal"), "[Regulatory obligation, audit findings, brand impact.]"),

        # Risk mechanics
        threat_description=_s(risk.threat_description),
        vulnerability_detail=_s(risk.vulnerability_detail),
        threat_actor_type=_s(risk.threat_actor_type),
        attack_vector=_s(risk.attack_vector),
        threat_intel_source=_s(risk.threat_intel_source),
        likelihood_val=_s(risk.likelihood, "?"),
        likelihood_label=_s(LIKELIHOOD_LABELS.get(risk.likelihood)),
        impact_val=_s(risk.impact, "?"),
        impact_label=_s(IMPACT_LABELS.get(risk.impact)),
        inherent_score=_s(inherent),
        existing_controls=_s(risk.existing_controls),
        control_type=_s(risk.control_type),
        control_effectiveness_val=_s(risk.control_effectiveness, "?"),
        control_effectiveness_label=_s(CONTROL_EFFECTIVENESS_LABELS.get(risk.control_effectiveness)),
        last_control_test_date=_date(risk.last_control_test_date, "Not tested"),
        control_test_result=_s(risk.control_test_result),
        residual_score=_s(residual),
        rag_status=risk.rag_status,
        exceeds_appetite=_yesno(risk.exceeds_risk_appetite),

        # Options
        opt_accept_summary=options["accept"]["summary"],
        opt_accept_pros=options["accept"]["pros"],
        opt_accept_tradeoffs=options["accept"]["tradeoffs"],
        opt_avoid_summary=options["avoid"]["summary"],
        opt_avoid_pros=options["avoid"]["pros"],
        opt_avoid_tradeoffs=options["avoid"]["tradeoffs"],
        opt_mitigate_summary=options["mitigate"]["summary"],
        opt_mitigate_pros=options["mitigate"]["pros"],
        opt_mitigate_tradeoffs=options["mitigate"]["tradeoffs"],
        opt_transfer_summary=options["transfer"]["summary"],
        opt_transfer_pros=options["transfer"]["pros"],
        opt_transfer_tradeoffs=options["transfer"]["tradeoffs"],

        # Requested decision & priority
        treatment_direction=_s(risk.treatment, "[Not yet set on the risk record]"),
        priority_level=_s(f.get("priority_level"), "[P1 / P2 / P3]"),
        funding_requested=_s(f.get("funding_requested"), "[Budget range, teams, timeframe.]"),
        acceptance_signoff=acceptance_signoff,

        # RACI
        raci_responsible=_s(f.get("raci_responsible"), "[Director / team]"),
        raci_accountable=_s(f.get("raci_accountable"), "[CIO / COO / Business owner]"),
        raci_consulted=_s(f.get("raci_consulted"), "[Risk, Legal, Finance, Service Owners]"),
        raci_informed=_s(f.get("raci_informed"), "Executive Core Team; affected units"),

        # Go deeper
        action1_desc=_s(risk.remediation_action, "[Action]"),
        action1_owner=_s(risk.action_owner, "[Name]"),
        action1_due=_date(risk.due_date, "[Date]"),
        action1_status=_s(risk.status, "Open"),
        action2_desc=_s(f.get("action2_desc"), "[Action]"),
        action2_owner=_s(f.get("action2_owner"), "[Name]"),
        action2_due=_s(f.get("action2_due"), "[Date]"),
        action2_status=_s(f.get("action2_status"), "[Status]"),
        action3_desc=_s(f.get("action3_desc"), "[Action]"),
        action3_owner=_s(f.get("action3_owner"), "[Name]"),
        action3_due=_s(f.get("action3_due"), "[Date]"),
        action3_status=_s(f.get("action3_status"), "[Status]"),

        nist_function=_s(risk.nist_csf_function, "N/A"),
        nist_category=_s(risk.nist_csf_category, "N/A"),
        nist_subcategory=_s(risk.nist_csf_subcategory, "N/A"),
        evidence_links=_s(risk.evidence_links, "None on file"),

        assumptions=_s(f.get("assumptions"), "[Only list assumptions that would materially change the decision if wrong.]"),
        dependencies=_s(f.get("dependencies"), "[Key systems, vendors, or projects this depends on.]"),
        review_trigger=_s(f.get("review_trigger"), "[Date, threat intelligence, control failure, or material business change.]"),
    )
    return _escape_ctx(ctx)


def _escape_ctx(ctx):
    """docxtpl inserts values into the docx XML without escaping them —
    an unescaped '&', '<', or '>' silently corrupts or truncates the
    document (confirmed against docxtpl 0.19.1). Escape every string value
    here, once, so nothing upstream has to remember to do it per-field.
    """
    return {k: (_xml_escape(v) if isinstance(v, str) else v) for k, v in ctx.items()}
