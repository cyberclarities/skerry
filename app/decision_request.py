"""Risk Decision Request export — two documents from one Risk record.

Builds the docxtpl context for a single Risk record and merges it with the
governance fields (RACI, priority, executive owner, the "ask", narrative,
option viability) that the register doesn't track because they belong to a
specific escalation event, not the risk itself.

The context built here is shared by two templates:
  - risk_exec_summary_template.docx      — one page, for the Executive Core Team
  - risk_supporting_evidence_template.docx — the full record behind that ask

Nothing here is persisted. The generated documents are meant to be reviewed,
edited if needed, and manually signed by the risk owner and the Executive
Core Team — the register stays the system of record for the risk; this is
the routing packet for one decision. The one exception is vulnerability
findings, which *are* persisted (VulnerabilityFinding) because the register
is the right place for that data to live, independent of any one export.
"""
from datetime import date
from xml.sax.saxutils import escape as _xml_escape

from docxtpl import RichText

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

# Supporting Evidence options table (Section 5) — summary/pros/tradeoffs style.
# Boilerplate, not risk-specific — the preparer should tighten before sending.
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
        summary="Reduce likelihood or impact through the remediation actions in Section 7.",
        pros="Reduces likelihood/impact and aligns with policy.",
        tradeoffs="Requires funding, change windows, and possible user impact.",
    ),
    "Transfer": dict(
        summary="Shift part of the exposure via insurance, contract, or a third party.",
        pros="Offloads some financial impact.",
        tradeoffs="Operational risk and reputational exposure stay with us.",
    ),
}

# Executive Summary decision block — short, approval-oriented text, not the
# summary/pros/tradeoffs breakdown. {rag} is substituted for Accept.
EXEC_OPTION_TEXT = {
    "Mitigate": "Approve immediate treatment plan, funding/resources, and executive accountable owner.",
    "Accept": "Formally accept residual {rag} risk through a defined review date, with documented compensating controls and accountable executive approval.",
    "Avoid": "Stop or remove the activity, asset, or exposure creating the risk.",
    "Transfer": "Shift part of the exposure via insurance, contract, or a third party.",
}

# Options that can be marked "not viable" at export time — Mitigate and
# Accept are always live choices; Avoid/Transfer often aren't for a system
# that has to keep running.
VIABILITY_OVERRIDABLE = ("Avoid", "Transfer")


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


def _money_abbrev(val):
    """$10,000 -> $10K, $1,000,000 -> $1M. Used on the Executive Summary's
    Risk at a Glance table, which is one line and needs to stay short."""
    if val is None:
        return None
    if val >= 1_000_000:
        return f"${val / 1_000_000:.1f}M".replace(".0M", "M")
    if val >= 1_000:
        return f"${val / 1_000:.0f}K"
    return "${:,.0f}".format(val)


def _yesno(val):
    return "Yes" if val else "No"


def _rt(text, color_hex, bold=True):
    """One colored/bold run as a docxtpl RichText, for the Executive
    Summary decision block's label suffix (★ RECOMMENDED in green,
    (not viable) in gray) — plain string concatenation can't carry color,
    so this is the one spot in the context that isn't a plain string."""
    if not text:
        return ""
    rt = RichText()
    rt.add(text, color=color_hex, bold=bold)
    return rt


def _bullets(text):
    """Textarea (one item per line) -> list of non-empty, stripped lines."""
    if not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def _paragraphs(text):
    """Textarea (blank-line-separated) -> list of paragraphs, for the risk
    narrative — several paragraphs of prose, not a bullet list."""
    if not text:
        return []
    return [p.strip() for p in text.split("\n\n") if p.strip()]


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

    # Executive Ask paragraph (Executive Summary) — longer than the 1a Big
    # Ask above; states the decision, the score, and the fallback (accept
    # with conditions) if the recommended direction isn't approved.
    exec_subject = (risk.business_process or risk.asset_system or "this system").strip()
    exec_ask = (
        f"The Executive Core Team must decide"
        + (f" by {due.isoformat()}" if due else "")
        + f" how to treat a {risk.rag_status} residual risk"
        + (f" ({risk.residual_risk_score})" if risk.residual_risk_score is not None else "")
        + f" on {exec_subject}. The recommended direction is {treatment}. If remediation cannot be "
        "approved, leadership must formally accept the residual risk with documented conditions and a review date."
    )

    return dict(
        requestor_name=current_user.name if current_user else "",
        requestor_role="CISO",
        executive_owner_requested="",
        decision_needed_by=due.isoformat() if due else "",
        priority_level=priority,
        big_ask=ask,
        exec_subject=exec_subject,
        executive_ask=exec_ask,
        why_it_matters_bullets="",
        recommended_action_bullets=risk.remediation_action or "",
        risk_narrative="",
        impact_operations="",
        impact_customers="",
        impact_legal=risk.regulatory_obligation or "",
        funding_requested="",
        suggested_treatment=treatment,
        avoid_not_viable_reason="",
        transfer_not_viable_reason="",
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
    collected at export time) into the full docxtpl render context shared
    by both the Executive Summary and Supporting Evidence templates.

    form_fields is a plain dict, typically request.form from the export form —
    every key here is expected to already be present (the form renders all of
    them with the suggested_defaults() above).
    """
    f = form_fields

    inherent = risk.inherent_risk_score
    residual = risk.residual_risk_score

    # Financial exposure: full numbers for Supporting Evidence, abbreviated
    # for the Executive Summary's one-line glance table.
    min_exp, max_exp = _money(risk.min_financial_exposure), _money(risk.max_financial_exposure)
    fin_parts = []
    if min_exp or max_exp:
        fin_parts.append(f"Exposure: {min_exp or DASH}–{max_exp or DASH}")
    cost_note = (f.get("impact_financial_note") or "").strip()
    if cost_note:
        fin_parts.append(cost_note)
    impact_financial = "   ".join(fin_parts) if fin_parts else DASH

    min_abbrev, max_abbrev = _money_abbrev(risk.min_financial_exposure), _money_abbrev(risk.max_financial_exposure)
    if min_abbrev or max_abbrev:
        financial_exposure_abbrev = f"{min_abbrev or DASH} – {max_abbrev or DASH}"
    else:
        financial_exposure_abbrev = DASH

    register_treatment = risk.treatment or ""
    suggested_treatment = _s(f.get("suggested_treatment"), register_treatment)
    if suggested_treatment == DASH:
        suggested_treatment = register_treatment

    reasons = {
        "Avoid": (f.get("avoid_not_viable_reason") or "").strip(),
        "Transfer": (f.get("transfer_not_viable_reason") or "").strip(),
    }

    # ── Options: Supporting Evidence (summary/pros/tradeoffs table) ──────
    options = {}
    for key in ("Accept", "Avoid", "Mitigate", "Transfer"):
        boiler = OPTION_BOILERPLATE[key]
        summary = boiler["summary"]
        pros = boiler["pros"]
        tradeoffs = boiler["tradeoffs"]

        if key == "Mitigate" and risk.remediation_action:
            summary = risk.remediation_action

        reason = reasons.get(key)
        if key in VIABILITY_OVERRIDABLE and reason:
            summary = f"Not an Option. {summary}"
            tradeoffs = reason

        is_register = key == register_treatment
        is_suggested = key == suggested_treatment
        if is_register and is_suggested:
            summary = f"★ RECOMMENDED — {summary}"
        elif is_suggested:
            summary = f"★ SUGGESTED ACTION. {summary}"
        elif is_register:
            summary = f"★ CURRENT STATE — Not Recommended. {summary}"

        options[key.lower()] = dict(summary=summary, pros=pros, tradeoffs=tradeoffs)

    treatment_note = ""
    if suggested_treatment and register_treatment and suggested_treatment != register_treatment:
        treatment_note = (
            f"Note: The register currently lists the CISO recommendation as {register_treatment}. "
            f"However, the treatment analysis below identifies {suggested_treatment} as the suggested "
            f"action and labels {register_treatment} as not recommended absent executive acceptance of "
            "the residual risk."
        )

    # ── Options: Executive Summary decision block (short, per-option) ────
    exec_options = {}
    for key in ("Mitigate", "Accept", "Avoid", "Transfer"):
        reason = reasons.get(key)
        if key in VIABILITY_OVERRIDABLE and reason:
            text = f"Not viable — {reason}"
            label_suffix = _rt("  (not viable)", "7A7974", bold=True)
        else:
            text = EXEC_OPTION_TEXT[key].format(rag=risk.rag_status)
            label_suffix = _rt("  ★ RECOMMENDED", "00B050", bold=True) if key == suggested_treatment else ""
        exec_options[key.lower()] = dict(text=text, label_suffix=label_suffix)

    acceptance_signoff = DASH
    if register_treatment == "Accept":
        by = _s(risk.acceptance_sign_off_by, "[Name]")
        dt = _date(risk.acceptance_sign_off_date, "[YYYY-MM-DD]")
        acceptance_signoff = f"Sign-off by: {by}   Sign-off date: {dt}"

    # ── Vulnerability findings ────────────────────────────────────────────
    findings = list(risk.vulnerability_findings)
    open_findings = [v for v in findings if v.status != "Remediated"]
    high_count = len([v for v in open_findings if v.severity == "High"])
    expert_high_count = len([v for v in open_findings if v.expert_rating == "High"])
    oldest_days = risk.oldest_vuln_days
    vuln_rows = [
        dict(
            cve_id=_s(v.cve_id),
            severity=_s(v.severity),
            remediation=_s(v.remediation),
            vulnerable_product=_s(v.vulnerable_product),
            days_open=_s(v.days_open, "?"),
        )
        for v in findings
    ]
    if findings:
        vuln_summary = (
            f"{len(findings)} listed findings; {high_count} High severity; "
            f"{expert_high_count} with High ExPRT risk ratings."
        )
        if oldest_days is not None:
            vuln_summary += f" Oldest vulnerability open {oldest_days} days."
    else:
        vuln_summary = "No vulnerability findings recorded on this risk."

    nist_combined = (
        f"Function: {_s(risk.nist_csf_function, 'N/A')}   |   "
        f"Category: {_s(risk.nist_csf_category, 'N/A')}   |   "
        f"Subcategory: {_s(risk.nist_csf_subcategory, 'N/A')}"
    )

    ctx = dict(
        # Header / meta
        request_id=f"RDR-{risk.risk_id}",
        request_date=date.today().isoformat(),
        requestor_name=_s(f.get("requestor_name"), "[Name]"),
        requestor_role=_s(f.get("requestor_role"), "CISO"),
        executive_owner_requested=_s(f.get("executive_owner_requested"), "[CIO / COO / CEO]"),
        decision_needed_by=_s(f.get("decision_needed_by"), "[Date]"),
        exec_subject=_s(f.get("exec_subject"), risk.business_process or risk.asset_system),

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
        nist_combined=nist_combined,

        # Asks
        big_ask=_s(f.get("big_ask"), "[Write the ask in one sentence.]"),
        executive_ask=_s(f.get("executive_ask"), "[What decision is needed, by when, and what happens if it isn't approved.]"),
        why_it_matters_bullets=_bullets(f.get("why_it_matters_bullets")),
        recommended_action_bullets=_bullets(f.get("recommended_action_bullets")),
        risk_narrative_paragraphs=_paragraphs(f.get("risk_narrative")),

        # Business impact (Supporting Evidence table)
        impact_operations=_s(f.get("impact_operations"), "[Outage, degraded service, recovery time.]"),
        impact_financial=impact_financial,
        impact_customers=_s(f.get("impact_customers"), "[Affected population, trust, contractual commitment.]"),
        impact_legal=_s(f.get("impact_legal"), "[Regulatory obligation, audit findings, brand impact.]"),

        # Risk at a Glance (Executive Summary)
        financial_exposure_abbrev=financial_exposure_abbrev,
        vuln_open_count=len(open_findings),
        vuln_high_count=high_count,
        vuln_oldest_days=_s(oldest_days, "None open"),

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

        # Options — Supporting Evidence table + note
        treatment_note=treatment_note,
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

        # Options — Executive Summary decision block
        exec_opt_mitigate_text=exec_options["mitigate"]["text"],
        exec_opt_mitigate_label=exec_options["mitigate"]["label_suffix"],
        exec_opt_accept_text=exec_options["accept"]["text"],
        exec_opt_accept_label=exec_options["accept"]["label_suffix"],
        exec_opt_avoid_text=exec_options["avoid"]["text"],
        exec_opt_avoid_label=exec_options["avoid"]["label_suffix"],
        exec_opt_transfer_text=exec_options["transfer"]["text"],
        exec_opt_transfer_label=exec_options["transfer"]["label_suffix"],

        # Requested decision & priority
        treatment_direction=_s(register_treatment, "[Not yet set on the risk record]"),
        suggested_treatment=_s(suggested_treatment, "[Not yet set]"),
        priority_level=_s(f.get("priority_level"), "[P1 / P2 / P3]"),
        funding_requested=_s(f.get("funding_requested"), "[Budget range, teams, timeframe.]"),
        acceptance_signoff=acceptance_signoff,

        # RACI
        raci_responsible=_s(f.get("raci_responsible"), "[Director / team]"),
        raci_accountable=_s(f.get("raci_accountable"), "[CIO / COO / Business owner]"),
        raci_consulted=_s(f.get("raci_consulted"), "[Risk, Legal, Finance, Service Owners]"),
        raci_informed=_s(f.get("raci_informed"), "Executive Core Team; affected units"),

        # Go deeper / action tracker
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

        # Vulnerability evidence
        vuln_summary=vuln_summary,
        vuln_findings=vuln_rows,

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
    Lists (bullets, narrative paragraphs, vuln rows) are escaped element-
    or field-wise so docxtpl's {%p%}/{%tr%} loops still see a list/dicts.
    """
    out = {}
    for k, v in ctx.items():
        if isinstance(v, str):
            out[k] = _xml_escape(v)
        elif isinstance(v, list):
            out[k] = [_escape_item(item) for item in v]
        else:
            out[k] = v
    return out


def _escape_item(item):
    if isinstance(item, str):
        return _xml_escape(item)
    if isinstance(item, dict):
        return {k: (_xml_escape(v) if isinstance(v, str) else v) for k, v in item.items()}
    return item
