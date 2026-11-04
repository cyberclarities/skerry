"""Risk Action Request export: two documents from one Risk record.

A Risk Action Request asks the CIO and CISO to mandate a course of action
on one risk. The analysis is done; the documents carry the options, the
recommendation, and a place for both executives to sign the mandate.

This module builds the docxtpl context for a single Risk record and merges
it with the fields that belong to one request rather than to the risk
itself: who it goes to, the accountable executive, priority, the ask,
background, issue, RACI, and option viability.

The context built here is shared by two templates:
  - risk_exec_summary_template.docx       the one-page Risk Action Request
  - risk_supporting_evidence_template.docx the full record behind it

Nothing here is persisted. The generated documents are reviewed, edited if
needed, and signed by hand: the CIO and CISO sign the mandate, and the risk
owner acknowledges it. The register stays the system of record for the
risk; this is the routing packet for one mandate. The one exception is
vulnerability findings, which *are* persisted (VulnerabilityFinding)
because the register is the right place for that data to live,
independent of any one export.
"""
from datetime import date
from xml.sax.saxutils import escape as _xml_escape

from docxtpl import RichText

from app.scoring import LIKELIHOOD_LABELS, IMPACT_LABELS, CONTROL_EFFECTIVENESS_LABELS

# Shown wherever the register has no value. Plain words, not a dash: these
# documents go to executives, and an empty cell should say what it means.
DASH = "Not recorded"

# Who the request asks to mandate the action. Editable per request.
MANDATING_EXECUTIVES = "CIO and CISO"

# "mandate <verb> <subject>" in the one-sentence ask.
TREATMENT_VERBS = {
    "Mitigate": "remediation of",
    "Accept": "formal acceptance of",
    "Transfer": "transfer of",
    "Avoid": "discontinuing the activity behind",
}

# Priority suggested from current RAG status, editable by the preparer.
PRIORITY_LEVELS = ["P1: Immediate", "P2: Within quarter", "P3: Planned"]
PRIORITY_FROM_RAG = {"RED": PRIORITY_LEVELS[0], "AMBER": PRIORITY_LEVELS[1],
                     "GREEN": PRIORITY_LEVELS[2]}

# Supporting Evidence options table (Section 5): summary, pros, trade-offs.
# Boilerplate, not risk-specific; the preparer should tighten before sending.
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
        pros="Reduces likelihood and impact, and aligns with policy.",
        tradeoffs="Requires funding, change windows, and possible user impact.",
    ),
    "Transfer": dict(
        summary="Shift part of the exposure through insurance, contract, or a third party.",
        pros="Offloads some financial impact.",
        tradeoffs="Operational risk and reputational exposure stay with us.",
    ),
}

# One-page request, Options section: what each box mandates if checked.
# {rag} is substituted for Accept.
EXEC_OPTION_TEXT = {
    "Mitigate": "Mandate the treatment plan in the Recommendation, with the funding, resources, "
                "and accountable executive it needs.",
    "Accept": "Mandate formal acceptance of the residual {rag} risk through a set review date, "
              "with documented compensating controls and a named accountable executive.",
    "Avoid": "Mandate stopping or removing the activity, asset, or exposure that creates the risk.",
    "Transfer": "Mandate shifting part of the exposure through insurance, contract, or a third party.",
}

# Options that can be marked "not viable" at export time. Mitigate and
# Accept are always live choices; Avoid and Transfer often aren't for a
# system that has to keep running.
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
    """$10,000 -> $10K, $1,000,000 -> $1M. Used on the one-page request's
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
    """One colored, bold run as a docxtpl RichText, for the label suffix on
    each option box (★ RECOMMENDED in blue, (not viable) in gray). Plain
    string concatenation can't carry color, so this is the one spot in the
    context that isn't a plain string."""
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
    """Textarea (blank-line-separated) -> list of paragraphs, for prose
    fields such as the background and the risk narrative."""
    if not text:
        return []
    return [p.strip() for p in text.split("\n\n") if p.strip()]


def suggested_defaults(risk, current_user):
    """Pre-fill values for the export form. All of them are editable."""
    due = risk.due_date
    priority = PRIORITY_FROM_RAG.get(risk.rag_status, PRIORITY_LEVELS[1])
    to = MANDATING_EXECUTIVES

    treatment = risk.treatment or "Mitigate"
    verb = TREATMENT_VERBS.get(treatment, "action on")
    exec_subject = (risk.business_process or risk.asset_system or "this system").strip()
    # Name the risk and what it touches. The threat description is a full
    # sentence of its own and does not read after "mandate remediation of".
    ask = f"{to}: mandate {verb} {risk.risk_id}, the risk to {exec_subject}"
    if due:
        ask += f", by {due.isoformat()}"
    ask += "."

    # The Ask paragraph on the one-page request. Longer than the one-line
    # ask above: who is asked, for what, by when, and what happens if the
    # recommended action is not mandated.
    score = f" ({risk.residual_risk_score})" if risk.residual_risk_score is not None else ""
    exec_ask = (
        f"We are asking the {to} to mandate {treatment} for a {risk.rag_status} residual "
        f"risk{score} on {exec_subject}"
        + (f", by {due.isoformat()}" if due else "")
        + ". The options and our recommendation follow. If the recommended action is not "
        "mandated, the residual risk stays with the business, and accepting it takes both "
        "signatures, documented conditions, and a review date."
    )

    background = (risk.threat_description or "").strip()

    return dict(
        requestor_name=current_user.name if current_user else "",
        requestor_role="",
        mandating_executives=to,
        accountable_executive="",
        mandate_needed_by=due.isoformat() if due else "",
        priority_level=priority,
        big_ask=ask,
        exec_subject=exec_subject,
        executive_ask=exec_ask,
        background=background,
        issue_bullets="",
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
        raci_informed="CIO; CISO; affected business units",
        assumptions="",
        dependencies="",
        review_trigger="",
        action2_desc="", action2_owner="", action2_due="", action2_status="",
        action3_desc="", action3_owner="", action3_due="", action3_status="",
    )


def build_context(risk, form_fields):
    """Merge register data (auto-filled) with form_fields (the request's own
    data, collected at export time) into the docxtpl render context shared
    by the one-page request and the Supporting Evidence document.

    form_fields is a plain dict, typically request.form from the export
    form. The form renders every key with suggested_defaults() above, but a
    missing key falls back to a bracketed prompt rather than failing.
    """
    f = form_fields

    inherent = risk.inherent_risk_score
    residual = risk.residual_risk_score

    # Financial exposure: full numbers for Supporting Evidence, abbreviated
    # for the one-line glance table on the one-page request.
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
            summary = f"Not viable. {summary}"
            tradeoffs = reason

        is_register = key == register_treatment
        is_suggested = key == suggested_treatment
        if is_suggested:
            summary = f"★ RECOMMENDED. {summary}"
        elif is_register:
            summary = f"CURRENT TREATMENT, NOT RECOMMENDED. {summary}"

        options[key.lower()] = dict(summary=summary, pros=pros, tradeoffs=tradeoffs)

    treatment_note = ""
    if suggested_treatment and register_treatment and suggested_treatment != register_treatment:
        treatment_note = (
            f"Note: The register lists {register_treatment} as the current treatment. The analysis "
            f"below recommends {suggested_treatment} instead. {register_treatment} is not recommended "
            "unless the CIO and CISO formally accept the residual risk."
        )

    # ── Options: one-page request, one mandate box per option ────────────
    exec_options = {}
    for key in ("Mitigate", "Accept", "Avoid", "Transfer"):
        reason = reasons.get(key)
        if key in VIABILITY_OVERRIDABLE and reason:
            text = f"Not viable: {reason}"
            label_suffix = _rt("  (not viable)", "404040", bold=True)
        else:
            text = EXEC_OPTION_TEXT[key].format(rag=risk.rag_status)
            label_suffix = _rt("  ★ RECOMMENDED", "2E75B6", bold=True) if key == suggested_treatment else ""
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
        request_id=f"RAR-{risk.risk_id}",
        request_date=date.today().isoformat(),
        requestor_name=_s(f.get("requestor_name"), "[Name]"),
        requestor_role=_s(f.get("requestor_role"), "[Role]"),
        mandating_executives=_s(f.get("mandating_executives"), MANDATING_EXECUTIVES),
        accountable_executive=_s(f.get("accountable_executive"), "[Accountable executive]"),
        mandate_needed_by=_s(f.get("mandate_needed_by"), "[Date]"),
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

        # The ask, and the one-page request's Background / Issue / Recommendation
        big_ask=_s(f.get("big_ask"), "[Write the ask in one sentence.]"),
        executive_ask=_s(f.get("executive_ask"), "[What we are asking them to mandate, by when, and what happens if they do not.]"),
        background_paragraphs=_paragraphs(f.get("background")),
        issue_bullets=_bullets(f.get("issue_bullets")),
        recommended_action_bullets=_bullets(f.get("recommended_action_bullets")),
        risk_narrative_paragraphs=_paragraphs(f.get("risk_narrative")),

        # Business impact (Supporting Evidence table)
        impact_operations=_s(f.get("impact_operations"), "[Outage, degraded service, recovery time.]"),
        impact_financial=impact_financial,
        impact_customers=_s(f.get("impact_customers"), "[Affected population, trust, contractual commitment.]"),
        impact_legal=_s(f.get("impact_legal"), "[Regulatory obligation, audit findings, brand impact.]"),

        # Risk at a Glance (one-page request, Background)
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
        # One cell: "2026-09-01: Pass", or just "Not tested" when it never was.
        last_control_test=(
            f"{_date(risk.last_control_test_date)}: {_s(risk.control_test_result)}"
            if risk.last_control_test_date else "Not tested"),
        control_test_result=_s(risk.control_test_result),
        residual_score=_s(residual),
        rag_status=risk.rag_status,
        exceeds_appetite=_yesno(risk.exceeds_risk_appetite),

        # Options: Supporting Evidence table and note
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

        # Options: one-page request mandate boxes
        exec_opt_mitigate_text=exec_options["mitigate"]["text"],
        exec_opt_mitigate_label=exec_options["mitigate"]["label_suffix"],
        exec_opt_accept_text=exec_options["accept"]["text"],
        exec_opt_accept_label=exec_options["accept"]["label_suffix"],
        exec_opt_avoid_text=exec_options["avoid"]["text"],
        exec_opt_avoid_label=exec_options["avoid"]["label_suffix"],
        exec_opt_transfer_text=exec_options["transfer"]["text"],
        exec_opt_transfer_label=exec_options["transfer"]["label_suffix"],

        # The mandate requested, and priority
        treatment_direction=_s(register_treatment, "[Not yet set on the risk record]"),
        suggested_treatment=_s(suggested_treatment, "[Not yet set]"),
        priority_level=_s(f.get("priority_level"), "[P1 / P2 / P3]"),
        funding_requested=_s(f.get("funding_requested"), "[Budget range, teams, timeframe.]"),
        acceptance_signoff=acceptance_signoff,

        # RACI
        raci_responsible=_s(f.get("raci_responsible"), "[Director / team]"),
        raci_accountable=_s(f.get("raci_accountable"), "[Accountable executive]"),
        raci_consulted=_s(f.get("raci_consulted"), "[Risk, Legal, Finance, Service Owners]"),
        raci_informed=_s(f.get("raci_informed"), "CIO; CISO; affected business units"),

        # Action and evidence tracker
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

        assumptions=_s(f.get("assumptions"), "[Only list assumptions that would change the mandate if wrong.]"),
        dependencies=_s(f.get("dependencies"), "[Key systems, vendors, or projects this depends on.]"),
        review_trigger=_s(f.get("review_trigger"), "[Date, threat intelligence, control failure, or material business change.]"),
    )
    return _escape_ctx(ctx)


def _escape_ctx(ctx):
    """docxtpl inserts values into the docx XML without escaping them:
    an unescaped '&', '<', or '>' silently corrupts or truncates the
    document (confirmed against docxtpl 0.19.1). Escape every string value
    here, once, so nothing upstream has to remember to do it per field.
    Lists (bullets, paragraphs, vuln rows) are escaped element- or
    field-wise so docxtpl's {%p%}/{%tr%} loops still see lists and dicts.
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
