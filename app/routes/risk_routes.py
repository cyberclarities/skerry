import io
from datetime import date, datetime, timezone
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort, jsonify, send_file)
from flask_login import login_required, current_user
from sqlalchemy import or_
from app.models import db, Risk, TrendLog, VulnerabilityFinding, NISTCSFReference, LookupItem
from app.decorators import operator_required, log_audit
from app.scoring import LIKELIHOOD_LABELS, IMPACT_LABELS, CONTROL_EFFECTIVENESS_LABELS
from app.decision_request import build_context, suggested_defaults

risks_bp = Blueprint("risks", __name__, url_prefix="/risks")

RISK_CATEGORIES = [
    "Infrastructure", "Application", "Data", "Identity & Access",
    "Supply Chain", "Compliance", "Physical", "People", "Third Party",
]
# Threat actors, attack vectors, intel sources, and risk owners are now
# managed from Settings → Lookup Lists and loaded from the database.
# The remaining lists below are structural / fixed and are not user-configurable.
CONTROL_TYPES = ["Preventive", "Detective", "Corrective", "Compensating", "None"]
TEST_RESULTS = ["Pass", "Fail", "Not Tested"]
ASSURANCE_SOURCES = [
    "Self-Assessment", "Internal Audit", "Vulnerability Scan",
    "Penetration Test", "Third-Party Assessment",
]
VELOCITIES = ["Rapid", "Moderate", "Slow"]
DETECTION_CAPABILITIES = ["Full", "Partial", "Minimal", "None"]
TREATMENTS = ["Mitigate", "Accept", "Transfer", "Avoid"]
STATUSES = ["Open", "In Progress", "Closed", "Accepted"]
FREQUENCIES = ["Monthly", "Quarterly", "Annually"]
VULN_SEVERITIES = ["Critical", "High", "Medium", "Low"]
VULN_STATUSES = ["Open", "Remediated"]
def _lookup(category):
    """Pull active lookup values for a given category from the database."""
    return [
        item.value for item in
        LookupItem.query
        .filter_by(category=category, is_active=True)
        .order_by(LookupItem.display_order, LookupItem.value)
        .all()
    ]


def _next_risk_id():
    from flask import current_app
    prefix = current_app.config.get("RISK_ID_PREFIX", "CR")
    last = (
        db.session.query(Risk.risk_id)
        .filter(Risk.risk_id.like(f"{prefix}-%"))
        .order_by(Risk.id.desc())
        .first()
    )
    if last:
        try:
            seq = int(last[0].split("-")[1]) + 1
        except (IndexError, ValueError):
            seq = Risk.query.count() + 1
    else:
        seq = 1
    return f"{prefix}-{seq:03d}"


def _nist_choices():
    functions = db.session.query(
        NISTCSFReference.function_code,
        NISTCSFReference.function_name,
    ).distinct().order_by(NISTCSFReference.function_code).all()
    categories = db.session.query(
        NISTCSFReference.category_code,
        NISTCSFReference.category_name,
        NISTCSFReference.function_code,
    ).distinct().order_by(NISTCSFReference.category_code).all()
    subcategories = db.session.query(
        NISTCSFReference.subcategory_code,
        NISTCSFReference.description,
        NISTCSFReference.category_code,
    ).order_by(NISTCSFReference.subcategory_code).all()
    return functions, categories, subcategories


def _form_context():
    functions, categories, subcategories = _nist_choices()
    return dict(
        risk_categories=RISK_CATEGORIES,
        threat_actors=_lookup("threat_actor_type"),
        attack_vectors=_lookup("attack_vector"),
        intel_sources=_lookup("threat_intel_source"),
        risk_owners=_lookup("risk_owner"),
        control_types=CONTROL_TYPES,
        test_results=TEST_RESULTS,
        assurance_sources=ASSURANCE_SOURCES,
        velocities=VELOCITIES,
        detection_capabilities=DETECTION_CAPABILITIES,
        treatments=TREATMENTS,
        statuses=STATUSES,
        frequencies=FREQUENCIES,
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
        effectiveness_labels=CONTROL_EFFECTIVENESS_LABELS,
        nist_functions=functions,
        nist_categories=categories,
        nist_subcategories=subcategories,
    )


@risks_bp.route("/")
@login_required
def list_risks():
    q = request.args.get("q", "").strip()
    rag_filter = request.args.get("rag", "")
    cat_filter = request.args.get("category", "")
    status_filter = request.args.get("status", "")
    owner_filter = request.args.get("owner", "").strip()
    appetite_filter = request.args.get("appetite", "")

    query = Risk.query

    if q:
        query = query.filter(
            or_(
                Risk.risk_id.ilike(f"%{q}%"),
                Risk.threat_description.ilike(f"%{q}%"),
                Risk.asset_system.ilike(f"%{q}%"),
                Risk.risk_owner.ilike(f"%{q}%"),
            )
        )
    if cat_filter:
        query = query.filter(Risk.risk_category == cat_filter)
    if status_filter:
        query = query.filter(Risk.status == status_filter)
    if owner_filter:
        query = query.filter(Risk.risk_owner.ilike(f"%{owner_filter}%"))

    risks = query.order_by(Risk.id.asc()).all()

    # In-Python filters for computed fields
    if rag_filter:
        risks = [r for r in risks if r.rag_status == rag_filter]
    if appetite_filter == "yes":
        risks = [r for r in risks if r.exceeds_risk_appetite]
    elif appetite_filter == "no":
        risks = [r for r in risks if not r.exceeds_risk_appetite]

    # For HTMX partial requests
    if request.headers.get("HX-Request"):
        return render_template("partials/risk_table.html", risks=risks)

    return render_template(
        "risks/list.html",
        risks=risks,
        risk_categories=RISK_CATEGORIES,
        statuses=STATUSES,
        q=q,
        rag_filter=rag_filter,
        cat_filter=cat_filter,
        status_filter=status_filter,
        owner_filter=owner_filter,
        appetite_filter=appetite_filter,
    )


@risks_bp.route("/<int:risk_pk>")
@login_required
def detail(risk_pk):
    risk = Risk.query.get_or_404(risk_pk)
    audit_entries = risk.audit_log.limit(50).all()
    trend_entries = risk.trend_entries.all()
    vulnerability_findings = risk.vulnerability_findings.all()
    return render_template(
        "risks/detail.html",
        risk=risk,
        audit_entries=audit_entries,
        trend_entries=trend_entries,
        vulnerability_findings=vulnerability_findings,
        vuln_severities=VULN_SEVERITIES,
        vuln_statuses=VULN_STATUSES,
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
        effectiveness_labels=CONTROL_EFFECTIVENESS_LABELS,
    )


@risks_bp.route("/new", methods=["GET", "POST"])
@operator_required
def new_risk():
    if request.method == "POST":
        risk = Risk(risk_id=_next_risk_id(), created_by_id=current_user.id)
        _populate_risk(risk, request.form)
        db.session.add(risk)
        db.session.flush()
        log_audit(risk, current_user, "created")
        _auto_trend_entry(risk)
        db.session.commit()
        flash(f"Risk {risk.risk_id} created.", "success")
        return redirect(url_for("risks.detail", risk_pk=risk.id))

    ctx = _form_context()
    ctx["risk"] = None
    ctx["next_id"] = _next_risk_id()
    return render_template("risks/form.html", **ctx)


@risks_bp.route("/<int:risk_pk>/edit", methods=["GET", "POST"])
@operator_required
def edit_risk(risk_pk):
    risk = Risk.query.get_or_404(risk_pk)

    # Operators can edit risks they created, or risks where risk_owner matches their name.
    # Risks with no owner require admin — no silent fallthrough.
    if not current_user.is_admin:
        created_by_me = risk.created_by_id == current_user.id
        owned_by_me = (
            risk.risk_owner
            and risk.risk_owner.strip().lower() == current_user.name.strip().lower()
        )
        if not (created_by_me or owned_by_me):
            abort(403)

    if request.method == "POST":
        old = _snapshot(risk)
        _populate_risk(risk, request.form)
        changes = _diff(old, _snapshot(risk))
        if changes:
            log_audit(risk, current_user, "updated", changes)
            _auto_trend_entry(risk)
        db.session.commit()
        flash(f"Risk {risk.risk_id} updated.", "success")
        return redirect(url_for("risks.detail", risk_pk=risk.id))

    ctx = _form_context()
    ctx["risk"] = risk
    return render_template("risks/form.html", **ctx)


@risks_bp.route("/<int:risk_pk>/delete", methods=["POST"])
@operator_required
def delete_risk(risk_pk):
    risk = Risk.query.get_or_404(risk_pk)
    if not current_user.is_admin:
        abort(403)
    risk_id = risk.risk_id
    db.session.delete(risk)
    db.session.commit()
    flash(f"Risk {risk_id} deleted.", "warning")
    if request.headers.get("HX-Request"):
        return "", 200
    return redirect(url_for("risks.list_risks"))


@risks_bp.route("/<int:risk_pk>/trend", methods=["POST"])
@operator_required
def add_trend(risk_pk):
    risk = Risk.query.get_or_404(risk_pk)
    review_date_str = request.form.get("review_date") or str(date.today())
    reviewer = request.form.get("reviewer", current_user.name)
    notes = request.form.get("notes", "")
    test_result = request.form.get("control_test_result", "")

    try:
        review_date = date.fromisoformat(review_date_str)
    except ValueError:
        review_date = date.today()

    residual = risk.residual_risk_score
    rag = risk.rag_status

    # Compute change vs prior
    prior = risk.trend_entries.order_by(TrendLog.review_date.desc()).first()
    change = None
    if prior and residual is not None and prior.residual_score is not None:
        change = round(residual - prior.residual_score, 1)

    entry = TrendLog(
        risk_id=risk.id,
        review_date=review_date,
        residual_score=residual,
        rag_status=rag,
        change_vs_prior=change,
        reviewer=reviewer,
        control_test_result=test_result,
        notes=notes,
    )
    risk.last_reviewed = review_date
    db.session.add(entry)
    db.session.commit()
    flash("Trend entry added.", "success")
    return redirect(url_for("risks.detail", risk_pk=risk.id))


@risks_bp.route("/<int:risk_pk>/vulnerability", methods=["POST"])
@operator_required
def add_vulnerability(risk_pk):
    """Add one vulnerability finding (typically one CVE) to a risk.

    Backs the vulnerability evidence table and open/High/oldest-open counts
    on the Decision Request exports — this is the source of that data, not
    a field on the export form.
    """
    risk = Risk.query.get_or_404(risk_pk)

    date_found_str = request.form.get("date_found", "").strip()
    try:
        date_found = date.fromisoformat(date_found_str) if date_found_str else None
    except ValueError:
        date_found = None

    finding = VulnerabilityFinding(
        risk_id=risk.id,
        cve_id=request.form.get("cve_id", "").strip() or None,
        severity=request.form.get("severity", "").strip() or None,
        expert_rating=request.form.get("expert_rating", "").strip() or None,
        vulnerable_product=request.form.get("vulnerable_product", "").strip() or None,
        remediation=request.form.get("remediation", "").strip() or None,
        date_found=date_found,
        status=request.form.get("status", "Open").strip() or "Open",
    )
    db.session.add(finding)
    log_audit(risk, current_user, "updated", {"vulnerability_finding": (None, finding.cve_id or "added")})
    db.session.commit()
    flash("Vulnerability finding added.", "success")
    return redirect(url_for("risks.detail", risk_pk=risk.id))


@risks_bp.route("/<int:risk_pk>/vulnerability/<int:vuln_pk>/delete", methods=["POST"])
@operator_required
def delete_vulnerability(risk_pk, vuln_pk):
    risk = Risk.query.get_or_404(risk_pk)
    finding = VulnerabilityFinding.query.filter_by(id=vuln_pk, risk_id=risk.id).first_or_404()
    cve = finding.cve_id
    db.session.delete(finding)
    log_audit(risk, current_user, "updated", {"vulnerability_finding": (cve or "removed", None)})
    db.session.commit()
    flash("Vulnerability finding removed.", "success")
    return redirect(url_for("risks.detail", risk_pk=risk.id))


@risks_bp.route("/<int:risk_pk>/decision-request", methods=["GET", "POST"])
@operator_required
def decision_request(risk_pk):
    """Generate a Risk Decision Request .docx for one risk.

    GET shows a short form for the handful of fields the register doesn't
    track (RACI, priority, executive owner, the "ask") — everything else is
    auto-filled from the risk record. POST renders the docx and returns it
    as a download; nothing here is written back to the database.
    """
    risk = Risk.query.get_or_404(risk_pk)

    if request.method == "POST":
        ctx = build_context(risk, request.form)

        import os
        import zipfile
        from docxtpl import DocxTemplate
        from flask import current_app

        exports_dir = os.path.join(current_app.root_path, "templates", "exports")
        stamp = date.today().isoformat()

        exec_summary = DocxTemplate(os.path.join(exports_dir, "risk_exec_summary_template.docx"))
        exec_summary.render(ctx)
        exec_out = io.BytesIO()
        exec_summary.save(exec_out)
        exec_name = f"{risk.risk_id}_Executive_Summary_Decision_Request_{stamp}.docx"

        evidence = DocxTemplate(os.path.join(exports_dir, "risk_supporting_evidence_template.docx"))
        evidence.render(ctx)
        evidence_out = io.BytesIO()
        evidence.save(evidence_out)
        evidence_name = f"{risk.risk_id}_Supporting_Evidence_{stamp}.docx"

        zip_out = io.BytesIO()
        with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(exec_name, exec_out.getvalue())
            zf.writestr(evidence_name, evidence_out.getvalue())
        zip_out.seek(0)

        filename = f"Risk_Decision_Request_{risk.risk_id}_{stamp}.zip"
        log_audit(risk, current_user, "exported", {"decision_request": (None, filename)})
        db.session.commit()
        return send_file(
            zip_out, download_name=filename, as_attachment=True,
            mimetype="application/zip",
        )

    defaults = suggested_defaults(risk, current_user)
    return render_template(
        "risks/decision_request_form.html",
        risk=risk,
        defaults=defaults,
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
    )


@risks_bp.route("/api/nist/categories")
@login_required
def api_nist_categories():
    function_code = request.args.get("function", "")
    cats = (
        NISTCSFReference.query
        .filter_by(function_code=function_code)
        .with_entities(NISTCSFReference.category_code, NISTCSFReference.category_name)
        .distinct()
        .order_by(NISTCSFReference.category_code)
        .all()
    )
    return jsonify([{"code": c.category_code, "name": c.category_name} for c in cats])


@risks_bp.route("/api/nist/subcategories")
@login_required
def api_nist_subcategories():
    category_code = request.args.get("category", "")
    subs = (
        NISTCSFReference.query
        .filter_by(category_code=category_code)
        .with_entities(NISTCSFReference.subcategory_code, NISTCSFReference.description)
        .order_by(NISTCSFReference.subcategory_code)
        .all()
    )
    return jsonify([{"code": s.subcategory_code, "desc": s.description} for s in subs])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _populate_risk(risk: Risk, form):
    """Map form fields onto a Risk instance."""

    def _date(key):
        val = form.get(key, "").strip()
        if val:
            try:
                return date.fromisoformat(val)
            except ValueError:
                pass
        return None

    def _int(key):
        val = form.get(key, "").strip()
        return int(val) if val and val.isdigit() else None

    def _float(key):
        val = form.get(key, "").strip()
        try:
            return float(val) if val else None
        except ValueError:
            return None

    def _bool(key):
        return form.get(key) in ("on", "true", "1", "yes")

    risk.risk_category = form.get("risk_category", "").strip() or None
    risk.asset_system = form.get("asset_system", "").strip() or None
    risk.business_process = form.get("business_process", "").strip() or None
    risk.threat_description = form.get("threat_description", "").strip() or None
    risk.vulnerability_detail = form.get("vulnerability_detail", "").strip() or None
    risk.threat_actor_type = form.get("threat_actor_type", "").strip() or None
    risk.attack_vector = form.get("attack_vector", "").strip() or None
    risk.threat_intel_source = form.get("threat_intel_source", "").strip() or None
    raw_likelihood = _int("likelihood")
    raw_impact = _int("impact")
    risk.likelihood = raw_likelihood if raw_likelihood in range(1, 6) else None
    risk.impact = raw_impact if raw_impact in range(1, 6) else None
    risk.existing_controls = form.get("existing_controls", "").strip() or None
    risk.control_type = form.get("control_type", "").strip() or None
    raw_ce = _int("control_effectiveness")
    risk.control_effectiveness = raw_ce if raw_ce in range(1, 6) else None
    risk.last_control_test_date = _date("last_control_test_date")
    risk.control_test_result = form.get("control_test_result", "").strip() or None
    risk.assurance_source = form.get("assurance_source", "").strip() or None
    risk.risk_velocity = form.get("risk_velocity", "").strip() or None
    risk.detection_capability = form.get("detection_capability", "").strip() or None
    risk.risk_owner = form.get("risk_owner", "").strip() or None
    risk.escalation_path = form.get("escalation_path", "").strip() or None

    # Accept sign-off — admin only
    if current_user.is_admin:
        risk.acceptance_sign_off_by = form.get("acceptance_sign_off_by", "").strip() or None
        risk.acceptance_sign_off_date = _date("acceptance_sign_off_date")

    risk.min_financial_exposure = _float("min_financial_exposure")
    risk.max_financial_exposure = _float("max_financial_exposure")
    risk.regulatory_obligation = form.get("regulatory_obligation", "").strip() or None
    risk.related_incident_ref = form.get("related_incident_ref", "").strip() or None
    risk.treatment = form.get("treatment", "").strip() or None
    risk.remediation_action = form.get("remediation_action", "").strip() or None
    risk.action_owner = form.get("action_owner", "").strip() or None
    risk.due_date = _date("due_date")
    risk.status = form.get("status", "Open").strip()
    risk.date_identified = _date("date_identified") or date.today()
    risk.last_reviewed = _date("last_reviewed")
    risk.review_frequency = form.get("review_frequency", "").strip() or None
    risk.board_reporting_flag = _bool("board_reporting_flag")
    risk.evidence_links = form.get("evidence_links", "").strip() or None
    risk.notes_history = form.get("notes_history", "").strip() or None
    risk.nist_csf_function = form.get("nist_csf_function", "").strip() or None
    risk.nist_csf_category = form.get("nist_csf_category", "").strip() or None
    risk.nist_csf_subcategory = form.get("nist_csf_subcategory", "").strip() or None

    risk.updated_at = datetime.now(timezone.utc)


def _snapshot(risk: Risk) -> dict:
    """Capture a dict snapshot of key risk fields for diffing."""
    fields = [
        "risk_category", "asset_system", "business_process", "threat_description",
        "vulnerability_detail", "threat_actor_type", "attack_vector",
        "threat_intel_source", "likelihood", "impact", "existing_controls",
        "control_type", "control_effectiveness", "last_control_test_date",
        "control_test_result", "assurance_source", "risk_velocity",
        "detection_capability", "risk_owner", "escalation_path",
        "acceptance_sign_off_by", "acceptance_sign_off_date",
        "min_financial_exposure", "max_financial_exposure",
        "regulatory_obligation", "related_incident_ref", "treatment",
        "remediation_action", "action_owner", "due_date", "status",
        "date_identified", "last_reviewed", "review_frequency",
        "board_reporting_flag", "evidence_links", "notes_history",
        "nist_csf_function", "nist_csf_category", "nist_csf_subcategory",
    ]
    return {f: getattr(risk, f) for f in fields}


def _diff(old: dict, new: dict) -> dict:
    return {
        k: (old[k], new[k])
        for k in old
        if str(old[k]) != str(new[k])
    }


def _auto_trend_entry(risk: Risk):
    """Add a trend log entry when likelihood/impact/effectiveness changes."""
    residual = risk.residual_risk_score
    if residual is None:
        return
    entry = TrendLog(
        risk_id=risk.id,
        review_date=date.today(),
        residual_score=residual,
        rag_status=risk.rag_status,
        reviewer=current_user.name,
        control_test_result=risk.control_test_result,
        notes="Auto-logged on save.",
    )
    # Set change vs prior
    prior = (
        TrendLog.query.filter_by(risk_id=risk.id)
        .order_by(TrendLog.review_date.desc())
        .first()
    )
    if prior and prior.residual_score is not None:
        entry.change_vs_prior = round(residual - prior.residual_score, 1)
    db.session.add(entry)
