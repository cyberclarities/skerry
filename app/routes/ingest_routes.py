"""Spotlight ingest queue: review, triage, and elevate to risk.

Route map:

    /ingest/                 host rollup -- the default working view
    /ingest/findings         flat finding list with filters
    /ingest/host/<aid>       one host, its findings, elevate button
    /ingest/cve/<cve_id>     one CVE across hosts, for a widespread issue
    /ingest/elevate          GET the pre-filled form, POST creates the risk
    /ingest/triage           bulk mark Triaged / Dismissed
    /ingest/delete           bulk delete as noise (remembered; see below)
    /ingest/deleted          what was deleted, by whom, and whether it can return
    /ingest/sync             manual pull (admin)
    /ingest/runs             sync history

Read access follows the app's normal login requirement. Elevation and
triage are operator-or-above; running a sync and testing credentials are
admin-only, because those touch an external system with a stored key.
"""

from datetime import date

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.decorators import admin_required, log_audit, operator_required
from app.models import NISTCSFReference, db
from app.models_spotlight import (INGEST_DISMISSED, INGEST_ELEVATED, INGEST_NEW,
                                  INGEST_STATES, INGEST_TRIAGED,
                                  SpotlightDeletion, SpotlightElevation,
                                  SpotlightFinding, SpotlightHost, SpotlightSyncRun)
from app.routes.auth_routes import _safe_next
from app.routes.risk_routes import (CONTROL_TYPES, RISK_CATEGORIES, STATUSES,
                                    TREATMENTS, VELOCITIES, _lookup, _next_risk_id)
from app.scoring import CONTROL_EFFECTIVENESS_LABELS, IMPACT_LABELS, LIKELIHOOD_LABELS
from app.spotlight import elevate as elevate_mod
from app.spotlight.ingest import client_from_config, run_sync
from app.spotlight.maintenance import delete_findings, restore_deletion

ingest_bp = Blueprint("ingest", __name__, url_prefix="/ingest")

OPEN_STATUSES = ("open", "reopen")
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
MAX_SELECTION = 2000  # guardrail: one risk covering 2000 findings is a mistake


def _base_query(include_closed=False, include_handled=False):
    """The queue, minus noise, unless the operator asks for the noise.

    Suppressed findings are excluded by default -- somebody in Falcon already
    made a decision about those, and re-litigating it here just buries the
    findings nobody has looked at yet.
    """
    query = SpotlightFinding.query
    if not include_closed:
        query = query.filter(SpotlightFinding.spotlight_status.in_(OPEN_STATUSES))
        query = query.filter(SpotlightFinding.is_suppressed.is_(False))
    if not include_handled:
        query = query.filter(SpotlightFinding.ingest_state.in_((INGEST_NEW, INGEST_TRIAGED)))
    return query


def _flag(name):
    return request.args.get(name, "") in ("1", "true", "on", "yes")


def _filters():
    return {
        "q": request.args.get("q", "").strip(),
        "severity": request.args.get("severity", "").strip(),
        "exprt": request.args.get("exprt", "").strip(),
        "state": request.args.get("state", "").strip(),
        "ptype": request.args.get("ptype", "").strip(),
        "kev": _flag("kev"),
        "internet": _flag("internet"),
        "include_closed": _flag("include_closed"),
        "include_handled": _flag("include_handled"),
    }


def _apply_filters(query, f):
    if f["q"]:
        term = f"%{f['q']}%"
        query = query.filter(or_(
            SpotlightFinding.hostname.ilike(term),
            SpotlightFinding.cve_id.ilike(term),
            SpotlightFinding.product_name_version.ilike(term),
        ))
    if f["severity"]:
        query = query.filter(SpotlightFinding.cve_severity == f["severity"].upper())
    if f["exprt"]:
        query = query.filter(SpotlightFinding.exprt_rating == f["exprt"].upper())
    if f["state"]:
        query = query.filter(SpotlightFinding.ingest_state == f["state"])
    if f["ptype"]:
        typed = db.session.query(SpotlightHost.aid).filter(
            SpotlightHost.product_type_desc == f["ptype"]
        )
        query = query.filter(SpotlightFinding.aid.in_(typed))
    if f["kev"]:
        query = query.filter(SpotlightFinding.is_cisa_kev.is_(True))
    if f["internet"]:
        exposed = db.session.query(SpotlightHost.aid).filter(
            func.lower(SpotlightHost.internet_exposure) == "yes"
        )
        query = query.filter(SpotlightFinding.aid.in_(exposed))
    return query


@ingest_bp.context_processor
def _product_types():
    """Host types for the filter bar, read from what Spotlight actually sent.

    Built from the data rather than hard-coded, because Falcon's labels
    (Workstation, Server, Domain Controller) are its vocabulary, not ours.
    """
    types = (db.session.query(SpotlightHost.product_type_desc)
             .filter(SpotlightHost.product_type_desc.isnot(None),
                     SpotlightHost.product_type_desc != "")
             .distinct()
             .order_by(SpotlightHost.product_type_desc)
             .all())
    return {"product_types": [t[0] for t in types]}


# -- views --------------------------------------------------------------------
@ingest_bp.route("/")
@login_required
def index():
    """Host rollup. One row per host, worst-first -- the default working view."""
    f = _filters()
    query = _apply_filters(
        _base_query(f["include_closed"], f["include_handled"]), f
    )
    findings = query.all()

    by_aid = {}
    for finding in findings:
        by_aid.setdefault(finding.aid, []).append(finding)

    hosts = {
        h.aid: h for h in
        SpotlightHost.query.filter(SpotlightHost.aid.in_(by_aid.keys())).all()
    } if by_aid else {}

    rows = []
    for aid, host_findings in by_aid.items():
        host = hosts.get(aid)
        severities = [(f_.cve_severity or "NONE").upper() for f_ in host_findings]
        worst = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0)) if severities else "NONE"
        ages = [f_.days_open for f_ in host_findings if f_.days_open is not None]
        rows.append({
            "aid": aid,
            "host": host,
            "hostname": (host.hostname if host else None) or host_findings[0].hostname or aid,
            "count": len(host_findings),
            "critical": len([s for s in severities if s == "CRITICAL"]),
            "high": len([s for s in severities if s == "HIGH"]),
            "kev": len([f_ for f_ in host_findings if f_.is_cisa_kev]),
            "worst": worst.capitalize(),
            "worst_rank": SEVERITY_ORDER.get(worst, 0),
            "max_cvss": max((f_.cve_base_score or 0) for f_ in host_findings),
            "oldest_days": max(ages) if ages else None,
            "internet": (host.internet_exposure if host else None),
            "criticality": (host.asset_criticality if host else None),
            "product_type": (host.product_type_desc if host else None),
        })

    rows.sort(key=lambda r: (r["kev"], r["worst_rank"], r["max_cvss"], r["count"]),
              reverse=True)

    return render_template(
        "ingest/index.html",
        rows=rows,
        filters=f,
        totals=_totals(),
        last_run=_last_run(),
        states=INGEST_STATES,
    )


@ingest_bp.route("/findings")
@login_required
def findings():
    """Flat list. Use this to work a single CVE across the estate."""
    f = _filters()
    query = _apply_filters(_base_query(f["include_closed"], f["include_handled"]), f)
    page = request.args.get("page", 1, type=int)
    pagination = query.order_by(
        SpotlightFinding.is_cisa_kev.desc(),
        SpotlightFinding.cve_base_score.desc(),  # SQLite orders NULLs last on DESC
        SpotlightFinding.hostname,
    ).paginate(page=page, per_page=100, error_out=False)

    return render_template(
        "ingest/findings.html",
        pagination=pagination,
        findings=pagination.items,
        filters=f,
        totals=_totals(),
        last_run=_last_run(),
        states=INGEST_STATES,
    )


@ingest_bp.route("/host/<aid>")
@login_required
def host_detail(aid):
    host = SpotlightHost.query.filter_by(aid=aid).first_or_404()
    f = _filters()
    query = _base_query(f["include_closed"], f["include_handled"]).filter(
        SpotlightFinding.aid == aid)
    host_findings = query.order_by(
        SpotlightFinding.is_cisa_kev.desc(),
        SpotlightFinding.cve_base_score.desc(),  # SQLite orders NULLs last on DESC
    ).all()

    proposal = elevate_mod.build_proposal(host_findings) if host_findings else {}
    elevations = (
        SpotlightElevation.query
        .filter(SpotlightElevation.scope_aids.contains(aid))
        .order_by(SpotlightElevation.created_at.desc())
        .all()
    )
    return render_template(
        "ingest/host_detail.html",
        host=host,
        findings=host_findings,
        proposal=proposal,
        elevations=elevations,
        filters=f,
    )


@ingest_bp.route("/cve/<cve_id>")
@login_required
def cve_detail(cve_id):
    """One CVE across every affected host -- the widespread-issue view."""
    f = _filters()
    query = _base_query(f["include_closed"], f["include_handled"]).filter(
        SpotlightFinding.cve_id == cve_id)
    cve_findings = query.order_by(SpotlightFinding.hostname).all()
    if not cve_findings:
        abort(404)

    proposal = elevate_mod.build_proposal(cve_findings)
    return render_template(
        "ingest/cve_detail.html",
        cve_id=cve_id,
        findings=cve_findings,
        proposal=proposal,
        sample=cve_findings[0],
        filters=f,
    )


# -- elevation ----------------------------------------------------------------
@ingest_bp.route("/elevate", methods=["GET", "POST"])
@operator_required
def elevate():
    """Pre-filled risk form on GET; creates the risk on POST.

    The scores arrive suggested, not decided. Nothing is written until an
    operator submits -- see spotlight/scoring.py for what the suggestion is
    built from and why.
    """
    ids = request.values.getlist("finding_ids", type=int)
    if not ids:
        flash("Select at least one finding to elevate.", "warning")
        return redirect(url_for("ingest.index"))
    if len(ids) > MAX_SELECTION:
        flash(f"Selection is capped at {MAX_SELECTION} findings. Narrow the "
              f"scope -- a risk that broad will not be actionable.", "warning")
        return redirect(url_for("ingest.index"))

    findings = elevate_mod.selected_findings(ids)
    if not findings:
        abort(404)

    already = [f for f in findings if f.elevation_id]
    if len(already) == len(findings):
        flash("Every finding selected has already been elevated.", "info")
        return redirect(url_for("ingest.index"))

    if request.method == "POST":
        try:
            risk, elevation, skipped = elevate_mod.elevate(
                findings, request.form, current_user, _next_risk_id()
            )
        except IntegrityError:
            # Another save took this risk ID between read and write.
            db.session.rollback()
            flash("That risk ID was taken by a save happening at the same "
                  "moment. Nothing was changed; submit again.", "warning")
            return redirect(url_for("ingest.index"))
        if risk is None:
            flash("Nothing to elevate — all selected findings are already on a risk.",
                  "info")
            return redirect(url_for("ingest.index"))

        log_audit(risk, current_user, "created")
        log_audit(risk, current_user, "updated", {
            "spotlight_elevation": (
                None,
                f"{elevation.finding_count} Spotlight finding(s) across "
                f"{elevation.host_count} host(s): {elevation.scope_label}",
            )
        })
        db.session.commit()

        message = (f"Risk {risk.risk_id} created from {elevation.finding_count} "
                   f"Spotlight finding(s).")
        if skipped:
            message += f" {len(skipped)} already-elevated finding(s) were left alone."
        flash(message, "success")
        return redirect(url_for("risks.detail", risk_pk=risk.id))

    eligible = [f for f in findings if not f.elevation_id]
    proposal = elevate_mod.build_proposal(eligible)
    return render_template(
        "ingest/elevate_form.html",
        proposal=proposal,
        findings=eligible,
        already=already,
        next_id=_next_risk_id(),
        today=date.today().isoformat(),
        risk_categories=RISK_CATEGORIES,
        control_types=CONTROL_TYPES,
        velocities=VELOCITIES,
        treatments=TREATMENTS,
        statuses=STATUSES,
        threat_actors=_lookup("threat_actor_type"),
        attack_vectors=_lookup("attack_vector"),
        risk_owners=_lookup("risk_owner"),
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
        effectiveness_labels=CONTROL_EFFECTIVENESS_LABELS,
        nist_subcategories=_csf_subcategories(),
    )


@ingest_bp.route("/triage", methods=["POST"])
@operator_required
def triage():
    """Bulk mark Triaged or Dismissed. Dismissal requires a reason."""
    ids = request.form.getlist("finding_ids", type=int)
    action = request.form.get("action", "")
    reason = (request.form.get("reason") or "").strip()
    back = _safe_next(request.form.get("back"), url_for("ingest.index"))

    if not ids:
        flash("No findings selected.", "warning")
        return redirect(back)

    state = {"triage": INGEST_TRIAGED, "dismiss": INGEST_DISMISSED}.get(action)
    if state is None:
        abort(400)
    if state == INGEST_DISMISSED and not reason:
        flash("Dismissing a finding needs a reason. Say why, so the next "
              "person reading this queue knows it was a decision.", "warning")
        return redirect(back)

    findings = elevate_mod.selected_findings(ids)
    changed = elevate_mod.set_state(findings, state, current_user, reason or None)
    db.session.commit()
    flash(f"{changed} finding(s) marked {state}.", "success")
    return redirect(back)


@ingest_bp.route("/delete", methods=["POST"])
@operator_required
def delete():
    """Delete findings as noise. They stay out of the queue while Spotlight
    keeps reporting them open; if they close and later reappear, they return.
    Findings attached to a risk are refused: they are that risk's evidence."""
    ids = request.form.getlist("finding_ids", type=int)
    reason = (request.form.get("reason") or "").strip()
    back = _safe_next(request.form.get("back"), url_for("ingest.index"))
    if not ids:
        flash("No findings selected.", "warning")
        return redirect(back)

    deleted, skipped = delete_findings(elevate_mod.selected_findings(ids),
                                       current_user, reason or None)
    db.session.commit()
    message = f"{len(deleted)} finding(s) deleted."
    if deleted:
        message += " They will stay out of the queue unless they close and reopen."
    if skipped:
        message += (f" {len(skipped)} left in place because they are attached to a "
                    f"risk; remove them from the risk first.")
    flash(message, "success" if deleted else "warning")
    return redirect(back)


@ingest_bp.route("/deleted")
@login_required
def deleted():
    rows = SpotlightDeletion.query.order_by(SpotlightDeletion.deleted_at.desc()).all()
    return render_template("ingest/deleted.html", deletions=rows)


@ingest_bp.route("/deleted/<int:deletion_id>/restore", methods=["POST"])
@operator_required
def restore(deletion_id):
    mark = db.get_or_404(SpotlightDeletion, deletion_id)
    label = f"{mark.cve_id} on {mark.hostname or mark.aid}"
    restore_deletion(mark)
    db.session.commit()
    flash(f"Restored {label}. It returns to the queue on the next sync if "
          f"Spotlight still reports it.", "success")
    return redirect(url_for("ingest.deleted"))


@ingest_bp.route("/finding/<int:finding_id>/reopen", methods=["POST"])
@operator_required
def reopen(finding_id):
    """Put a dismissed finding back in the queue."""
    finding = db.session.get(SpotlightFinding, finding_id) or abort(404)
    back = _safe_next(request.form.get("back"), url_for("ingest.index"))
    if finding.elevation_id:
        flash("That finding is attached to a risk; unpick it there first.", "warning")
        return redirect(back)
    finding.ingest_state = INGEST_NEW
    finding.dismissed_reason = None
    finding.dismissed_at = None
    finding.dismissed_by_id = None
    db.session.commit()
    flash("Finding returned to the queue.", "success")
    return redirect(back)


# -- sync ---------------------------------------------------------------------
@ingest_bp.route("/sync", methods=["POST"])
@admin_required
def sync():
    from flask import current_app
    fql = (request.form.get("fql_filter") or "").strip() or None
    run = run_sync(current_app, trigger="manual", user_id=current_user.id, fql_filter=fql)
    if run.status == "success":
        flash(
            f"Sync complete: {run.records_fetched} record(s) fetched, "
            f"{run.findings_created} new, {run.findings_updated} updated, "
            f"{run.findings_closed} closed"
            + (f", {run.parse_errors} skipped" if run.parse_errors else "")
            + ".",
            "success" if not run.parse_errors else "warning",
        )
    else:
        flash(f"Sync failed: {run.error_message}", "danger")
    return redirect(url_for("ingest.runs"))


@ingest_bp.route("/sync/reconcile", methods=["POST"])
@admin_required
def reconcile():
    """Mark register findings Remediated where Spotlight says the CVE closed."""
    updated = elevate_mod.sync_elevated_statuses()
    flash(f"{updated} elevated finding(s) marked Remediated.", "success")
    return redirect(url_for("ingest.runs"))


@ingest_bp.route("/runs")
@admin_required
def runs():
    from flask import current_app
    history = (SpotlightSyncRun.query
               .order_by(SpotlightSyncRun.started_at.desc()).limit(50).all())
    return render_template(
        "ingest/runs.html",
        runs=history,
        configured=bool(current_app.config.get("FALCON_CLIENT_ID")),
        default_filter=current_app.config.get("SPOTLIGHT_FQL_FILTER"),
        region=current_app.config.get("FALCON_CLOUD_REGION"),
        schedule_enabled=current_app.config.get("SPOTLIGHT_SYNC_ENABLED"),
        schedule_hour=current_app.config.get("SPOTLIGHT_SYNC_HOUR"),
        elevations=SpotlightElevation.query.order_by(
            SpotlightElevation.created_at.desc()).limit(25).all(),
    )


@ingest_bp.route("/test-connection", methods=["POST"])
@admin_required
def test_connection():
    """Credential check for the runs page. Returns JSON; never raises."""
    from flask import current_app
    try:
        client = client_from_config(current_app.config)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": str(exc)})
    ok, message = client.test_connection()
    return jsonify({"ok": ok, "message": message})


# -- helpers ------------------------------------------------------------------
def _csf_subcategories():
    return (NISTCSFReference.query
            .with_entities(NISTCSFReference.subcategory_code,
                           NISTCSFReference.description,
                           NISTCSFReference.category_code,
                           NISTCSFReference.function_code)
            .order_by(NISTCSFReference.subcategory_code).all())


def _totals():
    open_q = SpotlightFinding.query.filter(
        SpotlightFinding.spotlight_status.in_(OPEN_STATUSES),
        SpotlightFinding.is_suppressed.is_(False),
    )
    return {
        "new": open_q.filter(SpotlightFinding.ingest_state == INGEST_NEW).count(),
        "triaged": open_q.filter(SpotlightFinding.ingest_state == INGEST_TRIAGED).count(),
        "elevated": SpotlightFinding.query.filter(
            SpotlightFinding.ingest_state == INGEST_ELEVATED).count(),
        "dismissed": SpotlightFinding.query.filter(
            SpotlightFinding.ingest_state == INGEST_DISMISSED).count(),
        "deleted": SpotlightDeletion.query.count(),
        "kev": open_q.filter(
            SpotlightFinding.is_cisa_kev.is_(True),
            SpotlightFinding.ingest_state.in_((INGEST_NEW, INGEST_TRIAGED)),
        ).count(),
        "hosts": db.session.query(func.count(func.distinct(SpotlightFinding.aid))).filter(
            SpotlightFinding.spotlight_status.in_(OPEN_STATUSES),
            SpotlightFinding.ingest_state.in_((INGEST_NEW, INGEST_TRIAGED)),
        ).scalar() or 0,
    }


def _last_run():
    return SpotlightSyncRun.query.order_by(SpotlightSyncRun.started_at.desc()).first()
