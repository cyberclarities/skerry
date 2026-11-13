"""Spotlight ingest queue: review, triage, and elevate to risk.

Route map:

    /ingest/                 host rollup -- the default working view
    /ingest/findings         flat finding list with filters
    /ingest/host/<aid>       one host, its findings, elevate button
    /ingest/cve/<cve_id>     one CVE across hosts, for a widespread issue
    /ingest/elevate          GET the pre-filled form, POST creates the risk
    /ingest/triage           bulk mark Triaged / Dismissed
    /ingest/delete           bulk delete as noise (remembered; see below)
    /ingest/hosts/delete     bulk delete whole hosts no longer in CrowdStrike
    /ingest/deleted          what was deleted, by whom, and whether it can return
    /ingest/sync             manual pull (admin)
    /ingest/runs             sync history

Read access follows the app's normal login requirement. Elevation and
triage are operator-or-above; running a sync and testing credentials are
admin-only, because those touch an external system with a stored key.
"""

from datetime import date, datetime, timedelta, timezone
from math import ceil

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import case, func, or_
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
from app.spotlight.client import SpotlightError
from app.spotlight.ingest import OPEN as OPEN_STATUSES
from app.spotlight.ingest import client_from_config, run_sync, start_background_sync
from app.spotlight.maintenance import delete_findings, delete_hosts, restore_deletion

ingest_bp = Blueprint("ingest", __name__, url_prefix="/ingest")

MAX_SELECTION = 2000  # guardrail: one risk covering 2000 findings is a mistake
ROWS_PER_PAGE = 100   # host, CVE, and deleted-findings lists
MAX_HOST_DELETE = 500  # per action; past that, narrow the filter first
STALE_OPTIONS = (0, 14, 30, 60, 90)  # "not seen in Falcon for N+ days"


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


def _flag(name, source=None):
    source = request.args if source is None else source
    return source.get(name, "") in ("1", "true", "on", "yes")


def _filters(source=None):
    """The queue filters, read from the query string by default.

    A bulk action passes request.form instead, so the server re-applies the
    exact filters the operator was looking at rather than trusting a list
    of row ids built in the browser.
    """
    src = request.args if source is None else source
    return {
        "q": src.get("q", "").strip(),
        "severity": src.get("severity", "").strip(),
        "exprt": src.get("exprt", "").strip(),
        "state": src.get("state", "").strip(),
        "ptype": src.get("ptype", "").strip(),
        "kev": _flag("kev", src),
        "kev_overdue": _flag("kev_overdue", src),
        "internet": _flag("internet", src),
        "include_closed": _flag("include_closed", src),
        "include_handled": _flag("include_handled", src),
        "stale": _int(src.get("stale")),
    }


def _int(value):
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _naive_utc_now():
    """The app stores naive UTC (see spotlight/client.py parse_ts)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


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
    if f.get("kev_overdue"):
        # Matches the dashboard's "KEV past CISA due" (app/assurance.py).
        query = query.filter(SpotlightFinding.is_cisa_kev.is_(True),
                             SpotlightFinding.cisa_due_date < date.today())
    if f.get("stale"):
        # Falcon's own last check-in for the agent. A host retired from
        # CrowdStrike stops checking in, so this is how it shows itself.
        # Unknown last-seen is not shown to be stale, so it is left out.
        cutoff = _naive_utc_now() - timedelta(days=f["stale"])
        gone = db.session.query(SpotlightHost.aid).filter(
            SpotlightHost.last_seen.isnot(None), SpotlightHost.last_seen < cutoff)
        query = query.filter(SpotlightFinding.aid.in_(gone))
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
    return {"product_types": [t[0] for t in types], "stale_options": STALE_OPTIONS}


# -- views --------------------------------------------------------------------
@ingest_bp.route("/")
@login_required
def index():
    """Host rollup. One row per host, worst-first -- the default working view.

    The counting runs in SQL, one row per host. Loading every finding into
    Python to count them is what took this page down on a large tenant.
    """
    f = _filters()
    sev = func.upper(SpotlightFinding.cve_severity)
    query = (
        _apply_filters(_base_query(f["include_closed"], f["include_handled"]), f)
        .filter(SpotlightFinding.aid.isnot(None))
        .with_entities(
            SpotlightFinding.aid.label("aid"),
            func.count(SpotlightFinding.id).label("count"),
            func.sum(case((sev == "CRITICAL", 1), else_=0)).label("critical"),
            func.sum(case((sev == "HIGH", 1), else_=0)).label("high"),
            func.sum(case((SpotlightFinding.is_cisa_kev.is_(True), 1), else_=0)).label("kev"),
            _rank(SpotlightFinding.cve_severity).label("worst_rank"),
            func.max(SpotlightFinding.cve_base_score).label("max_cvss"),
            func.min(SpotlightFinding.created_timestamp).label("oldest"),
            func.max(SpotlightFinding.hostname).label("hostname"),
        )
        .group_by(SpotlightFinding.aid)
    )

    today = date.today()
    grouped = []
    for r in query.all():
        grouped.append({
            "aid": r.aid,
            "count": r.count,
            "critical": r.critical or 0,
            "high": r.high or 0,
            "kev": r.kev or 0,
            "worst_rank": r.worst_rank or 0,
            "worst": RANK_TITLE.get(r.worst_rank, "None"),
            "max_cvss": r.max_cvss or 0,
            "oldest_days": (today - r.oldest.date()).days if r.oldest else None,
            "hostname": r.hostname,
        })
    grouped.sort(key=lambda r: (r["kev"], r["worst_rank"], r["max_cvss"], r["count"]),
                 reverse=True)

    page = max(request.args.get("page", 1, type=int), 1)
    pages = max(ceil(len(grouped) / ROWS_PER_PAGE), 1)
    page = min(page, pages)
    rows = grouped[(page - 1) * ROWS_PER_PAGE: page * ROWS_PER_PAGE]

    # Host details for this page only.
    hosts = {h.aid: h for h in SpotlightHost.query.filter(
        SpotlightHost.aid.in_([r["aid"] for r in rows]))} if rows else {}
    now = _naive_utc_now()
    for r in rows:
        host = hosts.get(r["aid"])
        r["host"] = host
        r["last_seen"] = host.last_seen if host else None
        r["last_seen_days"] = (now - host.last_seen).days if host and host.last_seen else None
        r["hostname"] = (host.hostname if host else None) or r["hostname"] or r["aid"]
        r["internet"] = host.internet_exposure if host else None
        r["criticality"] = host.asset_criticality if host else None
        r["product_type"] = host.product_type_desc if host else None

    args = dict(request.args.items())

    def page_url(p):
        return url_for("ingest.index", **{**args, "page": p})

    return render_template(
        "ingest/index.html",
        rows=rows,
        total_hosts=len(grouped),
        page=page,
        pages=pages,
        page_url=page_url,
        filters=f,
        totals=_totals(),
        last_run=_last_run(),
        states=INGEST_STATES,
    )


@ingest_bp.route("/hosts/delete", methods=["POST"])
@operator_required
def hosts_delete():
    """Bulk delete hosts that are no longer in CrowdStrike, with their findings.

    The selection is a list of agent IDs, checked one by one on the host
    view. Every finding on each host goes, whatever the filters on screen
    said, because the host is what is being removed, not a slice of it.
    Each finding is remembered exactly as the per-finding Delete does it, so
    tonight's sync does not put a retired host back. Findings on a risk stay,
    and so does their host row.
    """
    aids = [a.strip() for a in request.form.getlist("aids") if a.strip()]
    reason = (request.form.get("reason") or "").strip()
    back = _safe_next(request.form.get("back"), url_for("ingest.index"))
    if not aids:
        flash("No hosts selected.", "warning")
        return redirect(back)
    if len(set(aids)) > MAX_HOST_DELETE:
        flash(f"Host delete is capped at {MAX_HOST_DELETE} hosts at a time. "
              f"Narrow the filter and run it again.", "warning")
        return redirect(back)

    summary = delete_hosts(aids, current_user, reason or None)
    db.session.commit()

    hosts, kept = summary["hosts"], summary["kept"]
    if hosts:
        message = (f"{len(hosts)} host(s) deleted with {summary['findings']} finding(s). "
                   f"If Spotlight still reports them, they stay out; if a host "
                   f"comes back to Falcon after a sync has stopped seeing it, it "
                   f"returns to the queue.")
    else:
        message = "No hosts deleted."
    if kept:
        shown = ", ".join(kept[:5]) + (f" and {len(kept) - 5} more" if len(kept) > 5 else "")
        message += (f" {len(kept)} host(s) kept because they have findings on a risk "
                    f"({shown}); their other findings were deleted.")
    flash(message, "success" if hosts else "warning")
    # A deleted host has no page to go back to.
    if any(f"/ingest/host/{a}" in back for a in aids):
        back = url_for("ingest.index")
    return redirect(back)


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


# -- CVE rollup ---------------------------------------------------------------
AGE_OPTIONS = (0, 30, 60, 90, 180)
DEFAULT_MIN_AGE = 60
RANK_TITLE = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}
CVE_SORTS = {
    # oldest exposure first, then known-exploited, then score
    "age": lambda r: (r["age"] if r["age"] is not None else -1, r["kev"], r["cvss"] or 0),
    "risk": lambda r: (r["kev"], r["exprt_rank"], r["cvss"] or 0, r["hosts"]),
    "hosts": lambda r: (r["hosts"], r["kev"], r["cvss"] or 0),
    # A-Z by product, so every CVE for one product sits together. Within a
    # product, the oldest first: that is usually the one worth keeping.
    "product": lambda r: ((r["product"] or "\uffff").lower(),
                          -(r["age"] if r["age"] is not None else -1)),
}
ASCENDING_SORTS = {"product"}
MAX_CVE_DELETE = 500  # per action; past that, narrow the filter first


def _rank(column):
    """Severity words to numbers, so MAX() means worst rather than alphabetical."""
    return func.max(case(
        (func.upper(column) == "CRITICAL", 4),
        (func.upper(column) == "HIGH", 3),
        (func.upper(column) == "MEDIUM", 2),
        (func.upper(column) == "LOW", 1),
        else_=0,
    ))


@ingest_bp.route("/cves")
@login_required
def cves():
    """One row per CVE, oldest exposure first. The review step before elevation.

    Age is how long the CVE has been open on our hosts: today minus the
    earliest Spotlight created_timestamp across its findings. That is the
    exposure window we own. The publish date is shown beside it, but a CVE
    published two years ago that landed on a new server last week is a
    last-week problem, not a two-year one.

    The grouping runs in SQL. Pulling every finding into Python to count
    them is what took the host view down on a large tenant.
    """
    f = _filters()
    min_age = request.args.get("min_age", DEFAULT_MIN_AGE, type=int)
    if min_age < 0:
        min_age = 0
    sort = request.args.get("sort", "age")
    if sort not in CVE_SORTS:
        sort = "age"

    query = (
        _apply_filters(_base_query(f["include_closed"], f["include_handled"]), f)
        .filter(SpotlightFinding.cve_id.isnot(None))
        .with_entities(
            SpotlightFinding.cve_id.label("cve_id"),
            func.count(SpotlightFinding.id).label("findings"),
            func.count(func.distinct(SpotlightFinding.aid)).label("hosts"),
            func.max(SpotlightFinding.cve_base_score).label("cvss"),
            _rank(SpotlightFinding.cve_severity).label("sev_rank"),
            _rank(SpotlightFinding.exprt_rating).label("exprt_rank"),
            func.max(case((SpotlightFinding.is_cisa_kev.is_(True), 1), else_=0)).label("kev"),
            func.max(SpotlightFinding.exploit_status).label("exploit_status"),
            func.min(SpotlightFinding.created_timestamp).label("oldest"),
            func.min(SpotlightFinding.cve_published_date).label("published"),
            func.min(SpotlightFinding.cisa_due_date).label("cisa_due"),
            func.max(SpotlightFinding.product_name_version).label("product"),
        )
        .group_by(SpotlightFinding.cve_id)
    )

    today = date.today()
    shown, hidden = [], 0
    for r in query.all():
        age = (today - r.oldest.date()).days if r.oldest else None
        # Unknown age cannot be shown to be over the line, so it waits with
        # the younger ones rather than jumping the queue.
        if min_age and (age is None or age < min_age):
            hidden += 1
            continue
        shown.append({
            "cve_id": r.cve_id,
            "findings": r.findings,
            "hosts": r.hosts,
            "cvss": r.cvss,
            "severity": RANK_TITLE.get(r.sev_rank),
            "exprt": RANK_TITLE.get(r.exprt_rank),
            "exprt_rank": r.exprt_rank or 0,
            "kev": r.kev or 0,
            "exploit_status": r.exploit_status,
            "age": age,
            "published": r.published.date() if r.published else None,
            "cisa_due": r.cisa_due,
            "product": (r.product or "").split(", ")[0] or None,
        })
    shown.sort(key=CVE_SORTS[sort], reverse=sort not in ASCENDING_SORTS)

    page = max(request.args.get("page", 1, type=int), 1)
    pages = max(ceil(len(shown) / ROWS_PER_PAGE), 1)
    page = min(page, pages)
    rows = shown[(page - 1) * ROWS_PER_PAGE: page * ROWS_PER_PAGE]

    # Links carry the operator's filters. The CVE page gets the host filters
    # (type, internet-facing, and so on) but not the rollup's own age, sort,
    # and page, which mean nothing inside one CVE.
    args = {k: v for k, v in request.args.items()}
    carry = {k: v for k, v in args.items() if k not in ("min_age", "sort", "page")}

    def page_url(p):
        return url_for("ingest.cves", **{**args, "page": p})

    return render_template(
        "ingest/cves.html",
        rows=rows,
        total_shown=len(shown),
        total_findings=sum(r["findings"] for r in shown),
        hidden=hidden,
        min_age=min_age,
        age_options=AGE_OPTIONS,
        sort=sort,
        sort_links={s: url_for("ingest.cves", **{**args, "sort": s, "page": 1})
                    for s in CVE_SORTS},
        carry=carry,
        page=page,
        pages=pages,
        page_url=page_url,
        filters=f,
        totals=_totals(),
        last_run=_last_run(),
        states=INGEST_STATES,
    )


@ingest_bp.route("/cves/delete", methods=["POST"])
@operator_required
def cves_delete():
    """Bulk delete whole CVEs as noise, within the filters on screen.

    The typical case: one product carries a dozen CVEs, the same patch fixes
    all of them, and one row in the queue says everything the other eleven
    do. Keep that one, delete the rest.

    Each finding is deleted exactly as the per-finding Delete does it: the
    host+CVE is remembered, it stays out while Spotlight reports it open,
    and it comes back if it closes and later reopens. Findings on a risk are
    left alone. The scope is what the operator was looking at: if the view
    was filtered to servers, only server findings for these CVEs go.
    """
    cve_ids = sorted({c.strip() for c in request.form.getlist("cve_ids") if c.strip()})
    reason = (request.form.get("reason") or "").strip()
    back = _safe_next(request.form.get("back"), url_for("ingest.cves"))
    if not cve_ids:
        flash("No CVEs selected.", "warning")
        return redirect(back)
    if len(cve_ids) > MAX_CVE_DELETE:
        flash(f"Bulk delete is capped at {MAX_CVE_DELETE} CVEs at a time. "
              f"Narrow the filter and run it again.", "warning")
        return redirect(back)

    f = _filters(request.form)
    findings = (_apply_filters(_base_query(f["include_closed"], f["include_handled"]), f)
                .filter(SpotlightFinding.cve_id.in_(cve_ids))
                .all())
    if not findings:
        flash("Nothing matched those CVEs under the current filters; "
              "nothing was deleted.", "info")
        return redirect(back)

    deleted, skipped = delete_findings(findings, current_user, reason or None)
    gone = len({x.cve_id for x in deleted})  # read before commit detaches them
    db.session.commit()

    message = (f"{len(deleted)} finding(s) across {gone} CVE(s) deleted. "
               f"They stay out of the queue unless they close and reopen.")
    if skipped:
        message += (f" {len(skipped)} left in place because they are attached to a "
                    f"risk.")
    flash(message, "success" if deleted else "warning")
    return redirect(back)


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
              f"scope; a risk that broad will not be actionable.", "warning")
        return redirect(url_for("ingest.index"))

    findings = elevate_mod.selected_findings(ids)
    if not findings:
        abort(404)

    already = [f for f in findings if f.elevation_id]
    if len(already) == len(findings):
        flash("Every finding selected has already been elevated.", "info")
        return redirect(url_for("ingest.index"))

    # A POST from the host, CVE, or finding pages carries only the selection.
    # It opens the pre-filled form for review. Only the form itself, which
    # carries confirm_elevate, creates the risk.
    if request.method == "POST" and request.form.get("confirm_elevate") == "1":
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
            flash("Nothing to elevate. All selected findings are already on a risk.",
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
                    f"risk. Remove the finding from the risk, or delete the risk, "
                    f"to return it to the queue.")
    flash(message, "success" if deleted else "warning")
    return redirect(back)


@ingest_bp.route("/deleted")
@login_required
def deleted():
    """Newest first, paged: a bulk CVE delete can add thousands in one click."""
    page = request.args.get("page", 1, type=int)
    pagination = (SpotlightDeletion.query
                  .order_by(SpotlightDeletion.deleted_at.desc(), SpotlightDeletion.id.desc())
                  .paginate(page=page, per_page=ROWS_PER_PAGE, error_out=False))
    return render_template("ingest/deleted.html", deletions=pagination.items,
                           pagination=pagination)


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
        flash("That finding is attached to a risk. Remove it from the risk, or "
              "delete the risk, to return it to the queue.", "warning")
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
    """Start a manual sync on a background thread and return at once.

    Missing or malformed credentials fail here, in the request, so the
    operator sees why straight away instead of on a page refresh.
    """
    from flask import current_app
    fql = (request.form.get("fql_filter") or "").strip() or None
    try:
        client_from_config(current_app.config)
    except SpotlightError:
        run = run_sync(current_app, trigger="manual", user_id=current_user.id, fql_filter=fql)
        flash(f"Sync failed: {run.error_message}", "danger")
        return redirect(url_for("ingest.runs"))

    _thread, message = start_background_sync(
        current_app._get_current_object(), user_id=current_user.id, fql_filter=fql)
    flash(message, "info" if _thread else "warning")
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
        schedule_minute=current_app.config.get("SPOTLIGHT_SYNC_MINUTE", 0),
        running=any(r.status == "running" for r in history),
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
            SpotlightFinding.is_suppressed.is_(False),
            SpotlightFinding.ingest_state.in_((INGEST_NEW, INGEST_TRIAGED)),
        ).scalar() or 0,
    }


def _last_run():
    return SpotlightSyncRun.query.order_by(SpotlightSyncRun.started_at.desc()).first()
