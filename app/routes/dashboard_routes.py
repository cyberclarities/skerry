from datetime import date, timedelta

from flask import Blueprint, current_app, render_template
from flask_login import login_required
from app.assurance import needs_attention
from app.models import RegisterSnapshot, Risk

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    everything = Risk.query.all()

    # The dashboard shows exposure we still carry, so every figure on it
    # counts active risks only: anything not Closed. Accepted risks stay,
    # because accepting a risk does not make it go away. Before this, the
    # KPIs, charts, and exposure totals counted closed risks while the heat
    # map did not, so the top row and the heat map disagreed.
    risks = [r for r in everything if r.status != "Closed"]
    closed_count = len(everything) - len(risks)

    # KPIs
    total = len(risks)
    red_risks = [r for r in risks if r.rag_status == "RED"]
    amber_risks = [r for r in risks if r.rag_status == "AMBER"]
    green_risks = [r for r in risks if r.rag_status == "GREEN"]
    exceeds_appetite = [r for r in risks if r.exceeds_risk_appetite]
    overdue = [r for r in risks if r.is_overdue]
    board_flags = [r for r in risks if r.board_reporting_flag]

    # Heat map. Each risk sits in the cell for its likelihood x impact (the
    # inherent position). The cell shows one total. The split by current RAG
    # label, which comes from the residual score after controls, is kept per
    # cell for the hover text, so a well-controlled risk in a red cell can
    # still be seen as green. Risks missing likelihood or impact cannot be
    # placed; they are counted so the matrix total plus the unplotted count
    # equals the Active Risks figure in the top row.
    heat_map = {}
    unplotted = 0
    for r in risks:
        if r.likelihood and r.impact:
            cell = heat_map.setdefault((r.likelihood, r.impact), {})
            cell[r.rag_status] = cell.get(r.rag_status, 0) + 1
        else:
            unplotted += 1
    rag_red = current_app.config.get("RAG_RED_THRESHOLD", 15)
    rag_amber = current_app.config.get("RAG_AMBER_THRESHOLD", 9)

    # Control test results
    pass_count = sum(1 for r in risks if r.control_test_result == "Pass")
    fail_count = sum(1 for r in risks if r.control_test_result == "Fail")
    not_tested_count = sum(1 for r in risks if r.control_test_result == "Not Tested" or not r.control_test_result)

    # Threat actor breakdown
    actor_counts = {}
    for r in risks:
        if r.threat_actor_type:
            actor_counts[r.threat_actor_type] = actor_counts.get(r.threat_actor_type, 0) + 1

    # Velocity distribution
    velocity_counts = {}
    for r in risks:
        if r.risk_velocity:
            velocity_counts[r.risk_velocity] = velocity_counts.get(r.risk_velocity, 0) + 1

    # Financial exposure
    min_exposures = [r.min_financial_exposure for r in risks if r.min_financial_exposure]
    max_exposures = [r.max_financial_exposure for r in risks if r.max_financial_exposure]
    red_max = [r.max_financial_exposure for r in red_risks if r.max_financial_exposure]

    fin_stats = {
        "total_min": sum(min_exposures),
        "total_max": sum(max_exposures),
        "avg_red_max": (sum(red_max) / len(red_max)) if red_max else 0,
    }

    # Category breakdown
    category_counts = {}
    for r in risks:
        cat = r.risk_category or "Uncategorized"
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Needs attention: only things someone has to act on. The rules live in
    # app/assurance.py, shared with the reports each tile links to.
    attention = needs_attention(everything, date.today(), rag_red, rag_amber)

    # Register trend from the daily snapshots: the last 365 days.
    snapshots = (RegisterSnapshot.query
                 .filter(RegisterSnapshot.snapshot_date >= date.today() - timedelta(days=365))
                 .order_by(RegisterSnapshot.snapshot_date).all())
    first_snapshot = (RegisterSnapshot.query
                      .order_by(RegisterSnapshot.snapshot_date).first())

    return render_template(
        "dashboard.html",
        total=total,
        closed_count=closed_count,
        attention=attention,
        trend=dict(
            dates=[s.snapshot_date.isoformat() for s in snapshots],
            red=[s.red for s in snapshots],
            amber=[s.amber for s in snapshots],
            green=[s.green for s in snapshots],
        ),
        first_snapshot=first_snapshot.snapshot_date if first_snapshot else None,
        red_count=len(red_risks),
        amber_count=len(amber_risks),
        green_count=len(green_risks),
        exceeds_appetite_count=len(exceeds_appetite),
        overdue_count=len(overdue),
        board_flag_count=len(board_flags),
        heat_map=heat_map,
        heat_unplotted=unplotted,
        rag_red=rag_red,
        rag_amber=rag_amber,
        pass_count=pass_count,
        fail_count=fail_count,
        not_tested_count=not_tested_count,
        actor_counts=actor_counts,
        velocity_counts=velocity_counts,
        fin_stats=fin_stats,
        category_counts=category_counts,
        # Recent activity includes closures, so this one list uses every risk.
        recent_risks=sorted(everything, key=lambda r: r.updated_at or r.created_at, reverse=True)[:5],
    )
