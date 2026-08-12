from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from app.models import db, Risk

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    risks = Risk.query.all()

    # KPIs
    total = len(risks)
    red_risks = [r for r in risks if r.rag_status == "RED"]
    amber_risks = [r for r in risks if r.rag_status == "AMBER"]
    green_risks = [r for r in risks if r.rag_status == "GREEN"]
    exceeds_appetite = [r for r in risks if r.exceeds_risk_appetite]
    overdue = [r for r in risks if r.is_overdue]
    board_flags = [r for r in risks if r.board_reporting_flag]

    # Heat map: likelihood (1-5) vs impact (1-5) — count of risks per cell
    heat_map = {}
    for r in risks:
        if r.likelihood and r.impact:
            key = (r.likelihood, r.impact)
            heat_map[key] = heat_map.get(key, 0) + 1

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

    return render_template(
        "dashboard.html",
        total=total,
        red_count=len(red_risks),
        amber_count=len(amber_risks),
        green_count=len(green_risks),
        exceeds_appetite_count=len(exceeds_appetite),
        overdue_count=len(overdue),
        board_flag_count=len(board_flags),
        heat_map=heat_map,
        pass_count=pass_count,
        fail_count=fail_count,
        not_tested_count=not_tested_count,
        actor_counts=actor_counts,
        velocity_counts=velocity_counts,
        fin_stats=fin_stats,
        category_counts=category_counts,
        recent_risks=sorted(risks, key=lambda r: r.updated_at or r.created_at, reverse=True)[:5],
    )
