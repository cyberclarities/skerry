from datetime import date
from flask import Blueprint, render_template
from flask_login import login_required
from app.models import Risk, TrendLog, NISTCSFReference

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")

NIST_FUNCTIONS = [
    ("GV", "Govern"),
    ("ID", "Identify"),
    ("PR", "Protect"),
    ("DE", "Detect"),
    ("RS", "Respond"),
    ("RC", "Recover"),
]


@reports_bp.route("/overdue")
@login_required
def overdue():
    risks = Risk.query.filter(Risk.status.notin_(["Closed", "Accepted"])).all()
    overdue_risks = [r for r in risks if r.is_overdue]
    overdue_risks.sort(key=lambda r: r.days_overdue or 0, reverse=True)
    return render_template("reports/overdue.html", risks=overdue_risks)


@reports_bp.route("/trend")
@login_required
def trend():
    risks = Risk.query.order_by(Risk.risk_id).all()
    # Build trend data: {risk_id: [TrendLog entries]}
    trend_data = {}
    for risk in risks:
        entries = risk.trend_entries.order_by(TrendLog.review_date.asc()).all()
        if entries:
            trend_data[risk.risk_id] = {
                "risk": risk,
                "entries": entries,
            }
    return render_template("reports/trend.html", trend_data=trend_data)


@reports_bp.route("/csf-coverage")
@login_required
def csf_coverage():
    risks = Risk.query.all()

    function_stats = {}
    for func_code, func_name in NIST_FUNCTIONS:
        func_risks = [r for r in risks if r.nist_csf_function == func_code]
        residuals = [r.residual_risk_score for r in func_risks if r.residual_risk_score is not None]
        function_stats[func_code] = {
            "name": func_name,
            "total": len(func_risks),
            "red": sum(1 for r in func_risks if r.rag_status == "RED"),
            "amber": sum(1 for r in func_risks if r.rag_status == "AMBER"),
            "green": sum(1 for r in func_risks if r.rag_status == "GREEN"),
            "exceeds_appetite": sum(1 for r in func_risks if r.exceeds_risk_appetite),
            "overdue": sum(1 for r in func_risks if r.is_overdue),
            "avg_residual": round(sum(residuals) / len(residuals), 1) if residuals else None,
            "not_mapped": func_code not in [r.nist_csf_function for r in risks],
        }

    # Category-level breakdown
    all_categories = (
        NISTCSFReference.query
        .with_entities(
            NISTCSFReference.function_code,
            NISTCSFReference.category_code,
            NISTCSFReference.category_name,
        )
        .distinct()
        .order_by(NISTCSFReference.function_code, NISTCSFReference.category_code)
        .all()
    )

    category_stats = {}
    for fc, cc, cn in all_categories:
        cat_risks = [r for r in risks if r.nist_csf_category == cc]
        residuals = [r.residual_risk_score for r in cat_risks if r.residual_risk_score is not None]
        category_stats[cc] = {
            "function_code": fc,
            "name": cn,
            "total": len(cat_risks),
            "red": sum(1 for r in cat_risks if r.rag_status == "RED"),
            "amber": sum(1 for r in cat_risks if r.rag_status == "AMBER"),
            "green": sum(1 for r in cat_risks if r.rag_status == "GREEN"),
            "avg_residual": round(sum(residuals) / len(residuals), 1) if residuals else None,
            "not_mapped": len(cat_risks) == 0,
        }

    unmapped = [r for r in risks if not r.nist_csf_function]

    return render_template(
        "reports/csf_coverage.html",
        function_stats=function_stats,
        category_stats=category_stats,
        nist_functions=NIST_FUNCTIONS,
        unmapped=unmapped,
    )
