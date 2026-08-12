import io
from datetime import date
from flask import Blueprint, send_file, request
from flask_login import login_required
from app.models import Risk

exports_bp = Blueprint("exports", __name__, url_prefix="/export")


@exports_bp.route("/excel")
@login_required
def export_excel():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    risks = Risk.query.order_by(Risk.id).all()
    wb = Workbook()

    # ── Risk Register sheet ──────────────────────────────────────────────────
    ws = wb.active
    ws.title = "Risk Register"

    header_fill = PatternFill("solid", fgColor="1F3864")
    section_fill = PatternFill("solid", fgColor="2E75B6")
    red_fill = PatternFill("solid", fgColor="FF0000")
    amber_fill = PatternFill("solid", fgColor="FFA500")
    green_fill = PatternFill("solid", fgColor="00B050")

    white_font = Font(bold=True, color="FFFFFF")
    bold_font = Font(bold=True)
    thin = Side(style="thin")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    sections = [
        ("CORE RISK IDENTIFICATION", 6),
        ("THREAT INTELLIGENCE", 3),
        ("RISK SCORING", 3),
        ("CONTROLS & ASSURANCE", 6),
        ("VELOCITY & DETECTION", 2),
        ("GOVERNANCE & APPETITE", 4),
        ("FINANCIAL & BUSINESS IMPACT", 4),
        ("TREATMENT & ACTIONS", 5),
        ("OPERATIONAL METADATA", 5),
        ("NIST CSF 2.0 MAPPING", 3),
    ]

    col = 1
    for section_name, span in sections:
        ws.merge_cells(start_row=1, start_column=col, end_row=1, end_column=col + span - 1)
        cell = ws.cell(row=1, column=col, value=section_name)
        cell.fill = section_fill
        cell.font = white_font
        cell.alignment = Alignment(horizontal="center")
        col += span

    headers = [
        "Risk ID", "Category", "Asset / System", "Business Process",
        "Threat Description", "Vulnerability Detail",
        "Threat Actor", "Attack Vector", "Intel Source",
        "Likelihood (1-5)", "Impact (1-5)", "Inherent Score",
        "Existing Controls", "Control Type", "Effectiveness (1-5)",
        "Last Test Date", "Test Result", "Assurance Source",
        "Risk Velocity", "Detection Capability",
        "Risk Owner", "Escalation Path", "Sign-Off By", "Sign-Off Date",
        "Min Exposure (USD)", "Max Exposure (USD)", "Regulatory Obligation", "Incident Ref",
        "Treatment", "Remediation Action", "Action Owner", "Due Date", "Status",
        "Date Identified", "Last Reviewed", "Age (Days)", "Review Freq", "Board Flag",
        "NIST Function", "NIST Category", "NIST Subcategory",
    ]

    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=2, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = white_font
        cell.alignment = Alignment(horizontal="center", wrap_text=True)
        cell.border = border

    ws.row_dimensions[2].height = 40

    for row_idx, risk in enumerate(risks, 3):
        row_data = [
            risk.risk_id, risk.risk_category, risk.asset_system, risk.business_process,
            risk.threat_description, risk.vulnerability_detail,
            risk.threat_actor_type, risk.attack_vector, risk.threat_intel_source,
            risk.likelihood, risk.impact, risk.inherent_risk_score,
            risk.existing_controls, risk.control_type, risk.control_effectiveness,
            risk.last_control_test_date, risk.control_test_result, risk.assurance_source,
            risk.risk_velocity, risk.detection_capability,
            risk.risk_owner, risk.escalation_path,
            risk.acceptance_sign_off_by, risk.acceptance_sign_off_date,
            risk.min_financial_exposure, risk.max_financial_exposure,
            risk.regulatory_obligation, risk.related_incident_ref,
            risk.treatment, risk.remediation_action, risk.action_owner,
            risk.due_date, risk.status,
            risk.date_identified, risk.last_reviewed, risk.age_days,
            risk.review_frequency,
            "Yes" if risk.board_reporting_flag else "No",
            risk.nist_csf_function, risk.nist_csf_category, risk.nist_csf_subcategory,
        ]

        for col_idx, value in enumerate(row_data, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = border
            cell.alignment = Alignment(wrap_text=True, vertical="top")

        # RAG color on residual score column (col 12 = inherent; residual not a column here)
        rag = risk.rag_status
        rag_col = ws.cell(row=row_idx, column=1)
        if rag == "RED":
            rag_col.fill = red_fill
            rag_col.font = Font(bold=True, color="FFFFFF")
        elif rag == "AMBER":
            rag_col.fill = amber_fill
        elif rag == "GREEN":
            rag_col.fill = green_fill

    # Add Residual Score column header after the fixed set
    residual_col = len(headers) + 1
    ws.cell(row=2, column=residual_col, value="Residual Score").fill = header_fill
    ws.cell(row=2, column=residual_col).font = white_font
    ws.cell(row=2, column=residual_col + 1, value="RAG").fill = header_fill
    ws.cell(row=2, column=residual_col + 1).font = white_font

    for row_idx, risk in enumerate(risks, 3):
        ws.cell(row=row_idx, column=residual_col, value=risk.residual_risk_score)
        rag_cell = ws.cell(row=row_idx, column=residual_col + 1, value=risk.rag_status)
        if risk.rag_status == "RED":
            rag_cell.fill = red_fill
            rag_cell.font = Font(bold=True, color="FFFFFF")
        elif risk.rag_status == "AMBER":
            rag_cell.fill = amber_fill
        elif risk.rag_status == "GREEN":
            rag_cell.fill = green_fill

    # Column widths
    col_widths = [10, 15, 20, 25, 40, 30, 18, 20, 18, 12, 12, 12,
                  30, 15, 15, 14, 12, 18, 12, 18, 20, 20, 18, 14,
                  16, 16, 25, 15, 12, 35, 20, 12, 12, 14, 14, 10,
                  12, 10, 12, 20, 20, 14, 12]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

    ws.freeze_panes = "A3"

    # ── Overdue Actions sheet ────────────────────────────────────────────────
    ws2 = wb.create_sheet("Overdue Actions")
    overdue_risks = [r for r in risks if r.is_overdue]
    od_headers = ["Risk ID", "Category", "Threat Description", "Owner",
                  "Due Date", "Days Overdue", "RAG", "Status", "Action"]
    for ci, h in enumerate(od_headers, 1):
        c = ws2.cell(row=1, column=ci, value=h)
        c.fill = header_fill
        c.font = white_font
    for ri, risk in enumerate(overdue_risks, 2):
        ws2.cell(row=ri, column=1, value=risk.risk_id)
        ws2.cell(row=ri, column=2, value=risk.risk_category)
        ws2.cell(row=ri, column=3, value=(risk.threat_description or "")[:80])
        ws2.cell(row=ri, column=4, value=risk.risk_owner)
        ws2.cell(row=ri, column=5, value=risk.due_date)
        ws2.cell(row=ri, column=6, value=risk.days_overdue)
        ws2.cell(row=ri, column=7, value=risk.rag_status)
        ws2.cell(row=ri, column=8, value=risk.status)
        ws2.cell(row=ri, column=9, value=risk.remediation_action)

    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    filename = f"skerry_{date.today().isoformat()}.xlsx"
    return send_file(out, download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True)
