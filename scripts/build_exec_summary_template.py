#!/usr/bin/env python3
"""Builds the docxtpl SOURCE template for the one-page Risk Action Request,
the document that asks the CIO and CISO to mandate a course of action.

This produces a .docx with {{ jinja }} placeholders (not a filled
document), in the colors of the organization's document template (PB-000):
a navy title banner, blue subheadings, gray label fills, and light blue
headers on the options and mandate blocks. No yellow.

The page follows Background, Issue, Options, Recommendation, after a short
statement of the ask. The four options are boxes; the executives check the
one they mandate, and both sign.

Run once to (re)generate app/templates/exports/risk_exec_summary_template.docx:

    python3 scripts/build_exec_summary_template.py

Edit THIS script (not the .docx by hand) when the template needs to
change, so the Jinja tags never get fragmented across Word runs. Paired
with scripts/build_supporting_evidence_template.py; both draw their
context from app/action_request.py's build_context().
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _docx_style import (  # noqa: E402
    NAVY, BLUE, RED, GRAY, BODY_TXT, BLOCK_FILL, FONT, PAGE_W_TWIPS,
    set_cell_bg, set_cell_borders, set_cell_text,
    label_value_table, title_banner, h2, body, body_multi, bullet, tag_p, spacer,
    add_header_footer, new_letter_doc,
)
from docx.shared import Pt, Twips

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_ROOT, "app", "templates", "exports", "risk_exec_summary_template.docx")

doc = new_letter_doc()
section = doc.sections[0]
add_header_footer(
    section,
    "RISK ACTION REQUEST  |  {{ risk_id }}",
    "{{ request_id }}  •  Full risk mechanics, vulnerability evidence, treatment options, and RACI "
    "are in the Supporting Evidence document.",
)

# ── Title block ──────────────────────────────────────────────────────────
title_banner(doc, "RISK ACTION REQUEST", "{{ risk_id }}: {{ exec_subject }}")
spacer(doc, 2)

body_multi(doc, [
    ("To: ", True, BODY_TXT), ("{{ mandating_executives }}     ", False, BODY_TXT),
    ("From: ", True, BODY_TXT), ("{{ requestor_name }}, {{ requestor_role }}", False, BODY_TXT),
], after=2, size=8)
body_multi(doc, [
    ("Request ID: ", True, BODY_TXT), ("{{ request_id }}     ", False, BODY_TXT),
    ("Date: ", True, BODY_TXT), ("{{ request_date }}     ", False, BODY_TXT),
    ("Priority: ", True, BODY_TXT), ("{{ priority_level }}", False, BODY_TXT),
], after=2, size=8)
body_multi(doc, [
    ("Mandate needed by: ", True, RED), ("{{ mandate_needed_by }}", True, RED),
], after=8, size=8)

# ── The ask ──────────────────────────────────────────────────────────────
h2(doc, "The Ask")
body(doc, "{{ executive_ask }}", after=8, size=9)

# ── 1. Background ────────────────────────────────────────────────────────
h2(doc, "1. Background")
tag_p(doc, "{%p for para in background_paragraphs %}")
body(doc, "{{ para }}", after=4, size=9)
tag_p(doc, "{%p endfor %}")
glance_w = [2400, 2784, 2400, 2784]
label_value_table(doc, glance_w, [
    ["Asset / System", "{{ asset_system }}", "Risk Owner", "{{ risk_owner }}"],
    ["Residual Risk", "{{ residual_score }} ({{ rag_status }})", "Inherent Risk", "{{ inherent_score }} (max)"],
    ["Likelihood", "{{ likelihood_val }} ({{ likelihood_label }})", "Business Impact", "{{ impact_val }} ({{ impact_label }})"],
    ["Exceeds Appetite", "{{ exceeds_appetite }}", "Financial Exposure", "{{ financial_exposure_abbrev }}"],
    ["Vulnerabilities", "{{ vuln_open_count }} open ({{ vuln_high_count }} High)", "Oldest Open", "{{ vuln_oldest_days }}"],
])
spacer(doc, 4)

# ── 2. Issue ─────────────────────────────────────────────────────────────
h2(doc, "2. Issue")
tag_p(doc, "{%p for b in issue_bullets %}")
bullet(doc, "{{ b }}")
tag_p(doc, "{%p endfor %}")
spacer(doc, 1)

# ── 3. Options ───────────────────────────────────────────────────────────
h2(doc, "3. Options")
opts = doc.add_table(rows=1, cols=1)
opts.style = "Table Grid"
opts.autofit = False
opts.columns[0].width = Twips(PAGE_W_TWIPS)
c0 = opts.rows[0].cells[0]
c0.width = Twips(PAGE_W_TWIPS)
set_cell_bg(c0, BLOCK_FILL)
set_cell_borders(c0)
set_cell_text(c0, "OPTIONS TO MANDATE: check one", bold=True, color=NAVY, size=10)


def option_row(label_tpl, label_suffix_tpl, text_tpl):
    row = opts.add_row()
    c = row.cells[0]
    set_cell_borders(c)
    c.width = Twips(PAGE_W_TWIPS)
    p = c.paragraphs[0]
    p.text = ""
    r1 = p.add_run(f"☐  {label_tpl}")
    r1.font.name = FONT
    r1.font.size = Pt(9.5)
    r1.font.bold = True
    # label_suffix_tpl renders as a docxtpl RichText (blue ★ RECOMMENDED or
    # gray (not viable)). RichText values require the {{r ...}} tag, not
    # {{ ... }}, or docxtpl silently drops them. The placeholder run's own
    # styling doesn't matter; RichText supplies its own runs on render.
    r2 = p.add_run(label_suffix_tpl)
    r2.font.name = FONT
    r2.font.size = Pt(9.5)
    p2 = c.add_paragraph()
    p2.paragraph_format.space_before = Pt(1)
    r3 = p2.add_run(text_tpl)
    r3.font.name = FONT
    r3.font.size = Pt(9)
    return row


option_row("Mitigate / Remediate", "{{r exec_opt_mitigate_label }}", "{{ exec_opt_mitigate_text }}")
option_row("Accept", "{{r exec_opt_accept_label }}", "{{ exec_opt_accept_text }}")
option_row("Avoid", "{{r exec_opt_avoid_label }}", "{{ exec_opt_avoid_text }}")
option_row("Transfer", "{{r exec_opt_transfer_label }}", "{{ exec_opt_transfer_text }}")
spacer(doc, 2)

# ── 4. Recommendation ────────────────────────────────────────────────────
h2(doc, "4. Recommendation")
body_multi(doc, [
    ("Recommended: ", True, BODY_TXT), ("{{ suggested_treatment }}", True, BLUE),
], after=3, size=9)
tag_p(doc, "{%p for a in recommended_action_bullets %}")
bullet(doc, "{{ a }}")
tag_p(doc, "{%p endfor %}")
rec_w = [3000, 7368]
label_value_table(doc, rec_w, [
    ["Accountable executive", "{{ accountable_executive }}"],
    ["Responsible for delivery", "{{ raci_responsible }}"],
    ["Funding and resources", "{{ funding_requested }}"],
])
spacer(doc, 4)

# ── Mandate ──────────────────────────────────────────────────────────────
mand = doc.add_table(rows=1, cols=1)
mand.style = "Table Grid"
mand.autofit = False
mand.columns[0].width = Twips(PAGE_W_TWIPS)
m0 = mand.rows[0].cells[0]
m0.width = Twips(PAGE_W_TWIPS)
set_cell_bg(m0, BLOCK_FILL)
set_cell_borders(m0)
set_cell_text(m0, "MANDATE: {{ mandating_executives }}", bold=True, color=NAVY, size=10)


def mandate_row(text, size=9):
    row = mand.add_row()
    c = row.cells[0]
    set_cell_borders(c)
    c.width = Twips(PAGE_W_TWIPS)
    set_cell_text(c, text, size=size)


mandate_row("Conditions or changes to the mandated option: "
            "_____________________________________________")
mandate_row("Accountable executive: ____________________   "
            "Complete by: ____________   Review date: ____________")
mandate_row("{{ signer_1 }} signature: ________________________________     Date: ______________")
mandate_row("{{ signer_2 }} signature: ________________________________     Date: ______________")

body(doc, "The mandate stands when both have signed.",
     italic=True, size=8, color=GRAY, after=4)

body(doc, "Risk owner acknowledgement ({{ risk_owner }}): "
          "____________________________     Date: ____________", after=0, size=9)
# The page footer already points to the Supporting Evidence document, so the
# page ends here; repeating it in the body pushed the request onto page two.

doc.save(OUTPUT_PATH)
print(f"template written to {OUTPUT_PATH}")
