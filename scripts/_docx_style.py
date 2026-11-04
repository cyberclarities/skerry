"""Shared docx-building helpers and palette for the Risk Action Request
export templates (the one-page request and its Supporting Evidence).

Colors match the organization's document template (PB-000): a navy title
banner, navy section bars and table headers, blue subheadings and rules,
light gray label and row fills, gray borders, and red for the one date that
must not be missed. The template's yellow (title subtitle and callout boxes)
is deliberately not used. If the brand system changes, this is the one file
to update; both builder scripts import their colors and helpers from here.
"""
import docx
from docx.shared import Pt, Twips, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ── Palette (PB-000 template; no yellow) ────────────────────────────────
NAVY_HEX = "1F3864"       # section bars, table headers, header text
BANNER_HEX = "002060"     # title banner
BLUE_HEX = "2E75B6"       # subheadings, bullet markers, the recommendation
RULE_HEX = "2E5496"       # header and footer rules
RED_HEX = "C00000"        # the mandate-needed-by date
GRAY_HEX = "404040"       # footer, notes, "not viable"

NAVY = RGBColor.from_string(NAVY_HEX)
BLUE = RGBColor.from_string(BLUE_HEX)
RED = RGBColor.from_string(RED_HEX)
GRAY = RGBColor.from_string(GRAY_HEX)
BODY_TXT = RGBColor(0x00, 0x00, 0x00)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

LABEL_FILL = "F2F2F2"     # label cells and alternate rows
BLOCK_FILL = "BDD7EE"     # header row of the options and mandate blocks
GRID_BORDER = "CCCCCC"

FONT = "Azo Sans"        # Word substitutes a similar font if Azo Sans is
                          # not installed on the machine opening the file.

PAGE_W_TWIPS = 10368  # Letter, 0.5in margins


def set_cell_bg(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def set_cell_borders(cell, color=GRID_BORDER, sz=4):
    tcPr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(sz))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tcPr.append(borders)


def set_col_widths(table, widths):
    table.autofit = False
    for row in table.rows:
        for cell, w in zip(row.cells, widths):
            cell.width = Twips(w)
    tbl = table._tbl
    grid = tbl.find(qn("w:tblGrid"))
    if grid is not None:
        for gridCol, w in zip(grid.findall(qn("w:gridCol")), widths):
            gridCol.set(qn("w:w"), str(w))


def set_cell_text(cell, text, bold=False, color=BODY_TXT, size=9, italic=False, align=None):
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
    p = cell.paragraphs[0]
    p.text = ""
    if align:
        p.alignment = align
    run = p.add_run(text)
    run.font.name = FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    return run


def add_table(doc, widths, header_labels=None, header_fill=NAVY_HEX, header_color=WHITE):
    cols = len(widths)
    rows = 1 if header_labels else 0
    table = doc.add_table(rows=rows, cols=cols)
    table.style = "Table Grid"
    if header_labels:
        for i, label in enumerate(header_labels):
            c = table.rows[0].cells[i]
            set_cell_bg(c, header_fill)
            set_cell_borders(c)
            set_cell_text(c, label, bold=True, color=header_color, size=9)
    set_col_widths(table, widths)
    return table


def add_data_row(table, widths, values, fill=None, italic=False, bold_first=True):
    row = table.add_row()
    for i, val in enumerate(values):
        c = row.cells[i]
        set_cell_borders(c)
        if fill:
            set_cell_bg(c, fill)
        set_cell_text(c, val, italic=italic, size=9, bold=(bold_first and i == 0 and fill == LABEL_FILL))
    set_col_widths(table, widths)
    return row


def label_value_table(doc, widths, rows, label_fill=LABEL_FILL):
    """A 2-or-4 column table where every even column is a label cell
    (gray fill, bold) and every odd column is its value: the pattern used
    for metadata tables throughout both documents."""
    table = doc.add_table(rows=0, cols=len(widths))
    table.style = "Table Grid"
    for row_vals in rows:
        row = table.add_row()
        for i, val in enumerate(row_vals):
            c = row.cells[i]
            set_cell_borders(c)
            is_label = (i % 2 == 0)
            if is_label:
                set_cell_bg(c, label_fill)
            set_cell_text(c, val, bold=is_label, size=9)
    set_col_widths(table, widths)
    return table


def _shade_paragraph(p, hex_fill):
    pPr = p._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    pPr.append(shd)


def _rule(p, edge, hex_color=RULE_HEX, sz=6):
    """A single line above or below a paragraph: the template's header and
    footer rules."""
    pPr = p._p.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    el = OxmlElement(f"w:{edge}")
    el.set(qn("w:val"), "single")
    el.set(qn("w:sz"), str(sz))
    el.set(qn("w:space"), "4")
    el.set(qn("w:color"), hex_color)
    bdr.append(el)
    pPr.append(bdr)


def h1(doc, text, size=12):
    """Section heading: white text on a full-width navy bar, as in the template."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(5)
    _shade_paragraph(p, NAVY_HEX)
    r = p.add_run(" " + text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.font.bold = True
    r.font.color.rgb = WHITE
    return p


def title_banner(doc, title, subtitle):
    """The template's title block: a full-width navy banner, title above a
    subtitle. The template sets the subtitle in yellow; this uses white."""
    t = doc.add_table(rows=1, cols=1)
    t.autofit = False
    t.columns[0].width = Twips(PAGE_W_TWIPS)
    c = t.rows[0].cells[0]
    c.width = Twips(PAGE_W_TWIPS)
    set_cell_bg(c, BANNER_HEX)
    set_cell_borders(c, color=BANNER_HEX)
    p = c.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(1)
    r = p.add_run(title)
    r.font.name = FONT
    r.font.size = Pt(13)
    r.font.bold = True
    r.font.color.rgb = WHITE
    p2 = c.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p2.paragraph_format.space_after = Pt(4)
    r2 = p2.add_run(subtitle)
    r2.font.name = FONT
    r2.font.size = Pt(10.5)
    r2.font.bold = True
    r2.font.color.rgb = WHITE
    return t


def h2(doc, text, color=BLUE, size=10.5):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run(text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.font.bold = True
    r.font.color.rgb = color
    return p


def body(doc, text, italic=False, bold=False, after=6, size=9, align=None, color=BODY_TXT):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    if align:
        p.alignment = align
    r = p.add_run(text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.font.italic = italic
    r.font.bold = bold
    r.font.color.rgb = color
    return p


def body_multi(doc, runs, after=6, size=9):
    """runs: list of (text, bold, color) tuples in one paragraph."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    for text, bold, color in runs:
        r = p.add_run(text)
        r.font.name = FONT
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = color
    return p


def bullet(doc, text, after=3, size=9, marker_color=BLUE):
    """One bullet with a blue marker, used with {%p for/endfor%} tags around
    it so docxtpl repeats this paragraph once per list item."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.left_indent = Twips(200)
    m = p.add_run("•  ")
    m.font.name = FONT
    m.font.size = Pt(size)
    m.font.bold = True
    m.font.color.rgb = marker_color
    r = p.add_run(text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.font.color.rgb = BODY_TXT
    return p


def tag_p(doc, tag_text, size=1):
    """A paragraph containing only a docxtpl {%p ...%} control tag —
    stripped from the output, used to open/close for/if blocks around the
    paragraphs between them. Tiny font size so a rendering hiccup won't
    leave a visible stray blank line."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(tag_text)
    r.font.name = FONT
    r.font.size = Pt(size)
    return p


def spacer(doc, after=4):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)


def add_header_footer(section, header_text, footer_text):
    """Template header and footer: navy bold header text over a blue rule,
    gray footer text under one."""
    header = section.header
    hp = header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _rule(hp, "bottom")
    hr = hp.add_run(header_text)
    hr.font.name = FONT
    hr.font.size = Pt(8)
    hr.font.bold = True
    hr.font.color.rgb = NAVY

    footer = section.footer
    fp = footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _rule(fp, "top")
    fr = fp.add_run(footer_text)
    fr.font.name = FONT
    fr.font.size = Pt(7.5)
    fr.font.color.rgb = GRAY


def new_letter_doc():
    doc = docx.Document()
    section = doc.sections[0]
    section.page_width = Twips(12240)
    section.page_height = Twips(15840)
    section.top_margin = Twips(560)
    section.bottom_margin = Twips(560)
    section.left_margin = Twips(720)
    section.right_margin = Twips(720)
    section.header_distance = Twips(430)
    section.footer_distance = Twips(430)

    style = doc.styles["Normal"]
    style.font.name = FONT
    style.font.size = Pt(9)
    style.font.color.rgb = BODY_TXT
    return doc
