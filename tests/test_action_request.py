"""Risk Action Request export: render the real package and read it back.

The documents ask the CIO and CISO to mandate a course of action. These
tests open both generated Word files and check what an executive would
actually see: the Background, Issue, Options, Recommendation order, four
mandate boxes with the recommendation marked, both signature lines, and no
template tag left unrendered.
"""

import io
import os
import sys
import zipfile
from datetime import date

import docx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import _login, _make_app  # noqa: E402


@pytest.fixture
def setup():
    app = _make_app()
    from app.models import Risk, VulnerabilityFinding, db
    with app.app_context():
        risk = Risk(
            risk_id="SKR-001", risk_category="Infrastructure", asset_system="SKY-DC01",
            business_process="Directory services & sign-in", risk_owner="Ted Mecimore",
            threat_description="Unpatched domain controller exposed to a known-exploited flaw.",
            likelihood=4, impact=5, treatment="Mitigate", status="Open",
            remediation_action="Patch SKY-DC01\nRotate the krbtgt account",
            action_owner="Infrastructure team", due_date=date(2026, 12, 15),
        )
        db.session.add(risk)
        db.session.flush()
        db.session.add(VulnerabilityFinding(risk_id=risk.id, cve_id="CVE-2024-21412",
                                            severity="High", status="Open"))
        db.session.commit()
        pk = risk.id
    c = app.test_client()
    _login(c)
    return app, c, pk


def _form(c, pk, **overrides):
    """The form's own defaults, as a browser would submit them, plus overrides."""
    import re
    html = c.get(f"/risks/{pk}/action-request").get_data(as_text=True)
    data = {}
    for name, value in re.findall(r'<input type="[a-z]+" class="form-control[^"]*" id="[^"]+" name="([^"]+)"\s+value="([^"]*)"', html):
        data[name] = value
    for name, value in re.findall(r'name="([^"]+)"\s+rows="\d+">([^<]*)</textarea>', html):
        data[name] = value
    for name in ("priority_level", "suggested_treatment"):
        sel = re.search(rf'name="{name}">(.*?)</select>', html, re.S).group(1)
        data[name] = re.search(r'value="([^"]+)" selected', sel).group(1)
    # A browser decodes HTML entities in values before submitting; so must we.
    import html as _html
    data = {k: _html.unescape(v) for k, v in data.items()}
    data.update(overrides)
    return data


def _read(blob):
    d = docx.Document(io.BytesIO(blob))
    parts = [p.text for p in d.paragraphs]
    for t in d.tables:
        for row in t.rows:
            for cell in row.cells:
                parts.append(cell.text)
    for s in d.sections:
        parts += [p.text for p in s.header.paragraphs] + [p.text for p in s.footer.paragraphs]
    return "\n".join(parts)


def _generate(c, pk, **overrides):
    resp = c.post(f"/risks/{pk}/action-request", data=_form(c, pk, **overrides))
    assert resp.status_code == 200, resp.status_code
    stamp = date.today().isoformat()
    assert f"Risk_Action_Request_SKR-001_{stamp}.zip" in resp.headers["Content-Disposition"]
    z = zipfile.ZipFile(io.BytesIO(resp.data))
    names = sorted(z.namelist())
    assert names == sorted([f"SKR-001_Risk_Action_Request_{stamp}.docx",
                            f"SKR-001_Supporting_Evidence_{stamp}.docx"])
    request = _read(z.read(f"SKR-001_Risk_Action_Request_{stamp}.docx"))
    evidence = _read(z.read(f"SKR-001_Supporting_Evidence_{stamp}.docx"))
    return request, evidence


def test_one_page_request_asks_the_cio_and_ciso_to_mandate(setup):
    _app, c, pk = setup
    request, evidence = _generate(
        c, pk,
        requestor_role="Information Security Manager",
        background="SKY-DC01 handles every sign-in.\n\nIt was last patched in June.",
        issue_bullets="A known-exploited flaw is open on it\nIt is reachable from the VPN",
        accountable_executive="CIO",
    )
    for doc_text in (request, evidence):
        assert "{{" not in doc_text and "{%" not in doc_text, "a template tag was not rendered"
        assert "Executive Core Team" not in doc_text
        assert "—" not in doc_text, "em dash in generated text"
        assert "RAR-SKR-001" in doc_text

    assert "RISK ACTION REQUEST" in request
    assert "To: CIO and CISO" in request
    assert "From:" in request and "Information Security Manager" in request
    assert "We are asking the CIO and CISO to mandate Mitigate" in request

    # Background, Issue, Options, Recommendation, then the mandate
    order = ["The Ask", "1. Background", "2. Issue", "3. Options", "4. Recommendation",
             "MANDATE: CIO and CISO"]
    positions = [request.index(h) for h in order]
    assert positions == sorted(positions), "sections out of order"

    assert "SKY-DC01 handles every sign-in." in request and "last patched in June" in request
    assert "A known-exploited flaw is open on it" in request

    # four boxes, each a mandate, the recommended one marked
    for label in ("Mitigate / Remediate", "Accept", "Avoid", "Transfer"):
        assert f"☐  {label}" in request
    assert request.count("Mandate ") >= 4
    assert "Mitigate / Remediate  ★ RECOMMENDED" in request

    assert "Recommended: Mitigate" in request
    assert "Patch SKY-DC01" in request and "Rotate the krbtgt account" in request
    assert "CIO signature:" in request and "CISO signature:" in request
    assert "The mandate stands when both the CIO and the CISO have signed." in request
    assert "Directory services &amp;" not in request, "the & was double-escaped"
    assert "Directory services & sign-in" in request


def test_supporting_evidence_is_retitled_for_a_mandate(setup):
    _app, c, pk = setup
    _request, evidence = _generate(c, pk)
    assert "Risk Action Request SKR-001: Directory services & sign-in" in evidence
    assert "CIO and CISO: mandate remediation of SKR-001, the risk to Directory services & sign-in, by 2026-12-15." in evidence
    assert "Mandate requested from" in evidence
    assert "6. Mandate Requirements and RACI" in evidence
    assert "4. Risk Mechanics (Security Assessment)" in evidence
    assert "CVE-2024-21412" in evidence
    assert "If the CIO and CISO mandate" in evidence


def test_not_viable_option_and_a_different_recommendation(setup):
    _app, c, pk = setup
    request, evidence = _generate(
        c, pk, suggested_treatment="Accept",
        avoid_not_viable_reason="Directory services cannot be switched off.")
    assert "Accept  ★ RECOMMENDED" in request
    assert "Avoid  (not viable)" in request
    assert "Not viable: Directory services cannot be switched off." in request
    assert "CURRENT TREATMENT, NOT RECOMMENDED." in evidence
    assert "The register lists Mitigate as the current treatment" in evidence


def test_old_address_redirects_and_the_export_is_audited(setup):
    app, c, pk = setup
    resp = c.get(f"/risks/{pk}/decision-request")
    assert resp.status_code == 301
    assert resp.headers["Location"].endswith(f"/risks/{pk}/action-request")
    _generate(c, pk)
    from app.models import AuditLog
    with app.app_context():
        entry = AuditLog.query.filter_by(action="exported").order_by(AuditLog.id.desc()).first()
        assert entry.field_name == "action_request"
        assert entry.new_value.startswith("Risk_Action_Request_SKR-001_")


def test_form_and_detail_button_use_the_new_names(setup):
    _app, c, pk = setup
    form = c.get(f"/risks/{pk}/action-request").get_data(as_text=True)
    assert "Risk Action Request: SKR-001" in form
    assert 'value="CIO and CISO"' in form
    assert "1. Background" in form and "2. Issue" in form
    assert "Generate Action Request" in form
    detail = c.get(f"/risks/{pk}").get_data(as_text=True)
    assert "Action Request" in detail and "Decision / Acceptance" not in detail


def test_requester_and_risk_owner_are_different_people(setup):
    """The person sending the request is not the risk owner. Each name must
    land only on its own lines."""
    app, c, pk = setup
    from app.models import Risk, db
    with app.app_context():
        db.session.get(Risk, pk).risk_owner = "Pat Owner"
        db.session.commit()
    request, evidence = _generate(c, pk, requestor_name="Jane Analyst",
                                  requestor_role="Security Analyst")
    assert "From: Jane Analyst, Security Analyst" in request
    assert "Risk owner acknowledgement (Pat Owner)" in request
    for line in request.splitlines() + evidence.splitlines():
        if "Jane Analyst" in line:
            assert "owner" not in line.lower(), f"requester on a risk-owner line: {line!r}"
        if "Pat Owner" in line:
            assert "From:" not in line and "Prepared by" not in line and "Requested by" not in line, line
    assert "Prepared by Jane Analyst" in evidence
    assert "Print Name: Pat Owner" in evidence
