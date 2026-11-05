"""Set the NIST CSF mapping from the register: one risk, or many at once."""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import (OPERATOR_PW, _login, _make_app,  # noqa: E402
                                 _make_operator, _make_risk)


@pytest.fixture
def app():
    return _make_app()


def _admin(app):
    c = app.test_client()
    _login(c)
    return c


def _csf(app, pk):
    from app.models import Risk, db
    with app.app_context():
        r = db.session.get(Risk, pk)
        return r.nist_csf_function, r.nist_csf_category, r.nist_csf_subcategory


def test_one_risk_gets_all_three_fields_from_the_subcategory(app):
    pk = _make_risk(app, status="Open")
    c = _admin(app)
    resp = c.post(f"/risks/{pk}/csf", data={"subcategory": "ID.RA-01", "back": "/risks/?hide_closed=1"})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/risks/?hide_closed=1")
    assert _csf(app, pk) == ("ID", "ID.RA", "ID.RA-01")

    from app.models import AuditLog
    with app.app_context():
        logged = {(a.field_name, a.old_value, a.new_value)
                  for a in AuditLog.query.filter_by(risk_id=pk, action="updated")}
    assert ("nist_csf_subcategory", None, "ID.RA-01") in logged
    assert ("nist_csf_function", None, "ID") in logged


def test_mismatched_old_mapping_is_corrected_and_can_be_cleared(app):
    pk = _make_risk(app, nist_csf_function="PR", nist_csf_category="ID.AM",
                    nist_csf_subcategory=None)
    c = _admin(app)
    c.post(f"/risks/{pk}/csf", data={"subcategory": "PR.AT-01"})
    assert _csf(app, pk) == ("PR", "PR.AT", "PR.AT-01")
    c.post(f"/risks/{pk}/csf", data={"subcategory": ""})
    assert _csf(app, pk) == (None, None, None)


def test_unknown_code_changes_nothing(app):
    pk = _make_risk(app, nist_csf_function="ID", nist_csf_category="ID.RA",
                    nist_csf_subcategory="ID.RA-01")
    c = _admin(app)
    assert c.post(f"/risks/{pk}/csf", data={"subcategory": "XX.YY-99"}).status_code == 400
    assert c.post("/risks/csf/bulk", data={"risk_ids": [pk], "subcategory": "XX"}).status_code == 400
    assert _csf(app, pk) == ("ID", "ID.RA", "ID.RA-01")


def test_bulk_sets_every_checked_risk(app):
    pks = [_make_risk(app) for _ in range(3)]
    other = _make_risk(app)
    c = _admin(app)
    resp = c.post("/risks/csf/bulk", data={"risk_ids": pks, "subcategory": "ID.RA-01"},
                  follow_redirects=True)
    assert b"3 risks set to ID.RA-01." in resp.data
    assert all(_csf(app, pk) == ("ID", "ID.RA", "ID.RA-01") for pk in pks)
    assert _csf(app, other) == (None, None, None), "an unchecked risk was changed"


def test_operator_changes_only_risks_they_may_edit(app):
    op_id = _make_operator(app)
    mine = _make_risk(app, created_by_id=op_id)
    theirs = _make_risk(app)
    c = app.test_client()
    _login(c, "op", OPERATOR_PW)
    assert c.post(f"/risks/{theirs}/csf", data={"subcategory": "ID.RA-01"}).status_code == 403
    resp = c.post("/risks/csf/bulk", data={"risk_ids": [mine, theirs], "subcategory": "ID.RA-01"},
                  follow_redirects=True)
    assert b"1 risk set to ID.RA-01." in resp.data
    assert b"1 left unchanged" in resp.data
    assert _csf(app, mine)[2] == "ID.RA-01"
    assert _csf(app, theirs) == (None, None, None)

    # the register offers a checkbox and an editable cell only on the risk they can change
    html = c.get("/risks/").get_data(as_text=True)
    assert html.count('class="form-check-input risk-check"') == 1
    assert html.count('class="btn btn-link btn-sm p-0 text-decoration-none csf-edit"') == 1


def test_viewer_sees_csf_read_only(app):
    from app.models import User, db
    with app.app_context():
        v = User(username="viewer", email="v@example.org", name="Vi Ewer", role="viewer", is_active=True)
        v.set_password(OPERATOR_PW)
        db.session.add(v)
        db.session.commit()
    pk = _make_risk(app, nist_csf_function="ID", nist_csf_category="ID.RA",
                    nist_csf_subcategory="ID.RA-01")
    c = app.test_client()
    _login(c, "viewer", OPERATOR_PW)
    html = c.get("/risks/").get_data(as_text=True)
    assert "ID.RA-01" in html
    table = html.split("<table")[1].split("</table>")[0]
    assert "csf-edit" not in table and "risk-check" not in table
    assert 'id="csf-modal"' not in html
    assert c.post(f"/risks/{pk}/csf", data={"subcategory": ""}).status_code == 403


def test_register_page_has_the_picker_and_the_column(app):
    _make_risk(app, nist_csf_function="ID", nist_csf_category="ID.RA", nist_csf_subcategory="ID.RA-01")
    c = _admin(app)
    html = c.get("/risks/").get_data(as_text=True)
    assert '<th style="width:90px;" title="NIST CSF 2.0 subcategory">CSF</th>' in html
    assert 'id="csf-modal"' in html and "Set CSF for selected" in html
    options = re.findall(r'<option value="([A-Z]{2}\.[A-Z]{2}-\d{2})">', html)
    assert len(options) == 106 and len(set(options)) == 106
    # the HTMX partial keeps the column and checkboxes
    part = c.get("/risks/?hide_closed=1", headers={"HX-Request": "true"}).get_data(as_text=True)
    assert "csf-edit" in part and "risk-check" in part and "<html" not in part
