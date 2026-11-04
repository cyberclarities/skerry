"""Register list: hide closed risks, and filter on several statuses at once."""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import _login, _make_app, _make_risk  # noqa: E402


@pytest.fixture
def register():
    """Five risks, one per status plus one with no status set."""
    app = _make_app()
    for status, asset in (("Open", "asset-open"), ("In Progress", "asset-progress"),
                          ("Closed", "asset-closed"), ("Accepted", "asset-accepted"),
                          (None, "asset-nostatus")):
        _make_risk(app, status=status, asset_system=asset)
    # The model fills a blank status with "Open"; older or imported data can
    # still hold a real NULL, so write one directly.
    from app.models import Risk, db
    with app.app_context():
        Risk.query.filter_by(asset_system="asset-nostatus").update({"status": None})
        db.session.commit()
    c = app.test_client()
    _login(c)
    return c


def shown(resp):
    return sorted(set(re.findall(r"asset-[a-z]+", resp.data.decode())))


def test_no_filter_shows_everything(register):
    assert shown(register.get("/risks/")) == [
        "asset-accepted", "asset-closed", "asset-nostatus", "asset-open", "asset-progress"]


def test_hide_closed_drops_only_closed(register):
    resp = register.get("/risks/?hide_closed=1")
    assert "asset-closed" not in shown(resp)
    assert "asset-nostatus" in shown(resp), "a risk with no status is not closed"
    assert len(shown(resp)) == 4
    assert re.search(r'id="hide-closed"\s+checked', resp.data.decode()), "switch stays on"


def test_several_statuses_at_once(register):
    resp = register.get("/risks/?status=Open&status=Accepted")
    assert shown(resp) == ["asset-accepted", "asset-open"]
    body = resp.data.decode()
    assert re.search(r'value="Open" id="status-\d+"\s+checked', body)
    assert re.search(r'value="Accepted" id="status-\d+"\s+checked', body)
    assert "Open, Accepted" in body          # the dropdown button's label


def test_hide_closed_wins_over_a_ticked_closed(register):
    resp = register.get("/risks/?status=Closed&status=Open&hide_closed=1")
    assert shown(resp) == ["asset-open"]


def test_unknown_status_values_are_ignored(register):
    assert len(shown(register.get("/risks/?status=Pwned"))) == 5


def test_htmx_partial_honors_the_same_filters(register):
    resp = register.get("/risks/?status=In+Progress&hide_closed=1",
                        headers={"HX-Request": "true"})
    assert "<html" not in resp.data.decode()
    assert shown(resp) == ["asset-progress"]
