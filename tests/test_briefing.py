"""The one-page Cyber Risk Briefing: every sentence matches the figures."""

import os
import re
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import OPERATOR_PW, _login, _make_app  # noqa: E402

TODAY = date.today()


def ago(days):
    return TODAY - timedelta(days=days)


@pytest.fixture
def app():
    return _make_app()


def _risk(app, **fields):
    from app.models import Risk, db
    fields.setdefault("likelihood", 3)
    fields.setdefault("impact", 3)
    fields.setdefault("status", "Open")
    with app.app_context():
        n = Risk.query.count() + 1
        db.session.add(Risk(risk_id=f"SKR-{n:03d}", **fields))
        db.session.commit()


def _page(app):
    c = app.test_client()
    _login(c)
    resp = c.get("/reports/briefing")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def _text(html, element_id):
    """An element's text as a reader sees it: tags dropped, entities decoded."""
    import html as _html
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", re.search(
        rf'id="{element_id}">(.*?)</(?:div|p)>', html, re.S).group(1)))).strip()


def test_empty_register_says_so_plainly(app):
    html = _page(app)
    assert _text(html, "headline") == "No active risks in the register."
    assert "every control" not in html
    assert "collecting since" in html or "appears from the second day" in html
    assert "{{" not in html and "{%" not in html


def test_headline_and_why_follow_the_figures(app):
    # RED before controls (20), claims controls, never tested; still RED after (20 -> 15)
    _risk(app, likelihood=5, impact=4, control_effectiveness=2)
    _risk(app, likelihood=2, impact=2)
    _risk(app, likelihood=3, impact=3, status="Closed")
    html = _page(app)
    assert _text(html, "headline") == "1 of 2 active risks is RED after controls."
    why = _text(html, "why")
    assert why.startswith("Why it matters: 1 risk rated RED before controls depends on controls nobody has proven.")
    assert "Test the controls behind 1 risk rated RED before controls, or rescore it" in html
    assert "1 closed, not counted" in html


def test_month_comparison_appears_only_with_a_month_of_history(app):
    from app.models import RegisterSnapshot, db
    _risk(app, likelihood=5, impact=5)
    assert "from a month ago" not in _page(app)
    with app.app_context():
        db.session.add(RegisterSnapshot(snapshot_date=ago(31), active=4, red=3, amber=1, green=0,
                                        kev_past_due=0))
        db.session.commit()
    html = _page(app)
    assert _text(html, "headline") == "1 of 1 active risk is RED after controls, down from 3 a month ago."
    assert "▼ 2 from a month ago" in html
    assert "Changes compare with the register a month ago." in html


def test_trend_draws_from_two_days_of_snapshots(app):
    from app.models import RegisterSnapshot, db
    _risk(app)
    html = _page(app)                      # today's snapshot only
    assert "<polyline" not in html and "appears from the second day" in html
    with app.app_context():
        db.session.add(RegisterSnapshot(snapshot_date=ago(1), red=2, amber=1, green=0))
        db.session.commit()
    html = _page(app)
    assert html.count("<polyline") == 3


def test_kev_why_and_at_most_three_actions(app):
    from app.models import db
    from app.models_spotlight import SpotlightFinding
    _risk(app, due_date=ago(5))                                  # overdue
    _risk(app, review_frequency="Monthly", last_reviewed=ago(60))  # review past due
    _risk(app, status="Accepted", treatment="Accept")            # acceptance, no frequency
    with app.app_context():
        db.session.add(SpotlightFinding(spotlight_id="k", aid="a", cve_id="CVE-2099-1",
                                        cve_severity="HIGH", spotlight_status="open",
                                        is_suppressed=False, is_cisa_kev=True, cisa_due_date=ago(3)))
        db.session.commit()
    html = _page(app)
    assert "1 vulnerability attackers are known to exploit is past CISA's fix-by date." in _text(html, "why")
    actions = re.findall(r"<li>(.*?)</li>", html.split("What's next")[1])
    assert actions == [
        "Patch 1 known-exploited vulnerability past the CISA date.",
        "Close or re-plan 1 overdue remediation action.",
        "Review 1 risk past its review date.",
    ], "most serious first, three at most"


def test_quiet_register_says_nothing_is_waiting(app):
    _risk(app, likelihood=2, impact=2)
    html = _page(app)
    assert _text(html, "why") == ("Why it matters: Nothing is waiting on a decision, "
                                  "and every control our scores rely on has been tested.")
    assert "Nothing is waiting on a decision. Keep reviews and control tests on schedule." in html


def test_any_signed_in_user_can_open_it_and_text_has_no_em_dash(app):
    from app.models import User, db
    with app.app_context():
        v = User(username="viewer", email="v@example.org", name="Vi", role="viewer", is_active=True)
        v.set_password(OPERATOR_PW)
        db.session.add(v)
        db.session.commit()
    _risk(app, likelihood=5, impact=4, control_effectiveness=3)
    c = app.test_client()
    assert c.get("/reports/briefing").status_code == 302          # signed out: to login
    _login(c, "viewer", OPERATOR_PW)
    html = c.get("/reports/briefing").get_data(as_text=True)
    body = html.split("<body>")[1]
    assert "—" not in body
    assert "One-Page Briefing" in c.get("/dashboard").get_data(as_text=True)


def test_treatment_counts_and_the_note_that_matters(app):
    _risk(app, treatment="Mitigate", due_date=ago(5))          # past target
    _risk(app, treatment="Mitigate", due_date=TODAY + timedelta(days=10))
    _risk(app, treatment="Accept", acceptance_sign_off_by="CIO")
    _risk(app, treatment="Accept")                              # no sign-off
    _risk(app)                                                  # no treatment chosen
    _risk(app, treatment="Avoid", status="Closed")              # closed, not counted
    with app.test_request_context():
        from app.briefing import build_briefing
        rows = {r["label"]: r for r in build_briefing()["treatment"]["rows"]}
    assert [rows[k]["n"] for k in ("Mitigate", "Accept", "Transfer", "Avoid", "Not set")] == [2, 2, 0, 0, 1]
    assert rows["Mitigate"]["note"] == "1 past target date"
    assert rows["Accept"]["note"] == "1 without sign-off"
    assert rows["Not set"]["note"] == "needs a decision"
    assert rows["Transfer"]["note"] == ""
    assert "How we are treating them" in _page(app)


def test_vulnerability_aging_bands(app):
    from datetime import datetime, time

    from app.models import db
    from app.models_spotlight import SpotlightFinding

    def seen(days):
        return datetime.combine(ago(days), time(12, 0))

    rows = [  # (age in days or None, severity, status, suppressed)
        (0, "CRITICAL", "open", False),
        (30, "HIGH", "open", False),        # last day of 0-30
        (31, "HIGH", "reopen", False),      # first day of 31-60
        (60, "CRITICAL", "open", False),    # last day of 31-60, not past the line
        (61, "HIGH", "open", False),        # first day past the line
        (200, "CRITICAL", "open", False),
        (None, "HIGH", "open", False),      # Spotlight gave no first-seen date
        (100, "MEDIUM", "open", False),     # below the line we report
        (100, "HIGH", "closed", False),     # fixed
        (100, "HIGH", "open", True),        # suppressed in Falcon
    ]
    with app.app_context():
        for i, (age, sev, status, sup) in enumerate(rows):
            db.session.add(SpotlightFinding(
                spotlight_id=f"s{i}", aid=f"a{i}", cve_id=f"CVE-2026-{i:04d}", cve_severity=sev,
                spotlight_status=status, is_suppressed=sup,
                created_timestamp=seen(age) if age is not None else None))
        db.session.commit()
    with app.test_request_context():
        from app.briefing import build_briefing
        ag = build_briefing()["aging"]
    got = {b["label"]: (b["crit"], b["high"]) for b in ag["bars"]}
    assert got == {"0-30": (1, 1), "31-60": (1, 1), "61-90": (0, 1), "Over 90": (1, 0)}
    assert (ag["past"], ag["unknown"], ag["critical"], ag["high"]) == (2, 1, 3, 3)
    html = _page(app)
    assert "2 past 60 days" in html
    assert "1 more with no first-seen date" in html


def test_aging_without_spotlight_data(app):
    html = _page(app)
    assert "No open Critical or High findings from Spotlight." in html
