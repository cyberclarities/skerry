"""Needs attention panel, Control Assurance and Reviews Due reports, and
the daily register snapshot."""

import os
import re
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import _login, _make_app  # noqa: E402

TODAY = date.today()


def ago(days):
    return TODAY - timedelta(days=days)


@pytest.fixture
def app():
    return _make_app()


def _make_risk(app, **fields):
    """A risk with likelihood and impact 3 unless given."""
    from app.models import Risk, db
    fields.setdefault("likelihood", 3)
    fields.setdefault("impact", 3)
    with app.app_context():
        n = Risk.query.count() + 1
        r = Risk(risk_id=f"SKR-{n:03d}", **fields)
        db.session.add(r)
        db.session.commit()
        return r.id


def _client(app):
    c = app.test_client()
    _login(c)
    return c


# ── The rules (app/assurance.py) ─────────────────────────────────────────
def test_review_dates_count_from_the_latest_review(app):
    from app.assurance import next_review_date
    from app.models import Risk
    with app.app_context():
        never = Risk(review_frequency="Monthly", date_identified=ago(40))
        assert next_review_date(never) == ago(10), "never reviewed counts from identified"
        signed = Risk(review_frequency="Quarterly", date_identified=ago(400),
                      last_reviewed=ago(200), acceptance_sign_off_date=ago(10))
        assert next_review_date(signed) == ago(10) + timedelta(days=90), "a sign-off is a review"
        assert next_review_date(Risk(date_identified=ago(5))) is None, "no frequency, no date"


def test_control_assurance_states(app):
    from app import assurance as a
    from app.models import Risk
    with app.app_context():
        case = lambda **kw: a.control_assurance(Risk(**kw), TODAY)  # noqa: E731
        assert case() is None, "no effectiveness claimed: nothing leans on controls"
        assert case(control_effectiveness=4, control_test_result="Fail",
                    last_control_test_date=ago(5)) == a.FAILED
        assert case(control_effectiveness=4) == a.NEVER_TESTED
        assert case(control_effectiveness=4, control_test_result="Not Tested",
                    last_control_test_date=ago(5)) == a.NEVER_TESTED
        assert case(control_effectiveness=4, control_test_result="Pass") == a.NO_RESULT
        assert case(control_effectiveness=4, control_test_result="Pass",
                    last_control_test_date=ago(400)) == a.STALE
        assert case(control_effectiveness=4, control_test_result="Pass",
                    last_control_test_date=ago(30)) == a.TESTED


# ── The panel and the pages it links to ──────────────────────────────────
@pytest.fixture
def register(app):
    """One risk per tile, plus risks that must NOT be counted."""
    from app.models import db
    from app.models_spotlight import SpotlightFinding
    ids = dict(
        overdue=_make_risk(app, status="Open", due_date=ago(3)),
        review=_make_risk(app, status="Open", review_frequency="Monthly", last_reviewed=ago(45)),
        accept=_make_risk(app, status="Accepted", treatment="Accept", review_frequency="Annually",
                          acceptance_sign_off_date=ago(350), last_reviewed=ago(350)),
        accept_nofreq=_make_risk(app, status="Accepted", treatment="Accept"),
        # RED before controls (5x4=20), claims High controls, never tested
        red_unproven=_make_risk(app, status="Open", likelihood=5, impact=4, control_effectiveness=4),
        # AMBER before controls, failed test: unproven, but not on a RED risk
        amber_unproven=_make_risk(app, status="Open", likelihood=3, impact=3, control_effectiveness=2,
                                  control_test_result="Fail", last_control_test_date=ago(10)),
        # not counted anywhere: closed, or tested and passed recently
        closed=_make_risk(app, status="Closed", due_date=ago(30), likelihood=5, impact=5,
                          control_effectiveness=4, review_frequency="Monthly", last_reviewed=ago(90)),
        tested=_make_risk(app, status="Open", likelihood=5, impact=5, control_effectiveness=4,
                          control_test_result="Pass", last_control_test_date=ago(20)),
    )
    with app.app_context():
        base = dict(aid="a1", hostname="h1", cve_severity="HIGH", spotlight_status="open",
                    is_suppressed=False, is_cisa_kev=True)
        db.session.add_all([
            SpotlightFinding(spotlight_id="kev-late", cve_id="CVE-2099-0001", cisa_due_date=ago(5), **base),
            SpotlightFinding(spotlight_id="kev-ok", cve_id="CVE-2099-0002", cisa_due_date=TODAY + timedelta(days=5), **base),
            SpotlightFinding(spotlight_id="kev-closed", cve_id="CVE-2099-0003", cisa_due_date=ago(5),
                             **dict(base, spotlight_status="closed")),
        ])
        db.session.commit()
    return ids


def _tiles(html):
    panel = html[html.index('id="needs-attention"'):html.index("<!-- KPI Row -->")]
    found = re.findall(r'<a href="([^"]+)"[^>]*>\s*<div class="fs-3[^"]*">(\d+)</div>\s*'
                       r'<div class="small fw-semibold text-body mt-1">([^<]+)</div>', panel)
    return {label: (int(n), href.replace("&amp;", "&")) for href, n, label in found}


def test_panel_counts_each_thing_once_and_skips_closed(app, register):
    tiles = _tiles(_client(app).get("/dashboard").get_data(as_text=True))
    assert {k: v[0] for k, v in tiles.items()} == {
        "Overdue actions": 1,
        "Reviews past due": 1,          # 'review'; 'accept' is due in 15 days, not past
        "Acceptances due": 2,           # 'accept' due in 15 days, 'accept_nofreq'
        "RED on unproven controls": 1,  # 'red_unproven'; the tested RED risk is fine
        "KEV past CISA due": 1,         # open and late; not the closed one, not the one not yet due
    }


def test_every_tile_links_to_a_page_that_lists_the_same_risks(app, register):
    c = _client(app)
    tiles = _tiles(c.get("/dashboard").get_data(as_text=True))
    controls = c.get(tiles["RED on unproven controls"][1]).get_data(as_text=True)
    assert controls.count('class="fw-semibold text-decoration-none">SKR-') == 1
    allc = c.get("/reports/controls").get_data(as_text=True)
    assert allc.count('class="fw-semibold text-decoration-none">SKR-') == 2
    assert "Never tested" in allc and "Failed" in allc

    reviews = c.get("/reports/reviews").get_data(as_text=True)
    assert "Past due (1)" in reviews and "(2)</h6>" in reviews.split('id="acceptances"')[1]
    assert "No review frequency set" in reviews

    kev = c.get(tiles["KEV past CISA due"][1]).get_data(as_text=True)
    assert "CVE-2099-0001" in kev and "CVE-2099-0002" not in kev and "CVE-2099-0003" not in kev

    overdue = c.get(tiles["Overdue actions"][1]).get_data(as_text=True)
    assert "1 action overdue" in overdue


def test_quiet_register_says_nothing_waiting(app):
    html = _client(app).get("/dashboard").get_data(as_text=True)
    assert "Nothing waiting" in html
    assert all(n == 0 for n, _ in _tiles(html).values())


# ── The daily snapshot ───────────────────────────────────────────────────
def test_first_request_of_the_day_takes_one_snapshot(app, register):
    from app.models import RegisterSnapshot
    c = _client(app)
    c.get("/dashboard")
    c.get("/health")
    c.get("/risks/")
    with app.app_context():
        snaps = RegisterSnapshot.query.all()
        assert len(snaps) == 1
        s = snaps[0]
        assert s.active == 7 and s.closed == 1
        assert (s.overdue_actions, s.reviews_past_due, s.acceptances_due,
                s.unproven_on_red, s.kev_past_due) == (1, 1, 2, 1, 1)
        assert s.unproven_controls == 2


def test_health_check_alone_takes_the_snapshot(app):
    """No one signs in: Docker's health check still records the day."""
    from app.models import RegisterSnapshot
    assert app.test_client().get("/health").status_code == 200
    with app.app_context():
        assert RegisterSnapshot.query.count() == 1


def test_a_days_row_is_never_rewritten(app):
    from app.models import RegisterSnapshot
    from app.snapshots import take_snapshot_if_missing, today_utc
    c = _client(app)
    c.get("/dashboard")
    _make_risk(app, status="Open")
    with app.app_context():
        assert take_snapshot_if_missing() is None
        assert RegisterSnapshot.query.filter_by(snapshot_date=today_utc()).one().active == 0


def test_trend_appears_from_the_second_day(app):
    from app.models import RegisterSnapshot, db
    c = _client(app)
    first = c.get("/dashboard").get_data(as_text=True)
    assert "Collecting since" in first and 'id="trendChart"' not in first
    with app.app_context():
        db.session.add(RegisterSnapshot(snapshot_date=ago(1), red=3, amber=2, green=1))
        db.session.commit()
    second = c.get("/dashboard").get_data(as_text=True)
    assert 'id="trendChart"' in second
    assert f'"{ago(1).isoformat()}"' in second and f"Daily since {ago(1).isoformat()}" in second


def test_a_snapshot_failure_never_breaks_a_page(app, monkeypatch):
    import app.snapshots as snapshots
    def broken(day):
        raise RuntimeError("disk full")
    monkeypatch.setattr(snapshots, "build_snapshot", broken)
    c = _client(app)
    assert c.get("/dashboard").status_code == 200
    assert c.get("/health").status_code == 200
