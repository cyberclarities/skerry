"""Spotlight ingest rebuild: one row per host+CVE, Critical/High only, delete.

Each sync here runs the real run_sync() against a fake Falcon client, so the
whole path is exercised -- severity filter, dedupe, deletion memory -- with no
network and no credentials.
"""

import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import ADMIN_PW, OPERATOR_PW, _login, _make_app, _make_operator  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = json.load(open(os.path.join(HERE, "sample_spotlight_payload.json")))["resources"][0]
AID, CVE = "abc123def456", "CVE-2024-21412"


def rec(n, product="Google Chrome 120.0", severity="HIGH", status="open",
        aid=AID, cve=CVE, created="2026-04-02T09:14:00Z"):
    """One Falcon record. n makes the Spotlight record id unique."""
    r = copy.deepcopy(BASE)
    r["id"] = f"{aid}_{cve}_{n}"
    r["aid"] = aid
    r["cve"] = dict(r["cve"], id=cve, severity=severity)
    r["status"] = status
    r["created_timestamp"] = created
    r["apps"] = [{"product_name_version": product}]
    return r


class FakeClient:
    def __init__(self, records):
        self.records = records

    def iter_vulnerabilities(self, fql, limit=400, max_pages=500):
        yield 1, list(self.records)


@pytest.fixture
def app():
    return _make_app()


def sync(app, monkeypatch, records, **kw):
    import app.spotlight.ingest as ingest
    monkeypatch.setattr(ingest, "client_from_config", lambda _cfg: FakeClient(records))
    with app.app_context():
        run = ingest.run_sync(app, trigger="manual", **kw)
        assert run.status == "success", run.error_message
        return run.id


def rows(app, aid=AID, cve=CVE):
    from app.models_spotlight import SpotlightFinding
    with app.app_context():
        return [(f.id, f.ingest_state, f.product_name_version, f.spotlight_status)
                for f in SpotlightFinding.query.filter_by(aid=aid, cve_id=cve)]


# ── Dedupe ──────────────────────────────────────────────────────────────────
def test_one_row_per_host_and_cve_listing_every_product(app, monkeypatch):
    sync(app, monkeypatch, [rec(1, "Google Chrome 120.0"), rec(2, "Microsoft Edge 120.0"),
                            rec(3, "Google Chrome 119.0", created="2026-01-15T00:00:00Z")])
    found = rows(app)
    assert len(found) == 1, "three records for one host+CVE must be one row"
    assert found[0][2] == "Google Chrome 120.0, Microsoft Edge 120.0, Google Chrome 119.0"
    from app.models_spotlight import SpotlightFinding
    with app.app_context():
        f = SpotlightFinding.query.one()
        assert f.created_timestamp.date().isoformat() == "2026-01-15", "earliest record wins"
        assert f.ingest_count == 1, "one sync is one ingest, however many records"


def test_nightly_resync_keeps_one_row_and_refreshes_products(app, monkeypatch):
    sync(app, monkeypatch, [rec(1, "Google Chrome 120.0"), rec(2, "Microsoft Edge 120.0")])
    sync(app, monkeypatch, [rec(1, "Google Chrome 121.0")])   # Edge patched since
    found = rows(app)
    assert len(found) == 1
    assert found[0][2] == "Google Chrome 121.0", "products reflect the latest sync only"


def test_row_is_open_if_any_record_is_open(app, monkeypatch):
    sync(app, monkeypatch, [rec(1, status="closed"), rec(2, status="open")])
    assert rows(app)[0][3] == "open"


# ── Critical and High only ──────────────────────────────────────────────────
def test_only_critical_and_high_are_ingested(app, monkeypatch):
    from app.models_spotlight import SpotlightFinding
    sync(app, monkeypatch, [
        rec(1, severity="CRITICAL", cve="CVE-1"), rec(2, severity="HIGH", cve="CVE-2"),
        rec(3, severity="MEDIUM", cve="CVE-3"), rec(4, severity="LOW", cve="CVE-4"),
        rec(5, severity="", cve="CVE-5"),
    ])
    with app.app_context():
        assert sorted(f.cve_id for f in SpotlightFinding.query) == ["CVE-1", "CVE-2"]


def test_severity_set_is_configurable(monkeypatch):
    from app.models_spotlight import SpotlightFinding
    app = _make_app(SPOTLIGHT_SEVERITIES=("CRITICAL",))
    sync(app, monkeypatch, [rec(1, severity="CRITICAL", cve="CVE-1"),
                            rec(2, severity="HIGH", cve="CVE-2")])
    with app.app_context():
        assert [f.cve_id for f in SpotlightFinding.query] == ["CVE-1"]


# ── Delete: stays gone unless it reopens ────────────────────────────────────
def _delete_via_ui(app, username="admin", password=ADMIN_PW, reason="noise"):
    from app.models_spotlight import SpotlightFinding
    with app.app_context():
        ids = [f.id for f in SpotlightFinding.query.filter_by(aid=AID, cve_id=CVE)]
    c = app.test_client()
    _login(c, username, password)
    return c.post("/ingest/delete", data={"finding_ids": ids, "reason": reason,
                                          "back": "/ingest/findings?"})


def test_deleted_finding_lifecycle(app, monkeypatch):
    from app.models_spotlight import INGEST_NEW, SpotlightDeletion
    other = rec(9, cve="CVE-2099-0001")            # keeps each sync non-empty

    sync(app, monkeypatch, [rec(1), other])
    assert _delete_via_ui(app).status_code == 302
    assert rows(app) == []

    # 1. Spotlight still reports it open: it stays gone.
    sync(app, monkeypatch, [rec(1), other])
    assert rows(app) == []
    with app.app_context():
        assert SpotlightDeletion.query.one().closed_seen_at is None

    # 2. A complete sync no longer returns it: Spotlight closed it.
    sync(app, monkeypatch, [other])
    with app.app_context():
        assert SpotlightDeletion.query.one().closed_seen_at is not None
    assert rows(app) == []

    # 3. It comes back: that is a reopen. It returns as New; the mark is gone.
    sync(app, monkeypatch, [rec(1), other])
    found = rows(app)
    assert len(found) == 1 and found[0][1] == INGEST_NEW
    with app.app_context():
        assert SpotlightDeletion.query.count() == 0


def test_closed_record_counts_as_closure(app, monkeypatch):
    from app.models_spotlight import SpotlightDeletion
    sync(app, monkeypatch, [rec(1)])
    _delete_via_ui(app)
    sync(app, monkeypatch, [rec(1, status="closed")])
    with app.app_context():
        assert SpotlightDeletion.query.one().closed_seen_at is not None


@pytest.mark.parametrize("kw", [{"fql_filter": "status:'open'+hostname:'x'"},
                                {"max_pages": 1}])
def test_absence_proves_nothing_on_a_partial_sync(app, monkeypatch, kw):
    """A one-off manual filter or a truncated run must not mark a deletion
    closed just because the finding was not in it."""
    from app.models_spotlight import SpotlightDeletion
    sync(app, monkeypatch, [rec(1)])
    _delete_via_ui(app)
    sync(app, monkeypatch, [rec(9, cve="CVE-2099-0001")], **kw)
    with app.app_context():
        assert SpotlightDeletion.query.one().closed_seen_at is None


def test_findings_on_a_risk_cannot_be_deleted(app, monkeypatch):
    from app.models_spotlight import SpotlightFinding
    sync(app, monkeypatch, [rec(1)])
    with app.app_context():
        ids = [f.id for f in SpotlightFinding.query]
    c = app.test_client()
    _login(c)
    c.post("/ingest/elevate", data={"finding_ids": ids, "likelihood": "4", "impact": "4"})
    resp = c.post("/ingest/delete", data={"finding_ids": ids}, follow_redirects=True)
    assert b"attached to a" in resp.data
    assert len(rows(app)) == 1


def test_restore_brings_it_back_on_next_sync(app, monkeypatch):
    from app.models_spotlight import SpotlightDeletion
    sync(app, monkeypatch, [rec(1)])
    _delete_via_ui(app)
    with app.app_context():
        did = SpotlightDeletion.query.one().id
    c = app.test_client()
    _login(c)
    assert c.post(f"/ingest/deleted/{did}/restore").status_code == 302
    sync(app, monkeypatch, [rec(1)])
    assert len(rows(app)) == 1


def test_operators_delete_viewers_do_not(app, monkeypatch):
    from app.models import User, db
    sync(app, monkeypatch, [rec(1)])
    with app.app_context():
        v = User(username="viewer", email="v@example.org", name="Vee", role="viewer")
        v.set_password(OPERATOR_PW)
        db.session.add(v)
        db.session.commit()
    assert _delete_via_ui(app, "viewer", OPERATOR_PW).status_code == 403
    assert len(rows(app)) == 1
    _make_operator(app)
    assert _delete_via_ui(app, "op", OPERATOR_PW).status_code == 302
    assert rows(app) == []


def test_deleted_page_and_delete_button_render(app, monkeypatch):
    sync(app, monkeypatch, [rec(1)])
    c = app.test_client()
    _login(c)
    page = c.get(f"/ingest/host/{AID}").get_data(as_text=True)
    assert 'formaction="/ingest/delete"' in page
    assert "e.submitter" in page, "Delete has its own confirm prompt"
    _delete_via_ui(app, reason="Lab VM, rebuilt nightly")
    body = c.get("/ingest/deleted").get_data(as_text=True)
    assert CVE in body and "Lab VM, rebuilt nightly" in body and "Still open in Spotlight" in body
    assert "Deleted findings (1)" in c.get("/ingest/").get_data(as_text=True)


# ── Upgrade cleanup of an existing database ─────────────────────────────────
def test_startup_cleanup_merges_duplicates_and_drops_medium_low(tmp_path):
    """An existing database with the old duplicates and Medium/Low rows is
    cleaned the first time the upgraded app starts."""
    from app.models import db
    from app.models_spotlight import (INGEST_DISMISSED, INGEST_ELEVATED, INGEST_NEW,
                                      SpotlightFinding)
    uri = f"sqlite:///{tmp_path}/old.db"
    app = _make_app(SQLALCHEMY_DATABASE_URI=uri)
    with app.app_context():
        add = db.session.add
        add(SpotlightFinding(spotlight_id="a_1", aid=AID, cve_id=CVE, cve_severity="HIGH",
                             product_name_version="Google Chrome 120.0", ingest_state=INGEST_NEW,
                             spotlight_status="open"))
        add(SpotlightFinding(spotlight_id="a_2", aid=AID, cve_id=CVE, cve_severity="HIGH",
                             product_name_version="Microsoft Edge 120.0",
                             ingest_state=INGEST_DISMISSED, dismissed_reason="kiosk",
                             spotlight_status="open"))
        add(SpotlightFinding(spotlight_id="m_1", aid=AID, cve_id="CVE-M", cve_severity="MEDIUM"))
        add(SpotlightFinding(spotlight_id="l_1", aid=AID, cve_id="CVE-L", cve_severity="Low"))
        add(SpotlightFinding(spotlight_id="m_2", aid=AID, cve_id="CVE-ME", cve_severity="MEDIUM",
                             ingest_state=INGEST_ELEVATED, elevation_id=1))
        db.session.commit()

    upgraded = _make_app(SQLALCHEMY_DATABASE_URI=uri)   # startup runs the cleanup
    with upgraded.app_context():
        dup = SpotlightFinding.query.filter_by(aid=AID, cve_id=CVE).all()
        assert len(dup) == 1
        assert dup[0].ingest_state == INGEST_DISMISSED, "the human decision survives the merge"
        assert dup[0].dismissed_reason == "kiosk"
        assert set(dup[0].product_name_version.split(", ")) == {
            "Google Chrome 120.0", "Microsoft Edge 120.0"}
        remaining = sorted(f.cve_id for f in SpotlightFinding.query)
        assert remaining == [CVE, "CVE-ME"], "Medium/Low gone, except the one on a risk"

    again = _make_app(SQLALCHEMY_DATABASE_URI=uri)       # idempotent
    with again.app_context():
        assert SpotlightFinding.query.count() == 2


def test_sync_counts_rows_not_records(app, monkeypatch):
    from app.models_spotlight import SpotlightSyncRun
    first = sync(app, monkeypatch, [rec(1), rec(2, "Microsoft Edge 120.0"), rec(3, "x 1")])
    again = sync(app, monkeypatch, [rec(1), rec(2, "Microsoft Edge 120.0")])
    with app.app_context():
        a, b = (app.extensions["sqlalchemy"].session.get(SpotlightSyncRun, i) for i in (first, again))
        assert (a.records_fetched, a.findings_created, a.findings_updated) == (3, 1, 0)
        assert (b.records_fetched, b.findings_created, b.findings_updated) == (2, 0, 1)


def test_queue_shows_how_many_products_a_row_covers(app, monkeypatch):
    sync(app, monkeypatch, [rec(1, "Google Chrome 120.0"), rec(2, "Microsoft Edge 120.0"),
                            rec(3, "Google Chrome 119.0")])
    c = app.test_client()
    _login(c)
    for path in (f"/ingest/host/{AID}", f"/ingest/cve/{CVE}", "/ingest/findings"):
        body = c.get(path).get_data(as_text=True)
        assert "+2 more" in body, path
        assert 'title="Google Chrome 120.0, Microsoft Edge 120.0, Google Chrome 119.0"' in body, path


# ── Closure by absence (review 2026-10-16, item 1) ──────────────────────────
def _other():
    return rec(9, cve="CVE-2099-0001")     # keeps a sync non-empty


def test_patched_finding_closes_when_spotlight_stops_reporting_it(app, monkeypatch):
    from app.models_spotlight import SpotlightFinding, SpotlightSyncRun
    sync(app, monkeypatch, [rec(1), _other()])
    run_id = sync(app, monkeypatch, [_other()])     # CVE patched: no longer returned
    with app.app_context():
        f = SpotlightFinding.query.filter_by(cve_id=CVE).one()
        assert f.spotlight_status == "closed" and f.closed_timestamp is not None
        assert app.extensions["sqlalchemy"].session.get(SpotlightSyncRun, run_id).findings_closed == 1
    c = app.test_client()
    _login(c)
    assert CVE not in c.get("/ingest/findings").get_data(as_text=True), "closed rows leave the queue"
    assert CVE in c.get("/ingest/findings?include_closed=1").get_data(as_text=True), "but are kept"


def test_closed_finding_reopens_when_it_comes_back(app, monkeypatch):
    from app.models_spotlight import SpotlightFinding
    sync(app, monkeypatch, [rec(1), _other()])
    sync(app, monkeypatch, [_other()])
    sync(app, monkeypatch, [rec(1), _other()])
    with app.app_context():
        f = SpotlightFinding.query.filter_by(cve_id=CVE).one()
        assert f.spotlight_status == "open" and f.closed_timestamp is None


def test_risk_shows_remediated_without_anyone_clicking_reconcile(app, monkeypatch):
    from app.models import VulnerabilityFinding
    from app.models_spotlight import SpotlightFinding
    sync(app, monkeypatch, [rec(1), _other()])
    with app.app_context():
        fid = SpotlightFinding.query.filter_by(cve_id=CVE).one().id
    c = app.test_client()
    _login(c)
    c.post("/ingest/elevate", data={"finding_ids": [fid], "likelihood": "4", "impact": "4"})
    sync(app, monkeypatch, [_other()])
    with app.app_context():
        assert VulnerabilityFinding.query.filter_by(cve_id=CVE).one().status == "Remediated"


@pytest.mark.parametrize("records,kw,why", [
    ([], {}, "empty response"),
    ([None], {"fql_filter": "status:'open'+hostname:'x'"}, "manual filter"),
    ([None], {"max_pages": 1}, "page limit"),
])
def test_untrustworthy_syncs_close_nothing(app, monkeypatch, records, kw, why):
    """An empty, filtered, or truncated sync proves nothing by absence: open
    findings stay open and deletions are not marked closed (item 2)."""
    from app.models_spotlight import SpotlightDeletion, SpotlightFinding
    sync(app, monkeypatch, [rec(1), rec(2, cve="CVE-2099-0002")])
    with app.app_context():
        doomed = SpotlightFinding.query.filter_by(cve_id="CVE-2099-0002").one().id
    c = app.test_client()
    _login(c)
    c.post("/ingest/delete", data={"finding_ids": [doomed]})
    sync(app, monkeypatch, [_other() if r is None else r for r in records], **kw)
    with app.app_context():
        assert SpotlightFinding.query.filter_by(cve_id=CVE).one().spotlight_status == "open", why
        assert SpotlightDeletion.query.one().closed_seen_at is None, why


# ── Items 3-5 ───────────────────────────────────────────────────────────────
def test_elevation_rejects_unknown_status(app, monkeypatch):
    from app.models import Risk
    from app.models_spotlight import SpotlightFinding
    sync(app, monkeypatch, [rec(1)])
    with app.app_context():
        fid = SpotlightFinding.query.one().id
    c = app.test_client()
    _login(c)
    c.post("/ingest/elevate", data={"finding_ids": [fid], "likelihood": "3", "impact": "3",
                                    "status": "Pwned"})
    with app.app_context():
        assert Risk.query.one().status == "Open"


def test_generated_text_uses_us_spelling():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("app/spotlight/elevate.py", "app/templates/ingest/cve_detail.html"):
        assert "theorised" not in open(os.path.join(root, rel)).read(), rel


def test_database_import_cleans_the_queue(app, monkeypatch, tmp_path):
    """Importing an older database applies the same cleanup a restart would."""
    import io
    import app.spotlight.maintenance as maint
    # a minimal valid database: an empty copy of this app's own schema
    src = tmp_path / "export.db"
    other = _make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{src}")
    with other.app_context():
        other.extensions["sqlalchemy"].engine.dispose()
    # Count only calls made by the import itself. Patched after building the
    # export, because every app startup runs the cleanup too.
    calls = []
    monkeypatch.setattr(maint, "dedupe_and_prune", lambda *a, **k: calls.append(a) or (0, 0))
    c = app.test_client()
    _login(c)
    resp = c.post("/settings/db/import", follow_redirects=True, content_type="multipart/form-data",
                  data={"db_file": (io.BytesIO(src.read_bytes()), "export.db")})
    assert b"imported successfully" in resp.data
    assert calls, "dedupe_and_prune must run after an import"
