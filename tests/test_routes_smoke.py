"""Boot the real app factory and render every new page.

Catches the failures unit tests miss: a blueprint that will not register, a
template that references a variable the view does not pass, a url_for to an
endpoint that does not exist.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def client():
    """A real app from create_app(), configured in code rather than via env.

    Config is passed as a class instead of environment variables because
    app.config.Config reads os.environ once at import time, and by the time
    a test runs that import has already happened.
    """
    tmp = tempfile.mkdtemp()
    from app import create_app
    from app.config import Config

    class TestConfig(Config):
        SECRET_KEY = "test-key-" + "z" * 40
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp}/smoke.db"
        SESSION_COOKIE_SECURE = False
        REMEMBER_COOKIE_SECURE = False
        WTF_CSRF_ENABLED = False
        TESTING = True
        ADMIN_EMAIL = "admin@example.org"
        ADMIN_USERNAME = "admin"
        ADMIN_PASSWORD = "Sm0ke-Test-Password!"
        SMTP_HOST = ""
        SPOTLIGHT_SYNC_ENABLED = False
        FALCON_CLIENT_ID = ""
        FALCON_CLIENT_SECRET = ""
        RATELIMIT_ENABLED = False

    application = create_app(TestConfig)

    with application.test_client() as c:
        c.post("/login", data={"username": "admin",
                               "password": "Sm0ke-Test-Password!"},
               follow_redirects=True)
        yield c, application


def test_ingest_pages_render_with_an_empty_queue(client):
    c, _app = client
    for path in ("/ingest/", "/ingest/findings", "/ingest/runs"):
        resp = c.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
    assert b"No Spotlight sync has run yet" in c.get("/ingest/").data


def test_ingest_pages_render_with_data(client):
    import json
    c, application = client
    from app.models import db
    from app.spotlight.ingest import upsert_finding, upsert_host

    payload = json.load(open(os.path.join(os.path.dirname(__file__),
                                          "sample_spotlight_payload.json")))
    with application.app_context():
        for record in payload["resources"]:
            host, _ = upsert_host(record)
            if host is not None and host.id is None:
                db.session.flush()
            upsert_finding(record, host)
        db.session.commit()

    body = c.get("/ingest/").data
    assert b"SKY-DC01" in body
    assert b"KEV" in body

    assert c.get("/ingest/host/abc123def456").status_code == 200
    assert c.get("/ingest/cve/CVE-2024-21412").status_code == 200
    assert c.get("/ingest/findings?kev=1").status_code == 200
    assert c.get("/ingest/findings?severity=High&exprt=Critical").status_code == 200
    assert c.get("/ingest/host/does-not-exist").status_code == 404


def test_elevate_form_renders_and_creates_a_risk(client):
    import json
    c, application = client
    from app.models import Risk, VulnerabilityFinding, db
    from app.models_spotlight import SpotlightFinding
    from app.spotlight.ingest import upsert_finding, upsert_host

    payload = json.load(open(os.path.join(os.path.dirname(__file__),
                                          "sample_spotlight_payload.json")))
    with application.app_context():
        for record in payload["resources"]:
            host, _ = upsert_host(record)
            if host is not None and host.id is None:
                db.session.flush()
            upsert_finding(record, host)
        db.session.commit()
        ids = [f.id for f in SpotlightFinding.query.filter_by(aid="abc123def456").all()]

    form = c.get("/ingest/elevate", query_string=[("finding_ids", i) for i in ids])
    assert form.status_code == 200
    assert b"How these scores were suggested" in form.data
    assert b"ExPRT.AI" in form.data

    resp = c.post("/ingest/elevate",
                  data={"finding_ids": ids, "confirm_elevate": "1",
                        "likelihood": "4", "impact": "5",
                        "risk_owner": "Ted Mecimore",
                        "business_process": "Directory services"},
                  follow_redirects=True)
    assert resp.status_code == 200

    with application.app_context():
        risk = Risk.query.filter(Risk.asset_system == "SKY-DC01").first()
        assert risk is not None
        assert risk.likelihood == 4 and risk.impact == 5
        assert risk.rag_status in ("RED", "AMBER")
        assert VulnerabilityFinding.query.filter_by(risk_id=risk.id).count() == 2

    # the existing risk detail page renders the copied findings unchanged
    detail = c.get(f"/risks/{risk.id}")
    assert detail.status_code == 200
    assert b"CVE-2024-21412" in detail.data


def test_dismiss_requires_a_reason(client):
    import json
    c, application = client
    from app.models import db
    from app.models_spotlight import INGEST_NEW, SpotlightFinding
    from app.spotlight.ingest import upsert_finding, upsert_host

    payload = json.load(open(os.path.join(os.path.dirname(__file__),
                                          "sample_spotlight_payload.json")))
    with application.app_context():
        for record in payload["resources"]:
            host, _ = upsert_host(record)
            if host is not None and host.id is None:
                db.session.flush()
            upsert_finding(record, host)
        db.session.commit()
        fid = SpotlightFinding.query.filter_by(aid="ffff9999").first().id

    c.post("/ingest/triage", data={"finding_ids": [fid], "action": "dismiss"},
           follow_redirects=True)
    with application.app_context():
        assert db.session.get(SpotlightFinding, fid).ingest_state == INGEST_NEW

    c.post("/ingest/triage",
           data={"finding_ids": [fid], "action": "dismiss",
                 "reason": "Laptop reimaged 2026-08-30."},
           follow_redirects=True)
    with application.app_context():
        row = db.session.get(SpotlightFinding, fid)
        assert row.ingest_state == "Dismissed"
        assert row.dismissed_reason == "Laptop reimaged 2026-08-30."
        assert row.dismissed_by_id is not None


def test_sync_without_credentials_fails_loudly(client):
    c, application = client
    from app.models_spotlight import SpotlightSyncRun

    resp = c.post("/ingest/sync", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Sync failed" in resp.data
    with application.app_context():
        run = SpotlightSyncRun.query.order_by(SpotlightSyncRun.id.desc()).first()
        assert run.status == "failed"
        assert "credentials" in run.error_message


# ---------------------------------------------------------------------------
# CVE review: group by CVE, oldest first, review before a risk is created.
# ---------------------------------------------------------------------------
def _load_sample(application):
    import json
    from app.models import db
    from app.spotlight.ingest import upsert_finding, upsert_host
    payload = json.load(open(os.path.join(os.path.dirname(__file__),
                                          "sample_spotlight_payload.json")))
    with application.app_context():
        for record in payload["resources"]:
            host, _ = upsert_host(record)
            if host is not None and host.id is None:
                db.session.flush()
            upsert_finding(record, host)
        db.session.commit()


def test_elevate_button_opens_the_form_instead_of_creating_a_risk(client):
    """The Elevate buttons on the host, CVE, and finding pages POST only the
    selection. That must land on the pre-filled form, not create the risk."""
    c, application = client
    from app.models import Risk
    from app.models_spotlight import SpotlightFinding
    _load_sample(application)
    with application.app_context():
        ids = [f.id for f in SpotlightFinding.query.filter_by(cve_id="CVE-2024-21412")]
        before = Risk.query.count()

    resp = c.post("/ingest/elevate", data={"finding_ids": ids})
    assert resp.status_code == 200
    assert b"How these scores were suggested" in resp.data
    assert b'name="confirm_elevate" value="1"' in resp.data
    with application.app_context():
        assert Risk.query.count() == before, "a risk was created without review"


def test_cve_view_groups_and_puts_the_oldest_first(client):
    from datetime import datetime, timedelta
    c, application = client
    from app.models import db
    from app.models_spotlight import SpotlightFinding
    _load_sample(application)

    with application.app_context():
        # only CVEs the default queue shows: open and not suppressed in Falcon
        cves = sorted({f.cve_id for f in SpotlightFinding.query
                       if f.cve_id and f.is_open and not f.is_suppressed})
        assert len(cves) >= 2
        old_cve, young_cve = cves[0], cves[-1]
        now = datetime.utcnow()
        for f in SpotlightFinding.query.filter_by(cve_id=old_cve):
            f.created_timestamp = now - timedelta(days=200)
        for f in SpotlightFinding.query.filter_by(cve_id=young_cve):
            f.created_timestamp = now - timedelta(days=5)
        for f in SpotlightFinding.query.filter(
                SpotlightFinding.cve_id.notin_([old_cve, young_cve])):
            f.created_timestamp = now - timedelta(days=75)
        db.session.commit()

    page = c.get("/ingest/cves")
    assert page.status_code == 200
    body = page.data.decode()
    # default is 60+ days: the 5-day CVE waits, and the page says so
    assert old_cve in body and young_cve not in body
    assert "younger CVE(s) not shown" in body
    # oldest exposure first
    others = [x for x in cves if x not in (old_cve, young_cve)]
    for other in others:
        assert body.index(old_cve) < body.index(other)
    assert "200d" in body

    every = c.get("/ingest/cves?min_age=0").data.decode()
    assert young_cve in every and "not shown" not in every

    # each CVE appears once, however many hosts it is on
    widespread = c.get("/ingest/cves?min_age=0&q=CVE-2024-21412").data.decode()
    assert widespread.count('href="/ingest/cve/CVE-2024-21412') == 2  # name + Review button
    assert c.get("/ingest/cves?sort=hosts").status_code == 200
    assert c.get("/ingest/cves?sort=risk&page=99").status_code == 200
    assert c.get("/ingest/cves?sort=nonsense&min_age=-4").status_code == 200


def test_single_cve_risk_is_built_from_the_cve_data(client):
    c, application = client
    from app.models import Risk
    from app.models_spotlight import SpotlightFinding
    _load_sample(application)
    with application.app_context():
        findings = SpotlightFinding.query.filter_by(cve_id="CVE-2024-21412").all()
        lead = max(findings, key=lambda f: f.cve_base_score or 0)
        ids = [f.id for f in findings]
        description = (lead.cve_description or "").strip()

    form = c.post("/ingest/elevate", data={"finding_ids": ids}).data.decode()
    assert "CVE-2024-21412 affects" in form
    assert "Affected hosts (2):" in form
    assert "SKY-DC01" in form and "SKY-LT-0042" in form
    if description:
        assert description[:40] in form

    c.post("/ingest/elevate", data={"finding_ids": ids, "confirm_elevate": "1",
                                    "likelihood": "4", "impact": "4"})
    with application.app_context():
        risk = Risk.query.order_by(Risk.id.desc()).first()
        assert risk.threat_description.startswith("CVE-2024-21412 affects")
        assert "2 hosts" in risk.threat_description
        assert "Affected software:" in risk.vulnerability_detail
        assert "Source: CrowdStrike Falcon Spotlight" in risk.vulnerability_detail
        assert "—" not in risk.threat_description
