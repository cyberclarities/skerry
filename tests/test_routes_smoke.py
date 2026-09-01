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
                  data={"finding_ids": ids, "likelihood": "4", "impact": "5",
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
