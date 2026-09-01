"""End-to-end check of the Spotlight ingest, run without touching CrowdStrike.

The important test is the first one: an existing risk_register.db must come
through this change with every table and every row exactly as it was. The
rest exercise the normalizer, the dedupe key, the scoring suggestions, and
the elevation copy.

Run:  python -m pytest tests/ -q
"""

import json
import os
import sqlite3
import sys
import tempfile
from datetime import date

import pytest
from flask import Flask

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import (AuditLog, LookupItem, NISTCSFReference, Risk, TrendLog,  # noqa: E402
                        User, VulnerabilityFinding, db)

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD = json.load(open(os.path.join(HERE, "sample_spotlight_payload.json")))

LEGACY_TABLES = [
    "users", "risks", "audit_log", "trend_log",
    "vulnerability_findings", "lookup_items", "nist_csf_reference",
]


def _app(db_path):
    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        TESTING=True,
        RAG_RED_THRESHOLD=15, RAG_AMBER_THRESHOLD=9, RISK_APPETITE_THRESHOLD=8,
    )
    db.init_app(app)
    return app


def _schema(db_path):
    """table/index name -> CREATE statement, as SQLite actually stored it."""
    con = sqlite3.connect(db_path)
    rows = con.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
    ).fetchall()
    con.close()
    return {(t, n): s for t, n, s in rows}


# ---------------------------------------------------------------------------
# 1. The one that matters: the existing database is not disturbed.
# ---------------------------------------------------------------------------
def test_existing_schema_and_data_survive_the_upgrade():
    """Build a DB from the pre-change models, add data, then boot with the
    new models and assert nothing about the old tables changed."""
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "risk_register.db")

    # -- Stage 1: the database as it exists today (legacy models only) ------
    app = _app(path)
    with app.app_context():
        legacy_metadata = db.MetaData()
        for name in LEGACY_TABLES:
            db.Model.metadata.tables[name].to_metadata(legacy_metadata)
        legacy_metadata.create_all(db.engine)

        user = User(email="ted@example.org", name="Ted", role="admin")
        user.set_password("x" * 20)
        db.session.add(user)
        db.session.flush()

        risk = Risk(risk_id="SKR-001", risk_category="Infrastructure",
                    asset_system="legacy-host", likelihood=4, impact=4,
                    control_effectiveness=3, created_by_id=user.id,
                    date_identified=date(2026, 1, 1))
        db.session.add(risk)
        db.session.flush()
        db.session.add(VulnerabilityFinding(
            risk_id=risk.id, cve_id="CVE-2019-0708", severity="Critical",
            date_found=date(2026, 1, 1), status="Open"))
        db.session.add(TrendLog(risk_id=risk.id, residual_score=10.4, rag_status="AMBER"))
        db.session.add(AuditLog(risk_id=risk.id, user_id=user.id, action="created"))
        db.session.add(LookupItem(category="risk_owner", value="Ted Mecimore"))
        db.session.add(NISTCSFReference(function_code="ID", category_code="ID.RA",
                                        subcategory_code="ID.RA-01",
                                        description="Vulnerabilities identified"))
        db.session.commit()

    before = _schema(path)
    con = sqlite3.connect(path)
    counts_before = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                     for t in LEGACY_TABLES}
    risk_row_before = con.execute("SELECT * FROM risks WHERE risk_id='SKR-001'").fetchone()
    con.close()

    # -- Stage 2: boot with the new models, exactly as create_app does ------
    app2 = _app(path)
    with app2.app_context():
        from app import models_spotlight  # noqa: F401
        db.create_all()

    after = _schema(path)

    # every legacy CREATE statement is byte-identical
    for key, sql in before.items():
        assert key in after, f"{key} disappeared"
        assert after[key] == sql, f"schema changed for {key}"

    # the new tables arrived
    new_tables = {n for (t, n) in after if t == "table"} - {n for (t, n) in before if t == "table"}
    assert {"spotlight_hosts", "spotlight_findings",
            "spotlight_elevations", "spotlight_sync_runs"} <= new_tables

    # every row is still there and unchanged
    con = sqlite3.connect(path)
    counts_after = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                    for t in LEGACY_TABLES}
    risk_row_after = con.execute("SELECT * FROM risks WHERE risk_id='SKR-001'").fetchone()
    con.close()
    assert counts_before == counts_after
    assert risk_row_before == risk_row_after


# ---------------------------------------------------------------------------
# 2. Normalizer
# ---------------------------------------------------------------------------
@pytest.fixture
def ingested():
    """A fresh DB with the sample payload loaded twice (to prove dedupe)."""
    tmp = tempfile.mkdtemp()
    app = _app(os.path.join(tmp, "t.db"))
    with app.app_context():
        from app import models_spotlight  # noqa: F401
        db.create_all()
        user = User(email="op@example.org", name="Operator", role="operator")
        db.session.add(user)
        db.session.commit()
        yield app, user.id


def _load(records):
    from app.spotlight.ingest import upsert_finding, upsert_host
    results = []
    for record in records:
        try:
            host, _ = upsert_host(record)
            if host is not None and host.id is None:
                db.session.flush()
            finding, action = upsert_finding(record, host)
            results.append((finding, action))
        except Exception as exc:  # mirrors the run_sync skip path
            results.append((None, f"skipped: {exc}"))
    db.session.commit()
    return results


def test_normalizer_parses_and_skips_bad_rows(ingested):
    app, _ = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding, SpotlightHost
        results = _load(PAYLOAD["resources"])

        # 5 findings from 5 records; only 3 hosts, because one record has no
        # aid and so no asset to hang off.
        assert SpotlightFinding.query.count() == 5
        assert SpotlightHost.query.count() == 3
        assert any(str(a).startswith("skipped") for _f, a in results) is False
        # the malformed record has an id but no aid -- it still stores, with
        # a null host. That is deliberate: an id is enough to dedupe on.
        orphan = SpotlightFinding.query.filter_by(spotlight_id="nohost_malformed_1").first()
        assert orphan is not None and orphan.host_id is None

        dc = SpotlightFinding.query.filter_by(
            spotlight_id="abc123def456_CVE-2024-21412_1").first()
        assert dc.cve_id == "CVE-2024-21412"
        assert dc.cve_base_score == 8.1
        assert dc.exprt_rating == "CRITICAL"
        assert dc.exploit_status == 90
        assert dc.is_cisa_kev is True
        assert dc.cisa_due_date == date(2026, 3, 5)
        assert dc.hostname == "SKY-DC01"
        assert dc.remediation_title == "Update Windows Server 2019 to build 17763.5458"
        assert dc.severity_title == "High"
        assert dc.is_open is True
        assert dc.days_open == (date.today() - date(2026, 4, 2)).days

        host = SpotlightHost.query.filter_by(aid="abc123def456").first()
        assert host.hostname == "SKY-DC01"
        assert host.product_type_desc == "Domain Controller"
        assert host.asset_criticality == "Critical"
        assert host.host_groups == "Production Servers"
        assert host.tags == "tier0, patch-window-sat"

        closed = SpotlightFinding.query.filter_by(
            spotlight_id="beef0001_CVE-2021-44228_1").first()
        assert closed.is_open is False
        assert closed.days_open == (date(2026, 7, 1) - date(2025, 11, 1)).days


def test_resync_updates_rather_than_duplicates(ingested):
    app, _ = ingested
    with app.app_context():
        from app.models_spotlight import (INGEST_DISMISSED, SpotlightFinding,
                                          SpotlightHost)
        _load(PAYLOAD["resources"])
        first_count = SpotlightFinding.query.count()

        # An operator makes a triage decision between syncs.
        dc = SpotlightFinding.query.filter_by(
            spotlight_id="abc123def456_CVE-2023-44487_1").first()
        dc.ingest_state = INGEST_DISMISSED
        dc.dismissed_reason = "Compensating control: not exposed."
        db.session.commit()

        _load(PAYLOAD["resources"])   # second pull, same data
        assert SpotlightFinding.query.count() == first_count
        assert SpotlightHost.query.count() == 3

        dc = SpotlightFinding.query.filter_by(
            spotlight_id="abc123def456_CVE-2023-44487_1").first()
        assert dc.ingest_count == 2
        # the sync did NOT undo the human decision
        assert dc.ingest_state == INGEST_DISMISSED
        assert dc.dismissed_reason == "Compensating control: not exposed."


def test_close_is_detected_not_deleted(ingested):
    app, _ = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        _load(PAYLOAD["resources"])

        closing = dict(PAYLOAD["resources"][0])
        closing["status"] = "closed"
        closing["closed_timestamp"] = "2026-08-31T00:00:00Z"
        from app.spotlight.ingest import upsert_finding, upsert_host
        host, _c = upsert_host(closing)
        _f, action = upsert_finding(closing, host)
        db.session.commit()

        assert action == "closed"
        row = SpotlightFinding.query.filter_by(
            spotlight_id="abc123def456_CVE-2024-21412_1").first()
        assert row is not None          # kept, not deleted
        assert row.is_open is False


# ---------------------------------------------------------------------------
# 3. Scoring suggestions
# ---------------------------------------------------------------------------
def test_scoring_suggestions_are_reasoned(ingested):
    app, _ = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding, SpotlightHost
        from app.spotlight.scoring import suggest_scores, suggest_velocity
        _load(PAYLOAD["resources"])

        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()
        hosts = SpotlightHost.query.filter_by(aid="abc123def456").all()
        likelihood, impact, rationale = suggest_scores(findings, hosts)

        # ExPRT CRITICAL -> 5, capped at 5 despite the KEV bump
        assert likelihood == 5
        # CVSS 8.1 -> 4, +1 for Critical asset criticality
        assert impact == 5
        assert "ExPRT.AI" in rationale
        assert "CISA Known Exploited" in rationale
        assert "Set the final numbers yourself" in rationale
        assert suggest_velocity(findings) == "Rapid"

        # A laptop with the same CVE scores lower on impact -- context matters
        lt = SpotlightFinding.query.filter_by(aid="ffff9999").all()
        lt_hosts = SpotlightHost.query.filter_by(aid="ffff9999").all()
        _l, lt_impact, _r = suggest_scores(lt, lt_hosts)
        assert lt_impact == 4


def test_scoring_returns_none_rather_than_inventing_a_number(ingested):
    app, _ = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        from app.spotlight.scoring import suggest_scores
        _load(PAYLOAD["resources"])
        orphan = SpotlightFinding.query.filter_by(spotlight_id="nohost_malformed_1").all()
        likelihood, impact, rationale = suggest_scores(orphan, [])
        assert likelihood is None and impact is None
        assert "left blank" in rationale


# ---------------------------------------------------------------------------
# 4. Elevation
# ---------------------------------------------------------------------------
def test_elevate_single_host_creates_risk_and_copies_findings(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import (INGEST_ELEVATED, SpotlightElevation,
                                          SpotlightFinding)
        from app.spotlight.elevate import elevate
        _load(PAYLOAD["resources"])

        user = db.session.get(User, user_id)
        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()
        risk, elevation, skipped = elevate(findings, {}, user, "SKR-001")
        db.session.commit()

        assert skipped == []
        assert risk.risk_id == "SKR-001"
        assert risk.asset_system == "SKY-DC01"
        assert risk.likelihood == 5 and risk.impact == 5
        assert risk.threat_intel_source == "CrowdStrike Falcon Spotlight"
        assert risk.assurance_source == "Vulnerability Scan"
        assert risk.nist_csf_subcategory == "ID.RA-01"
        assert risk.date_identified == date(2026, 1, 15)  # earliest of the two
        assert "CISA Known Exploited" in risk.threat_description
        assert "CVE-2024-21412" in risk.vulnerability_detail
        assert "Source: CrowdStrike Falcon Spotlight" in risk.vulnerability_detail
        assert "Elevated from CrowdStrike Spotlight ingest" in risk.notes_history

        # the copy landed in the register's own table -- existing code path
        copied = VulnerabilityFinding.query.filter_by(risk_id=risk.id).all()
        assert len(copied) == 2
        assert {c.cve_id for c in copied} == {"CVE-2024-21412", "CVE-2023-44487"}
        assert all(c.severity == "High" for c in copied)
        assert {c.expert_rating for c in copied} == {"Critical", "High"}
        assert all(c.vulnerable_product.startswith("SKY-DC01 | ") for c in copied)

        # the existing aggregate properties now work with no other change
        assert risk.open_vuln_count == 2
        assert risk.high_vuln_count == 2
        assert risk.oldest_vuln_days == (date.today() - date(2026, 1, 15)).days
        assert risk.inherent_risk_score == 25

        # provenance is recorded both ways
        for staged in SpotlightFinding.query.filter_by(aid="abc123def456").all():
            assert staged.ingest_state == INGEST_ELEVATED
            assert staged.elevation_id == elevation.id
            assert staged.risk_id == risk.id
            assert staged.vuln_finding_id in {c.id for c in copied}

        assert SpotlightElevation.query.count() == 1
        assert elevation.scope_type == "host"
        assert elevation.host_count == 1 and elevation.finding_count == 2
        assert elevation.suggested_likelihood == 5
        assert elevation.risk.risk_id == "SKR-001"


def test_elevate_one_cve_across_hosts(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        from app.spotlight.elevate import elevate
        _load(PAYLOAD["resources"])

        user = db.session.get(User, user_id)
        widespread = SpotlightFinding.query.filter_by(cve_id="CVE-2024-21412").all()
        assert len(widespread) == 2

        risk, elevation, _s = elevate(widespread, {}, user, "SKR-002")
        db.session.commit()

        assert elevation.scope_type == "hosts"
        assert elevation.scope_label == "CVE-2024-21412 (2 hosts)"
        assert elevation.host_count == 2
        assert "SKY-DC01" in elevation.scope_hosts and "SKY-LT-0042" in elevation.scope_hosts
        assert "2 hosts" in risk.threat_description
        # host-qualified product names, so a multi-host risk stays readable
        products = {c.vulnerable_product for c in
                    VulnerabilityFinding.query.filter_by(risk_id=risk.id).all()}
        assert any(p.startswith("SKY-DC01 |") for p in products)
        assert any(p.startswith("SKY-LT-0042 |") for p in products)


def test_operator_input_overrides_the_suggestion(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        from app.spotlight.elevate import elevate
        _load(PAYLOAD["resources"])
        user = db.session.get(User, user_id)
        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()

        form = {"likelihood": "2", "impact": "3", "risk_owner": "Ted Mecimore",
                "business_process": "Directory services for the whole estate",
                "treatment": "Accept"}
        risk, elevation, _s = elevate(findings, form, user, "SKR-003")
        db.session.commit()

        assert risk.likelihood == 2 and risk.impact == 3   # operator wins
        assert risk.risk_owner == "Ted Mecimore"
        assert risk.treatment == "Accept"
        # but the suggestion is still on the record, for review later
        assert elevation.suggested_likelihood == 5
        assert elevation.suggested_impact == 5


def test_double_elevation_is_refused(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        from app.spotlight.elevate import elevate
        _load(PAYLOAD["resources"])
        user = db.session.get(User, user_id)
        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()

        elevate(findings, {}, user, "SKR-001")
        db.session.commit()

        risk2, elev2, skipped = elevate(findings, {}, user, "SKR-002")
        assert risk2 is None and elev2 is None
        assert len(skipped) == 2
        assert Risk.query.count() == 1


def test_reconcile_marks_remediated_without_touching_anything_else(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightFinding
        from app.spotlight.elevate import elevate, sync_elevated_statuses
        _load(PAYLOAD["resources"])
        user = db.session.get(User, user_id)
        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()
        risk, _e, _s = elevate(findings, {}, user, "SKR-001")
        db.session.commit()

        copied = VulnerabilityFinding.query.filter_by(
            risk_id=risk.id, cve_id="CVE-2024-21412").first()
        copied.severity = "Critical"   # an operator corrects the severity by hand
        db.session.commit()

        staged = SpotlightFinding.query.filter_by(
            spotlight_id="abc123def456_CVE-2024-21412_1").first()
        staged.spotlight_status = "closed"
        db.session.commit()

        assert sync_elevated_statuses() == 1
        db.session.refresh(copied)
        assert copied.status == "Remediated"
        assert copied.severity == "Critical"   # the hand correction survived
        assert risk.open_vuln_count == 1


def test_deleting_a_risk_does_not_break_the_elevation_record(ingested):
    app, user_id = ingested
    with app.app_context():
        from app.models_spotlight import SpotlightElevation, SpotlightFinding
        from app.spotlight.elevate import elevate
        _load(PAYLOAD["resources"])
        user = db.session.get(User, user_id)
        findings = SpotlightFinding.query.filter_by(aid="abc123def456").all()
        risk, elevation, _s = elevate(findings, {}, user, "SKR-001")
        db.session.commit()
        risk_pk = risk.id

        # exactly what the existing admin delete route does
        db.session.delete(db.session.get(Risk, risk_pk))
        db.session.commit()

        elevation = db.session.get(SpotlightElevation, elevation.id)
        assert elevation is not None
        assert elevation.risk is None            # resolves to None, does not raise
        assert elevation.risk_ref == "SKR-001"   # the reference is still readable


# ---------------------------------------------------------------------------
# 5. Client plumbing (no network)
# ---------------------------------------------------------------------------
def test_parse_ts_handles_falcon_timestamps():
    from app.spotlight.client import parse_ts
    assert parse_ts("2026-04-02T09:14:00Z").isoformat() == "2026-04-02T09:14:00"
    assert parse_ts("2026-04-02T09:14:00.123Z").year == 2026
    assert parse_ts("2026-04-02T09:14:00+02:00").hour == 7   # normalized to UTC
    assert parse_ts("") is None
    assert parse_ts("not a date") is None


def test_client_refuses_missing_credentials_and_bad_region():
    from app.spotlight.client import FalconSpotlightClient, SpotlightError
    with pytest.raises(SpotlightError, match="credentials"):
        FalconSpotlightClient("", "", region="us-1")
    with pytest.raises(SpotlightError, match="Unknown Falcon region"):
        FalconSpotlightClient("id", "secret", region="mars-1")
