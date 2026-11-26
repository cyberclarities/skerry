"""Sending risks to SolarWinds Service Desk by email, and the Email
Settings page. See the project spec SPEC-service-desk-email.md.

Mail never leaves the test: app.ticketing.deliver is replaced with a
recorder, so each test sees exactly what would have been sent.
"""

import os
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import (OPERATOR_PW, _login, _make_app,  # noqa: E402
                                 _make_operator, _make_risk)

DESK = "risk-register@desk.example.org"


@pytest.fixture
def app():
    return _make_app(SMTP_HOST="mail.example.org", SMTP_FROM="skerry@example.org",
                     BASE_URL="https://skerry.example.org:8443")


@pytest.fixture
def outbox(monkeypatch):
    """Every message ticketing would send: (to, subject, body)."""
    import app.ticketing as ticketing
    sent = []

    def fake_deliver(to, subject, body):
        sent.append((to, subject, body))
        return None

    monkeypatch.setattr(ticketing, "deliver", fake_deliver)
    return sent


def _admin(app):
    c = app.test_client()
    _login(c)
    return c


def _configure(client, enabled=True, address=DESK, auto="off", fields=None, **extra):
    data = {"ticket_address": address, "ticket_auto_send": auto,
            "notice_overdue": "1", "notice_review_due": "1", "notice_escalation": "1"}
    if enabled:
        data["ticket_enabled"] = "1"
    data.update(extra)
    if fields is not None:
        data["ticket_fields"] = fields
    return client.post("/settings/email", data=data)


def _sends(app, risk_pk):
    from app.models import TicketSend
    with app.app_context():
        return [(s.ok, s.trigger, s.recipient, s.error)
                for s in TicketSend.query.filter_by(risk_id=risk_pk).order_by(TicketSend.id)]


SECRET_THREAT = "Attackers can reach the VPN appliance. More detail here."


def _red_risk(app, **fields):
    defaults = dict(risk_category="Infrastructure", likelihood=5, impact=5,
                    threat_description=SECRET_THREAT, asset_system="vpn01",
                    remediation_action="Patch it", risk_owner="Owen Owner",
                    action_owner="Ada Action", due_date=date(2026, 12, 10))
    defaults.update(fields)
    from app.models import Risk, db
    with app.app_context():
        n = Risk.query.count() + 1
        r = Risk(risk_id=f"SKR-{n:03d}", **defaults)
        db.session.add(r)
        db.session.commit()
        return r.id


# ── Defaults ─────────────────────────────────────────────────────────────
def test_ticketing_is_off_by_default_and_the_card_is_hidden(app):
    pk = _red_risk(app)
    html = _admin(app).get(f"/risks/{pk}").get_data(as_text=True)
    assert 'id="service-desk"' not in html


def test_send_route_is_not_there_while_ticketing_is_off(app, outbox):
    pk = _red_risk(app)
    assert _admin(app).post(f"/risks/{pk}/ticket/send").status_code == 404
    assert outbox == []


def test_daily_notices_default_on(app):
    from app import app_settings as s
    with app.app_context():
        assert all(s.get_bool(k) for k in s.NOTICES)
        assert s.ticket_fields() == {"category", "treatment", "nist_csf"}


# ── Email Settings page ──────────────────────────────────────────────────
def test_email_settings_is_admin_only(app):
    _make_operator(app)
    c = app.test_client()
    _login(c, "op", OPERATOR_PW)
    assert c.get("/settings/email").status_code == 403
    assert c.post("/settings/email/test").status_code == 403


def test_settings_page_renders_and_saves(app):
    c = _admin(app)
    assert c.get("/settings/email").status_code == 200
    _configure(c, auto="red", fields=["category", "threat"])
    from app import app_settings as s
    from app.models import AppSetting, db
    with app.app_context():
        assert s.get_bool(s.TICKET_ENABLED)
        assert s.get(s.TICKET_ADDRESS) == DESK
        assert s.get(s.TICKET_AUTO_SEND) == "red"
        assert s.ticket_fields() == {"category", "threat"}
        assert db.session.get(AppSetting, s.TICKET_ADDRESS).updated_by_id is not None
    html = c.get("/settings/email").get_data(as_text=True)
    assert "Last changed" in html and DESK in html


def test_cannot_switch_on_without_an_address(app):
    c = _admin(app)
    _configure(c, address="")
    from app import app_settings as s
    with app.app_context():
        assert not s.get_bool(s.TICKET_ENABLED)


def test_a_bad_address_is_refused(app):
    c = _admin(app)
    _configure(c, address="not-an-address")
    from app import app_settings as s
    with app.app_context():
        assert s.get(s.TICKET_ADDRESS) == ""


def test_unknown_auto_send_rule_is_refused(app):
    assert _configure(_admin(app), auto="everything-twice").status_code == 400


# ── The button ───────────────────────────────────────────────────────────
def test_send_opens_one_incident_and_is_recorded(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    assert "Send to Service Desk" in c.get(f"/risks/{pk}").get_data(as_text=True)

    c.post(f"/risks/{pk}/ticket/send")
    assert len(outbox) == 1
    to, subject, body = outbox[0]
    assert to == [DESK]
    assert subject == "SKR-001 [RED] New risk: Infrastructure risk logged in Skerry"
    assert "Rating: RED (residual 25; appetite is 8)" in body
    assert "Action Owner: Ada Action" in body
    assert "Due Date: 2026-12-10" in body
    assert "Full record: https://skerry.example.org:8443/risks/1" in body
    assert "does not close SKR-001" in body
    assert _sends(app, pk) == [(True, "manual", DESK, None)]

    from app.models import AuditLog
    with app.app_context():
        assert AuditLog.query.filter_by(risk_id=pk, action="ticket_sent").count() == 1


def test_sensitive_fields_stay_out_by_default(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    c.post(f"/risks/{pk}/ticket/send")
    _, subject, body = outbox[0]
    for secret in (SECRET_THREAT, "Attackers", "vpn01", "Patch it"):
        assert secret not in subject and secret not in body


def test_switched_on_fields_appear(app, outbox):
    c = _admin(app)
    _configure(c, fields=["threat", "asset_system", "remediation"])
    pk = _red_risk(app)
    c.post(f"/risks/{pk}/ticket/send")
    _, subject, body = outbox[0]
    assert subject == "SKR-001 [RED] New risk: Attackers can reach the VPN appliance"
    assert "Asset / System: vpn01" in body
    assert "Threat\n" + SECRET_THREAT in body
    assert "Remediation action\nPatch it" in body
    assert "Category:" not in body  # switched off by this save


def test_a_resend_needs_confirming(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    c.post(f"/risks/{pk}/ticket/send")
    html = c.get(f"/risks/{pk}").get_data(as_text=True)
    assert "Send again" in html and "opens a second incident" in html

    c.post(f"/risks/{pk}/ticket/send")  # no confirmation
    assert len(outbox) == 1
    c.post(f"/risks/{pk}/ticket/send", data={"confirm_resend": "1"})
    assert len(outbox) == 2
    _, subject, body = outbox[1]
    assert "[RED] Resent risk:" in subject
    assert "This risk was sent before" in body


def test_a_failed_send_is_recorded_and_says_why(app, monkeypatch):
    import app.ticketing as ticketing
    monkeypatch.setattr(ticketing, "deliver", lambda *a: "connection refused")
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    resp = c.post(f"/risks/{pk}/ticket/send", follow_redirects=True)
    assert "connection refused" in resp.get_data(as_text=True)
    assert _sends(app, pk) == [(False, "manual", DESK, "connection refused")]
    # A failure is not a send: the next try needs no confirmation.
    assert "Send to Service Desk" in c.get(f"/risks/{pk}").get_data(as_text=True)


def test_no_smtp_means_no_send_and_a_reason(monkeypatch):
    app = _make_app(SMTP_HOST="")
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    html = c.get(f"/risks/{pk}").get_data(as_text=True)
    assert "Email is not configured on this server" in html
    c.post(f"/risks/{pk}/ticket/send")
    assert _sends(app, pk) == []


def test_only_people_who_can_edit_may_send(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app, risk_owner="Someone Else")
    _make_operator(app)
    op = app.test_client()
    _login(op, "op", OPERATOR_PW)
    assert op.post(f"/risks/{pk}/ticket/send").status_code == 403
    assert "Send to Service Desk" not in op.get(f"/risks/{pk}").get_data(as_text=True)

    mine = _red_risk(app, risk_owner="Op Erator")
    op.post(f"/risks/{mine}/ticket/send")
    assert len(outbox) == 1


def test_spotlight_risks_carry_hosts_cves_and_kev_count(app, outbox):
    c = _admin(app)
    _configure(c, fields=["hosts", "cves"])
    pk = _red_risk(app)
    from app.models import VulnerabilityFinding, db
    from app.models_spotlight import SpotlightElevation, SpotlightFinding
    with app.app_context():
        db.session.add(SpotlightElevation(risk_id=pk, risk_ref="SKR-001",
                                          scope_hosts="vpn02, vpn01", host_count=2,
                                          finding_count=3, cve_list="CVE-2026-0001"))
        db.session.add(VulnerabilityFinding(risk_id=pk, cve_id="CVE-2026-0002", status="Open"))
        db.session.add(VulnerabilityFinding(risk_id=pk, cve_id="CVE-2026-0003", status="Remediated"))
        db.session.add(SpotlightFinding(spotlight_id="f1", risk_id=pk, is_cisa_kev=True))
        db.session.commit()
    c.post(f"/risks/{pk}/ticket/send")
    _, _, body = outbox[0]
    assert "Source: CrowdStrike Spotlight, 2 host(s), 3 finding(s), 1 in CISA KEV" in body
    assert "Affected hosts: vpn01, vpn02" in body
    assert "CVEs: CVE-2026-0002\n" in body   # open findings only


# ── Incident number ──────────────────────────────────────────────────────
def test_incident_number_is_saved_on_the_send(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    c.post(f"/risks/{pk}/ticket/send")
    from app.models import TicketSend
    with app.app_context():
        send_pk = TicketSend.query.one().id
    c.post(f"/risks/{pk}/ticket/{send_pk}/number", data={"ticket_number": " INC-1234 "})
    with app.app_context():
        assert TicketSend.query.one().ticket_number == "INC-1234"

    other = _red_risk(app)
    assert c.post(f"/risks/{other}/ticket/{send_pk}/number",
                  data={"ticket_number": "x"}).status_code == 404


# ── Auto-send ────────────────────────────────────────────────────────────
def _new_risk(client, likelihood, impact):
    return client.post("/risks/new", data={
        "risk_category": "Data", "likelihood": str(likelihood), "impact": str(impact),
        "risk_owner": "Owen Owner", "status": "Open"})


def test_auto_send_follows_the_rule(app, outbox):
    c = _admin(app)
    _configure(c, auto="red")
    _new_risk(c, 5, 5)   # RED
    _new_risk(c, 1, 2)   # GREEN
    assert [s[1].split(" ")[1] for s in outbox] == ["[RED]"]
    from app.models import TicketSend
    with app.app_context():
        assert [t.trigger for t in TicketSend.query.all()] == ["auto"]


def test_auto_send_off_sends_nothing(app, outbox):
    c = _admin(app)
    _configure(c, auto="off")
    _new_risk(c, 5, 5)
    assert outbox == []


def test_a_failed_auto_send_does_not_lose_the_risk(app, monkeypatch):
    import app.ticketing as ticketing
    monkeypatch.setattr(ticketing, "deliver", lambda *a: "server down")
    c = _admin(app)
    _configure(c, auto="all")
    resp = _new_risk(c, 5, 5)
    assert resp.status_code == 302
    from app.models import Risk
    with app.app_context():
        assert Risk.query.count() == 1
    assert _sends(app, 1) == [(False, "auto", DESK, "server down")]


# ── Test message ─────────────────────────────────────────────────────────
def test_test_message_is_marked_and_touches_no_risk(app, outbox):
    c = _admin(app)
    _configure(c, enabled=False)   # address saved, ticketing still off
    c.post("/settings/email/test")
    assert len(outbox) == 1
    _, subject, body = outbox[0]
    assert subject.startswith("[TEST] SKR-TEST [RED]")
    from app.models import Risk, TicketSend
    with app.app_context():
        assert Risk.query.count() == 0 and TicketSend.query.count() == 0


# ── Daily notices ────────────────────────────────────────────────────────
def test_a_switched_off_notice_is_not_sent(app, monkeypatch):
    import app.email_utils as eu
    from app.models import User, db
    with app.app_context():
        u = User(username="ada", email="ada@example.org", name="Ada Action",
                 role="operator", is_active=True)
        u.set_password(OPERATOR_PW)
        db.session.add(u)
        db.session.commit()
    _red_risk(app, due_date=date.today() - timedelta(days=5))

    sent = []
    monkeypatch.setattr(eu, "_send", lambda to, subject, body: sent.append(subject))
    eu.run_daily_notifications(app)
    assert any("Overdue Action" in s for s in sent)

    sent.clear()
    _configure(_admin(app), enabled=False, address="", notice_overdue="0")
    eu.run_daily_notifications(app)
    assert not any("Overdue Action" in s for s in sent)


# ── Deleting a risk ──────────────────────────────────────────────────────
def test_send_history_survives_a_delete_under_the_tombstone(app, outbox):
    c = _admin(app)
    _configure(c)
    pk = _red_risk(app)
    c.post(f"/risks/{pk}/ticket/send")
    c.post(f"/risks/{pk}/delete")
    from app.models import TicketSend
    with app.app_context():
        send = TicketSend.query.one()
        assert send.risk_id < 0 and send.risk_ref == "SKR-001"
    # The next risk takes the freed id and must not inherit the send.
    new_pk = _red_risk(app)
    assert new_pk == pk
    assert "Not sent to the Service Desk yet" in c.get(f"/risks/{new_pk}").get_data(as_text=True)
