"""The daily register snapshot: one row of counts per day.

A snapshot is taken at most once per calendar day (UTC), by the first
request of the day (the hook in app/__init__.py). Docker's health check
calls /health every 30 seconds, so in a running deployment that is just
after midnight UTC, every day, whether or not anyone signs in. The same
time each day keeps the trend comparable from one day to the next.

The nightly Spotlight sync also asks for one when it finishes, as a backup
for a deployment without the health check. A day's row is never
rewritten, so history stays as it was seen.
"""
import logging
from datetime import datetime, timezone

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.assurance import is_active, needs_attention
from app.models import RegisterSnapshot, Risk, db

log = logging.getLogger(__name__)

def _mark(day):
    """Remember, per app, the day already known to have a row."""
    current_app.extensions["snapshot_day"] = day


def today_utc():
    return datetime.now(timezone.utc).date()


def build_snapshot(day):
    """A RegisterSnapshot of the register as it stands now, dated `day`."""
    from app.models_spotlight import SpotlightFinding
    red_t = current_app.config.get("RAG_RED_THRESHOLD", 15)
    amber_t = current_app.config.get("RAG_AMBER_THRESHOLD", 9)
    risks = Risk.query.all()
    active = [r for r in risks if is_active(r)]
    rag = [r.rag_status for r in active]
    attention = needs_attention(risks, day, red_t, amber_t)
    return RegisterSnapshot(
        snapshot_date=day,
        active=len(active),
        closed=len(risks) - len(active),
        red=rag.count("RED"),
        amber=rag.count("AMBER"),
        green=rag.count("GREEN"),
        unscored=rag.count("UNKNOWN"),
        exceeds_appetite=sum(1 for r in active if r.exceeds_risk_appetite),
        board_flags=sum(1 for r in active if r.board_reporting_flag),
        spotlight_open=SpotlightFinding.query.filter(
            SpotlightFinding.spotlight_status.in_(("open", "reopen")),
            SpotlightFinding.is_suppressed.is_(False)).count(),
        **attention,
    )


def take_snapshot_if_missing(day=None):
    """Write today's snapshot unless one exists. Returns the row written, or
    None when the day already had one. Safe to call from anywhere, any
    number of times: the unique date keeps it to one row a day."""
    day = day or today_utc()
    if RegisterSnapshot.query.filter_by(snapshot_date=day).first() is not None:
        _mark(day)
        return None
    snap = build_snapshot(day)
    db.session.add(snap)
    try:
        db.session.commit()
    except IntegrityError:          # another request wrote it first
        db.session.rollback()
        _mark(day)
        return None
    _mark(day)
    log.info("Register snapshot taken for %s: %s active, %s RED.", day, snap.active, snap.red)
    return snap


def ensure_today():
    """The per-request hook: one cheap comparison on every request after the
    first of the day. Never lets a snapshot problem break a page."""
    if current_app.extensions.get("snapshot_day") == today_utc():
        return
    try:
        take_snapshot_if_missing()
    except Exception:  # noqa: BLE001 -- a page must not fail for a snapshot
        db.session.rollback()
        log.exception("Register snapshot failed; the page carries on.")
