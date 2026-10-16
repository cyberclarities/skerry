"""Queue upkeep: the one-time cleanup, and deleting findings as noise.

dedupe_and_prune() runs at every startup and does nothing once the queue is
clean, so an existing database is fixed on the first restart after upgrade
with no separate migration step:

  * Findings below the configured severities (default Critical and High) are
    deleted, unless they are attached to a risk. A finding on a risk is
    evidence for that risk and is never removed by tidying.

  * Duplicate rows for one host+CVE are merged into one. The survivor is the
    row a person already acted on (elevated, then dismissed, then triaged,
    then the oldest), so no triage decision is lost. Affected products from
    every merged row are kept on the survivor.

delete_findings() removes rows an operator calls noise and remembers the
host+CVE in SpotlightDeletion, so the next sync does not put them back. See
that model for the "stay gone unless it reopens" rule.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, or_

from ..models import db
from ..models_spotlight import (INGEST_DISMISSED, INGEST_ELEVATED, INGEST_TRIAGED,
                                SpotlightDeletion, SpotlightFinding)
from .ingest import DEFAULT_SEVERITIES, OPEN

log = logging.getLogger(__name__)

# Which duplicate survives a merge: human decisions outrank untouched rows.
_STATE_RANK = {INGEST_ELEVATED: 0, INGEST_DISMISSED: 1, INGEST_TRIAGED: 2}


def _utcnow():
    return datetime.now(timezone.utc)


def _split(text):
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def prune_below_severity(severities=DEFAULT_SEVERITIES):
    """Delete unelevated findings whose severity is not in `severities`."""
    allowed = [s.upper() for s in severities]
    doomed = SpotlightFinding.query.filter(
        SpotlightFinding.elevation_id.is_(None),
        or_(SpotlightFinding.cve_severity.is_(None),
            func.upper(SpotlightFinding.cve_severity).notin_(allowed)),
    )
    return doomed.delete(synchronize_session=False)


def merge_duplicates():
    """Fold duplicate rows for one host+CVE into a single row.

    Elevated rows are never deleted. If more than one row in a group is
    elevated, each keeps its link to its risk; only unelevated rows fold in.
    """
    groups = (
        db.session.query(SpotlightFinding.aid, SpotlightFinding.cve_id)
        .filter(SpotlightFinding.aid.isnot(None), SpotlightFinding.cve_id.isnot(None))
        .group_by(SpotlightFinding.aid, SpotlightFinding.cve_id)
        .having(func.count(SpotlightFinding.id) > 1)
        .all()
    )
    removed = 0
    for aid, cve_id in groups:
        rows = SpotlightFinding.query.filter_by(aid=aid, cve_id=cve_id).all()
        rows.sort(key=lambda r: (_STATE_RANK.get(r.ingest_state, 9), r.id))
        survivor, others = rows[0], rows[1:]

        products = _split(survivor.product_name_version)
        rem_ids = set(_split(survivor.remediation_ids))
        for row in others:
            for p in _split(row.product_name_version):
                if p not in products:
                    products.append(p)
            rem_ids.update(_split(row.remediation_ids))
            if row.created_timestamp and (not survivor.created_timestamp
                                          or row.created_timestamp < survivor.created_timestamp):
                survivor.created_timestamp = row.created_timestamp
            if row.spotlight_status in OPEN and survivor.spotlight_status not in OPEN:
                survivor.spotlight_status = row.spotlight_status
                survivor.closed_timestamp = None
            survivor.is_cisa_kev = bool(survivor.is_cisa_kev or row.is_cisa_kev)
            if (row.cve_base_score or 0) > (survivor.cve_base_score or 0):
                survivor.cve_base_score = row.cve_base_score
            if row.elevation_id is None:
                db.session.delete(row)
                removed += 1
        survivor.product_name_version = ", ".join(products)[:500] or None
        survivor.remediation_ids = ", ".join(sorted(rem_ids))[:2000] or None
    return removed


def dedupe_and_prune(severities=DEFAULT_SEVERITIES):
    """Startup cleanup. Idempotent: a clean queue costs two cheap queries."""
    pruned = prune_below_severity(severities)
    merged = merge_duplicates()
    if pruned or merged:
        db.session.commit()
        log.warning("Spotlight queue cleanup: removed %s finding(s) below %s and "
                    "merged away %s duplicate row(s).", pruned, "/".join(severities), merged)
    return pruned, merged


def delete_findings(findings, user, reason=None):
    """Delete findings as noise and remember them. Returns (deleted, skipped).

    Findings attached to a risk are skipped: they are evidence for that risk.
    """
    deleted, skipped = [], []
    for f in findings:
        if f.elevation_id:
            skipped.append(f)
            continue
        if f.aid and f.cve_id:
            mark = SpotlightDeletion.query.filter_by(aid=f.aid, cve_id=f.cve_id).first()
            if mark is None:
                mark = SpotlightDeletion(aid=f.aid, cve_id=f.cve_id)
                db.session.add(mark)
            mark.hostname = f.hostname
            mark.cve_severity = f.cve_severity
            mark.product_name_version = f.product_name_version
            mark.reason = reason or None
            mark.deleted_at = _utcnow()
            mark.deleted_by_id = user.id if user else None
            mark.closed_seen_at = None
        db.session.delete(f)
        deleted.append(f)
    if deleted:
        log.warning("Spotlight: %s deleted %s finding(s) as noise%s.",
                    getattr(user, "username", None) or getattr(user, "email", "?"),
                    len(deleted), f" ({reason})" if reason else "")
    return deleted, skipped


def restore_deletion(deletion):
    """Forget a deletion. The finding returns on the next sync if still open."""
    db.session.delete(deletion)
