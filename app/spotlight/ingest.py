"""Normalize Falcon Spotlight records into the staging tables.

The contract here is narrow and worth stating plainly:

  * One row per host per CVE. Spotlight issues a separate record for each
    affected product (Chrome and Edge both vulnerable to one Chromium CVE is
    two records), so records are keyed on (aid, CVE), not on Spotlight's
    record id. Every affected product is listed on that one row. Re-running
    the sync updates the row; it never creates a second copy.

  * Only the severities in SPOTLIGHT_SEVERITIES (default Critical and High)
    are stored. This is enforced here on every record, not left to the FQL
    filter, so a broad filter cannot flood the queue.

  * A host+CVE an operator deleted stays out of the queue while Spotlight
    keeps reporting it open. If Spotlight stops reporting it and it later
    comes back, that is a reopen, and it returns as New. See
    SpotlightDeletion.

  * A finding Spotlight stops reporting is marked closed here, dated the
    night it disappeared. The default filter fetches only open findings, so
    a patched CVE does not come back as "closed" -- it just stops coming
    back. Absence is only trusted from a sync that can prove it: one that
    used the configured filter, finished every page, and returned at least
    one record. A record Spotlight returns as closed is marked closed too.
    Either way the row is **not deleted**, because a closed finding that was once elevated
    into a risk is evidence, and deleting evidence to tidy a queue is how
    you lose the ability to answer a question later.

  * Our triage state (`ingest_state`) is never overwritten by a sync. If an
    operator dismissed a finding last week, tonight's pull does not quietly
    move it back to New.

  * A record that fails to parse increments a counter and is skipped. One
    malformed row does not abort a 30,000-record sync, and the run record
    reports how many were skipped rather than reporting success.
"""

import json
import logging
from datetime import datetime, timezone

from ..models import db
from ..models_spotlight import (
    INGEST_NEW,
    SpotlightDeletion,
    SpotlightFinding,
    SpotlightHost,
    SpotlightSyncRun,
)
from .client import FalconSpotlightClient, SpotlightError, parse_ts

log = logging.getLogger(__name__)

COMMIT_EVERY = 500  # rows between commits -- bounded memory, bounded rollback
OPEN = ("open", "reopen")
DEFAULT_SEVERITIES = ("CRITICAL", "HIGH")


def record_key(record):
    """(aid, CVE) for a raw record: the identity of a queue row."""
    cve = (record.get("cve") or {}).get("id") or record.get("cve_id")
    return record.get("aid"), cve


def record_severity(record):
    return ((record.get("cve") or {}).get("severity") or "").strip().upper()


def _utcnow():
    return datetime.now(timezone.utc)


def _join(values, limit=2000):
    """Comma-join a list of scalars or {'name': ...} dicts, truncated."""
    if not values:
        return None
    out = []
    for item in values:
        if isinstance(item, dict):
            item = item.get("name") or item.get("id") or ""
        text = str(item).strip()
        if text:
            out.append(text)
    if not out:
        return None
    joined = ", ".join(out)
    return joined[:limit]


def client_from_config(config):
    return FalconSpotlightClient(
        client_id=config.get("FALCON_CLIENT_ID"),
        client_secret=config.get("FALCON_CLIENT_SECRET"),
        region=config.get("FALCON_CLOUD_REGION", "us-1"),
        base_url=config.get("FALCON_BASE_URL") or None,
        timeout=int(config.get("FALCON_HTTP_TIMEOUT", 60)),
    )


# -- host ---------------------------------------------------------------------
def upsert_host(record):
    """Create or refresh the SpotlightHost for one API record.

    Returns (host, created). Falls back to a host row keyed on aid alone when
    the host_info facet is missing, so a finding is never orphaned.
    """
    aid = record.get("aid")
    if not aid:
        return None, False

    info = record.get("host_info") or {}
    host = SpotlightHost.query.filter_by(aid=aid).first()
    created = False
    if not host:
        host = SpotlightHost(aid=aid)
        db.session.add(host)
        created = True

    host.hostname = info.get("hostname") or host.hostname
    host.local_ip = info.get("local_ip") or host.local_ip
    host.machine_domain = info.get("machine_domain") or host.machine_domain
    host.os_version = info.get("os_version") or host.os_version
    host.platform = info.get("platform") or info.get("platform_name") or host.platform
    host.product_type_desc = info.get("product_type_desc") or host.product_type_desc
    host.site_name = info.get("site_name") or host.site_name
    host.ou = _join(info.get("ou")) if isinstance(info.get("ou"), list) else (
        info.get("ou") or host.ou)
    host.system_manufacturer = info.get("system_manufacturer") or host.system_manufacturer
    host.service_provider = info.get("service_provider") or host.service_provider
    host.instance_id = info.get("instance_id") or host.instance_id
    host.asset_criticality = info.get("asset_criticality") or host.asset_criticality
    host.internet_exposure = info.get("internet_exposure") or host.internet_exposure
    host.host_groups = _join(info.get("groups")) or host.host_groups
    host.tags = _join(info.get("tags")) or host.tags

    first_seen = parse_ts(info.get("first_seen_timestamp"))
    if first_seen and (not host.first_seen or first_seen < host.first_seen):
        host.first_seen = first_seen
    last_seen = parse_ts(info.get("last_seen_timestamp"))
    if last_seen:
        host.last_seen = last_seen
    host.last_synced_at = _utcnow()

    return host, created


# -- finding ------------------------------------------------------------------
def upsert_finding(record, host, run_seen=None):
    """Create or refresh the SpotlightFinding for this record's host+CVE.

    Returns (finding, action) where action is 'created', 'updated',
    'closed' -- the row was already here and this sync is what flipped it
    out of an open state -- or 'merged': another record for a host+CVE this
    run already touched, folded into that row.

    run_seen, when given, is a dict shared across one sync run. It lets
    several records for the same host+CVE (one per affected product) build
    up one row: the first record in a run resets the product list, later
    ones add to it, and the row is open if any of its records is open.
    Without it, each call stands alone.
    """
    spotlight_id = record.get("id")
    if not spotlight_id:
        raise ValueError("record has no id")
    aid, cve_key = record_key(record)

    cve = record.get("cve") or {}
    suppression = record.get("suppression_info") or {}
    apps = record.get("apps") or []
    remediation = record.get("remediation") or {}
    rem_entities = remediation.get("entities") or []

    finding = None
    if aid and cve_key:
        finding = SpotlightFinding.query.filter_by(aid=aid, cve_id=cve_key).first()
    if finding is None:
        finding = SpotlightFinding.query.filter_by(spotlight_id=spotlight_id).first()
    action = "updated"
    if not finding:
        finding = SpotlightFinding(
            spotlight_id=spotlight_id,
            ingest_state=INGEST_NEW,
            first_ingested_at=_utcnow(),
            ingest_count=0,
        )
        db.session.add(finding)
        action = "created"

    was_open = finding.is_open if action == "updated" else False

    finding.aid = record.get("aid") or finding.aid
    finding.host_id = host.id if host else finding.host_id
    finding.hostname = (
        (record.get("host_info") or {}).get("hostname")
        or (host.hostname if host else None)
        or finding.hostname
    )

    finding.cve_id = cve.get("id") or record.get("cve_id") or finding.cve_id
    finding.cve_severity = cve.get("severity") or finding.cve_severity
    base_score = cve.get("base_score")
    finding.cve_base_score = float(base_score) if base_score is not None else finding.cve_base_score
    finding.cve_vector = (cve.get("vector") or finding.cve_vector or "")[:255] or None
    finding.cve_description = cve.get("description") or finding.cve_description
    finding.cve_published_date = parse_ts(cve.get("published_date")) or finding.cve_published_date

    finding.exprt_rating = cve.get("exprt_rating") or finding.exprt_rating
    exploit_status = cve.get("exploit_status")
    if exploit_status is not None:
        try:
            finding.exploit_status = int(exploit_status)
        except (TypeError, ValueError):
            pass
    finding.remediation_level = cve.get("remediation_level") or finding.remediation_level

    cisa = cve.get("cisa_info") or {}
    finding.is_cisa_kev = bool(cisa.get("is_cisa_kev", finding.is_cisa_kev))
    due = parse_ts(cisa.get("due_date"))
    finding.cisa_due_date = due.date() if due else finding.cisa_due_date

    # apps[] is the affected software. Several entries can share one CVE on
    # one host, within one record and across records; list them all.
    products = [a.get("product_name_version") for a in apps if a.get("product_name_version")]
    rem_ids = []
    for app in apps:
        rem_ids.extend(((app.get("remediation") or {}).get("ids")) or [])

    key = (aid, cve_key) if aid and cve_key else ("id", spotlight_id)
    group = None
    if run_seen is not None:
        group = run_seen.get(key)
        if group is None:
            group = run_seen[key] = {"products": [], "rem_ids": set(), "statuses": set(),
                                     "first": True}
        else:
            group["first"] = False
        for p in products:
            if p not in group["products"]:
                group["products"].append(p)
        group["rem_ids"].update(rem_ids)
        group["statuses"].add(record.get("status"))
        products, rem_ids = group["products"], group["rem_ids"]

    if products:
        finding.product_name_version = _join(products, limit=500)
    if rem_ids:
        finding.remediation_ids = _join(sorted(set(rem_ids)))
    if rem_entities:
        finding.remediation_title = _join([e.get("title") for e in rem_entities])
        finding.remediation_action = _join([e.get("action") for e in rem_entities], limit=4000)
        finding.remediation_link = _join([e.get("link") for e in rem_entities])

    status = record.get("status") or finding.spotlight_status
    if group is not None:
        open_statuses = [s for s in group["statuses"] if s in OPEN]
        if open_statuses:
            status = "reopen" if "reopen" in open_statuses else "open"
    finding.spotlight_status = status
    finding.is_suppressed = bool(suppression.get("is_suppressed", finding.is_suppressed))
    finding.suppression_reason = suppression.get("reason") or finding.suppression_reason

    # Earliest record wins: the host has been exposed since the first one.
    created = parse_ts(record.get("created_timestamp"))
    if created and (not finding.created_timestamp or created < finding.created_timestamp):
        finding.created_timestamp = created
    finding.updated_timestamp = parse_ts(record.get("updated_timestamp")) or finding.updated_timestamp
    if finding.is_open:
        finding.closed_timestamp = None   # an open row has no close date
    else:
        finding.closed_timestamp = parse_ts(record.get("closed_timestamp")) or finding.closed_timestamp

    finding.last_ingested_at = _utcnow()
    if group is None or group["first"]:
        finding.ingest_count = (finding.ingest_count or 0) + 1
    try:
        finding.raw_payload = json.dumps(record)[:200000]
    except (TypeError, ValueError):
        finding.raw_payload = None

    # NOTE: ingest_state is intentionally NOT written here. Triage decisions
    # belong to people, and a sync must not undo them.

    if group is not None and not group["first"]:
        return finding, "merged"
    if action == "updated" and was_open and not finding.is_open:
        action = "closed"
    return finding, action


# -- orchestration ------------------------------------------------------------
def run_sync(app, trigger="scheduled", user_id=None, fql_filter=None, max_pages=500):
    """Pull Spotlight into the staging tables. Returns the SpotlightSyncRun.

    Every exit path leaves a completed run record behind -- success or
    failure. A sync that dies silently and leaves yesterday's numbers on the
    dashboard is worse than no sync at all, because it looks like it worked.
    """
    config = app.config
    fql = fql_filter or config.get("SPOTLIGHT_FQL_FILTER")

    run = SpotlightSyncRun(
        trigger=trigger, status="running", fql_filter=fql, run_by_id=user_id,
        started_at=_utcnow(),
    )
    db.session.add(run)
    db.session.commit()

    severities = tuple(config.get("SPOTLIGHT_SEVERITIES") or DEFAULT_SEVERITIES)
    deletions = {(d.aid, d.cve_id): d for d in SpotlightDeletion.query.all()}
    run_seen = {}
    open_keys = set()
    below_severity = still_deleted = 0

    try:
        client = client_from_config(config)
        pending = 0

        for page, resources in client.iter_vulnerabilities(
            fql, limit=int(config.get("SPOTLIGHT_PAGE_SIZE", 400)), max_pages=max_pages
        ):
            run.pages_fetched = page
            for record in resources:
                run.records_fetched += 1
                try:
                    if record_severity(record) not in severities:
                        below_severity += 1
                        continue
                    key = record_key(record)
                    is_open = record.get("status") in OPEN
                    if is_open:
                        open_keys.add(key)
                    deletion = deletions.get(key)
                    if deletion is not None:
                        if not is_open:
                            deletion.closed_seen_at = deletion.closed_seen_at or _utcnow()
                            continue
                        if deletion.closed_seen_at is None:
                            still_deleted += 1      # deleted, still open: stays gone
                            continue
                        # It closed after the deletion and is back: a reopen.
                        log.info("Spotlight %s on %s reopened after deletion; "
                                 "returning it to the queue.", key[1], key[0])
                        db.session.delete(deletion)
                        deletions.pop(key)

                    host, host_created = upsert_host(record)
                    if host_created:
                        run.hosts_created += 1
                    if host is not None and host.id is None:
                        db.session.flush()  # need host.id for the finding FK

                    _finding, action = upsert_finding(record, host, run_seen)
                    if action == "created":
                        run.findings_created += 1
                    elif action == "closed":
                        run.findings_closed += 1
                    elif action == "updated":
                        run.findings_updated += 1
                    # "merged": a second record for a row this run already
                    # counted; counting it again would overstate the work.
                except Exception as exc:  # noqa: BLE001 -- one bad row, not the run
                    run.parse_errors += 1
                    log.warning("Skipped Spotlight record %s: %s",
                                record.get("id", "<no id>"), exc)

                pending += 1
                if pending >= COMMIT_EVERY:
                    db.session.commit()
                    pending = 0

            db.session.commit()
            pending = 0
            log.info("Spotlight sync page %s: %s records so far", page, run.records_fetched)

        # Closure by absence. The filter fetches open findings only, so a
        # patched CVE is not reported closed; it stops being reported. That
        # absence is evidence only from a run that could have seen it: the
        # configured filter (not a one-off manual one), every page fetched
        # (not truncated), and at least one record (an empty response is a
        # hiccup or a broken filter, not proof that everything was fixed).
        trustworthy = (fql_filter is None
                       and run.pages_fetched < max_pages
                       and run.records_fetched > 0)
        if trustworthy:
            now = _utcnow()
            for key, deletion in deletions.items():
                if key not in open_keys and deletion.closed_seen_at is None:
                    deletion.closed_seen_at = now
            for finding in SpotlightFinding.query.filter(
                    SpotlightFinding.spotlight_status.in_(OPEN)):
                if (finding.aid, finding.cve_id) not in open_keys:
                    finding.spotlight_status = "closed"
                    finding.closed_timestamp = now
                    run.findings_closed += 1
        else:
            log.info("Spotlight sync: closure by absence skipped (%s).",
                     "manual filter" if fql_filter is not None else
                     "run hit the page limit" if run.pages_fetched >= max_pages else
                     "no records returned")

        run.status = "success"
        run.finished_at = _utcnow()
        db.session.commit()

        # Push closures onto findings already copied into risks, so a
        # patched CVE shows Remediated on its risk without anyone clicking
        # Reconcile. Only ever flips Open -> Remediated; see elevate.py.
        from .elevate import sync_elevated_statuses
        remediated = sync_elevated_statuses()
        if remediated:
            log.info("Spotlight sync: %s elevated finding(s) marked Remediated.", remediated)

        log.info(
            "Spotlight sync complete: %s fetched, %s new, %s updated, %s closed, "
            "%s skipped (unparseable), %s below %s, %s still deleted",
            run.records_fetched, run.findings_created, run.findings_updated,
            run.findings_closed, run.parse_errors, below_severity,
            "/".join(severities), still_deleted,
        )

    except SpotlightError as exc:
        db.session.rollback()
        run = db.session.get(SpotlightSyncRun, run.id)
        run.status = "failed"
        run.error_message = str(exc)[:2000]
        run.finished_at = _utcnow()
        db.session.commit()
        log.error("Spotlight sync failed: %s", exc)

    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        run = db.session.get(SpotlightSyncRun, run.id)
        run.status = "failed"
        run.error_message = f"Unexpected error: {exc}"[:2000]
        run.finished_at = _utcnow()
        db.session.commit()
        log.exception("Spotlight sync failed unexpectedly")

    return run


def run_sync_job(app):
    """APScheduler entry point -- needs its own app context."""
    with app.app_context():
        run_sync(app, trigger="scheduled")
