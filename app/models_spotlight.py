"""CrowdStrike Spotlight ingest models.

These tables are additive. Nothing in this module changes `users`, `risks`,
`audit_log`, `trend_log`, `vulnerability_findings`, `lookup_items`, or
`nist_csf_reference` -- `db.create_all()` creates new tables and leaves
existing ones alone, so an existing risk_register.db picks these up on the
next boot without a migration step and without touching a single stored row.

Two deliberate constraints follow from that:

1. **No foreign key constraints pointing at `risks` or
   `vulnerability_findings`.** `risk_id` and `vuln_finding_id` are plain
   indexed integers. A real FK would make the existing admin "delete risk"
   route fail (or silently cascade) once the database enforces constraints,
   and the whole point here is that the current app keeps working exactly as
   it does today. The trade is that referential integrity is the
   application's job -- see `SpotlightElevation.risk` for how the link is
   resolved, and `elevate.py` for how a deleted risk is handled.

2. **The staging tables are the system of record for provenance.** When a
   finding is elevated, its data is *copied* into a normal
   `VulnerabilityFinding` row so every existing export, Decision Request,
   and count keeps working untouched. The staging row remembers what it
   became.
"""

from datetime import date, datetime, timezone

from .models import db


def _utcnow():
    return datetime.now(timezone.utc)


# -- Workflow states ---------------------------------------------------------
# Spotlight has its own status (open / closed / reopen / expired). That is the
# scanner's opinion and we store it verbatim in `spotlight_status`. These
# states are *ours* -- where the finding sits in our triage queue.
INGEST_NEW = "New"
INGEST_TRIAGED = "Triaged"
INGEST_ELEVATED = "Elevated"
INGEST_DISMISSED = "Dismissed"
INGEST_STATES = [INGEST_NEW, INGEST_TRIAGED, INGEST_ELEVATED, INGEST_DISMISSED]


class SpotlightHost(db.Model):
    """One asset, keyed on the CrowdStrike agent ID (aid).

    Hostnames get reused and renamed; the aid does not. Everything joins on
    aid, and hostname is carried along for humans to read.
    """

    __tablename__ = "spotlight_hosts"

    id = db.Column(db.Integer, primary_key=True)
    aid = db.Column(db.String(64), unique=True, nullable=False, index=True)

    hostname = db.Column(db.String(255), index=True)
    local_ip = db.Column(db.String(64))
    machine_domain = db.Column(db.String(255))
    os_version = db.Column(db.String(255))
    platform = db.Column(db.String(50))            # Windows | Mac | Linux
    product_type_desc = db.Column(db.String(50))   # Workstation | Server | Domain Controller
    site_name = db.Column(db.String(255))
    ou = db.Column(db.String(255))
    system_manufacturer = db.Column(db.String(255))
    service_provider = db.Column(db.String(100))   # AWS_EC2_V2 etc. -- blank for on-prem
    instance_id = db.Column(db.String(255))

    # Falcon asset context. These drive triage priority more than CVSS does.
    asset_criticality = db.Column(db.String(50))
    internet_exposure = db.Column(db.String(50))   # Yes | No | Unknown
    host_groups = db.Column(db.Text)               # comma-joined group names
    tags = db.Column(db.Text)                      # comma-joined Falcon tags

    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    last_synced_at = db.Column(db.DateTime, default=_utcnow)
    created_at = db.Column(db.DateTime, default=_utcnow)

    findings = db.relationship(
        "SpotlightFinding",
        backref="host",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @property
    def display_name(self):
        return self.hostname or self.aid

    @property
    def open_findings(self):
        return self.findings.filter(
            SpotlightFinding.spotlight_status.in_(("open", "reopen"))
        )

    def __repr__(self):
        return f"<SpotlightHost {self.display_name}>"


class SpotlightFinding(db.Model):
    """One Spotlight vulnerability record -- one CVE on one host.

    Keyed on the Spotlight-assigned `spotlight_id`, which is stable across
    scans. Re-ingesting the same finding updates the row rather than adding
    a second one, so the queue never grows a duplicate on a nightly pull.
    """

    __tablename__ = "spotlight_findings"

    id = db.Column(db.Integer, primary_key=True)

    # -- Identity / dedupe ---------------------------------------------------
    spotlight_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    aid = db.Column(db.String(64), index=True)
    host_id = db.Column(db.Integer, db.ForeignKey("spotlight_hosts.id"), index=True)
    hostname = db.Column(db.String(255), index=True)  # denormalized on purpose

    # -- CVE detail ----------------------------------------------------------
    cve_id = db.Column(db.String(50), index=True)
    cve_severity = db.Column(db.String(20))        # CRITICAL | HIGH | MEDIUM | LOW | NONE
    cve_base_score = db.Column(db.Float)
    cve_vector = db.Column(db.String(255))
    cve_description = db.Column(db.Text)
    cve_published_date = db.Column(db.DateTime)

    # CrowdStrike's own judgement. ExPRT.AI weighs real-world exploitation,
    # which is a better likelihood input than a raw CVSS base score.
    exprt_rating = db.Column(db.String(20))        # CRITICAL | HIGH | MEDIUM | LOW
    exploit_status = db.Column(db.Integer)         # 0 | 30 | 60 | 90
    remediation_level = db.Column(db.String(10))   # O | T | W | U
    is_cisa_kev = db.Column(db.Boolean, default=False)
    cisa_due_date = db.Column(db.Date)

    # -- Affected software and fix -------------------------------------------
    product_name_version = db.Column(db.String(500))
    remediation_ids = db.Column(db.Text)           # comma-joined
    remediation_title = db.Column(db.Text)
    remediation_action = db.Column(db.Text)
    remediation_link = db.Column(db.Text)

    # -- Spotlight's own lifecycle (scanner opinion, stored verbatim) --------
    spotlight_status = db.Column(db.String(20), index=True)  # open|closed|reopen|expired
    is_suppressed = db.Column(db.Boolean, default=False)
    suppression_reason = db.Column(db.String(255))
    created_timestamp = db.Column(db.DateTime)     # when Spotlight first saw it
    updated_timestamp = db.Column(db.DateTime)
    closed_timestamp = db.Column(db.DateTime)

    # -- Our triage lifecycle ------------------------------------------------
    ingest_state = db.Column(db.String(20), default=INGEST_NEW, index=True)
    triage_note = db.Column(db.Text)
    dismissed_reason = db.Column(db.Text)
    dismissed_at = db.Column(db.DateTime)
    dismissed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # -- Provenance after elevation ------------------------------------------
    # Plain integers, no FK -- see the module docstring. `elevation_id` is a
    # real FK because spotlight_elevations is one of our own new tables.
    elevation_id = db.Column(db.Integer, db.ForeignKey("spotlight_elevations.id"), index=True)
    risk_id = db.Column(db.Integer, index=True)          # -> risks.id, app-enforced
    vuln_finding_id = db.Column(db.Integer, index=True)  # -> vulnerability_findings.id

    # -- Ingest bookkeeping --------------------------------------------------
    first_ingested_at = db.Column(db.DateTime, default=_utcnow)
    last_ingested_at = db.Column(db.DateTime, default=_utcnow, index=True)
    ingest_count = db.Column(db.Integer, default=1)
    raw_payload = db.Column(db.Text)  # the API record as returned, for audit

    __table_args__ = (
        db.Index("ix_spotlight_findings_queue", "ingest_state", "spotlight_status"),
        db.Index("ix_spotlight_findings_host_cve", "aid", "cve_id"),
    )

    # -- Derived -------------------------------------------------------------
    @property
    def is_open(self):
        return self.spotlight_status in ("open", "reopen")

    @property
    def days_open(self):
        """Age as of today, computed from Spotlight's created_timestamp.

        Never stored -- a stored age is wrong the morning after you write it.
        """
        if not self.created_timestamp:
            return None
        found = self.created_timestamp.date()
        end = self.closed_timestamp.date() if self.closed_timestamp else date.today()
        return (end - found).days

    @property
    def date_found(self):
        return self.created_timestamp.date() if self.created_timestamp else None

    @property
    def severity_title(self):
        """Spotlight returns CRITICAL; the register stores Critical."""
        return (self.cve_severity or "").capitalize() or None

    @property
    def exprt_title(self):
        return (self.exprt_rating or "").capitalize() or None

    @property
    def exploit_status_label(self):
        return {
            0: "Unproven",
            30: "Available",
            60: "Easily accessible",
            90: "Actively used",
        }.get(self.exploit_status, "Unknown")

    def __repr__(self):
        return f"<SpotlightFinding {self.cve_id} on {self.hostname or self.aid}>"


class SpotlightElevation(db.Model):
    """The record of an operator promoting ingest rows into a Risk.

    Scope is host-primary: the normal case is one hostname's open findings
    becoming one risk. A widely-discovered issue can instead be elevated
    across several hosts as a single risk -- that is `scope_type == 'hosts'`,
    with the hosts listed in `scope_hosts`.
    """

    __tablename__ = "spotlight_elevations"

    id = db.Column(db.Integer, primary_key=True)

    risk_id = db.Column(db.Integer, index=True)  # -> risks.id, app-enforced
    risk_ref = db.Column(db.String(20))          # e.g. SKR-014, kept if the risk is deleted

    scope_type = db.Column(db.String(20), default="host")  # host | hosts
    scope_label = db.Column(db.String(500))       # hostname, or "CVE-2024-1234 (7 hosts)"
    scope_hosts = db.Column(db.Text)              # comma-joined hostnames
    scope_aids = db.Column(db.Text)               # comma-joined aids -- the durable key

    host_count = db.Column(db.Integer, default=1)
    finding_count = db.Column(db.Integer, default=0)
    cve_list = db.Column(db.Text)                 # comma-joined CVE ids at elevation time

    # Scores suggested by the mapping vs. what the operator actually saved.
    # Kept so the suggestion logic can be reviewed against real decisions
    # instead of being taken on faith.
    suggested_likelihood = db.Column(db.Integer)
    suggested_impact = db.Column(db.Integer)
    suggestion_rationale = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=_utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    findings = db.relationship("SpotlightFinding", backref="elevation", lazy="dynamic")
    created_by = db.relationship("User", foreign_keys=[created_by_id])

    @property
    def risk(self):
        """Resolve the linked Risk, or None if an admin has since deleted it.

        No FK constraint by design, so this can dangle. Returning None and
        showing `risk_ref` is more honest than pretending the link is intact.
        """
        if not self.risk_id:
            return None
        from .models import Risk
        return db.session.get(Risk, self.risk_id)

    def __repr__(self):
        return f"<SpotlightElevation {self.scope_label} -> {self.risk_ref}>"


class SpotlightSyncRun(db.Model):
    """One pull from the Falcon API -- what was asked for, what came back.

    Exists so "when did we last actually look?" has an answer in the
    database rather than in someone's memory. A failed run is recorded as a
    failed run; it does not quietly leave the last good numbers on screen.
    """

    __tablename__ = "spotlight_sync_runs"

    id = db.Column(db.Integer, primary_key=True)

    trigger = db.Column(db.String(20), default="scheduled")  # scheduled | manual
    status = db.Column(db.String(20), default="running", index=True)  # running|success|failed
    fql_filter = db.Column(db.Text)

    started_at = db.Column(db.DateTime, default=_utcnow, index=True)
    finished_at = db.Column(db.DateTime)

    pages_fetched = db.Column(db.Integer, default=0)
    records_fetched = db.Column(db.Integer, default=0)
    findings_created = db.Column(db.Integer, default=0)
    findings_updated = db.Column(db.Integer, default=0)
    findings_closed = db.Column(db.Integer, default=0)
    hosts_created = db.Column(db.Integer, default=0)
    parse_errors = db.Column(db.Integer, default=0)

    error_message = db.Column(db.Text)
    run_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    run_by = db.relationship("User", foreign_keys=[run_by_id])

    @property
    def duration_seconds(self):
        if not self.finished_at:
            return None
        return round((self.finished_at - self.started_at).total_seconds(), 1)

    def __repr__(self):
        return f"<SpotlightSyncRun {self.started_at:%Y-%m-%d %H:%M} {self.status}>"
