from datetime import date, datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=True, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False, default="viewer")  # viewer|operator|admin
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    oidc_sub = db.Column(db.String(255), unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)

    risks_created = db.relationship("Risk", backref="created_by", lazy="dynamic",
                                    foreign_keys="Risk.created_by_id")
    audit_entries = db.relationship("AuditLog", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_operator(self):
        return self.role in ("operator", "admin")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


class Risk(db.Model):
    __tablename__ = "risks"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.String(20), unique=True, nullable=False, index=True)

    # ── Core Identification ──────────────────────────────────────────────────
    risk_category = db.Column(db.String(100))
    asset_system = db.Column(db.String(255))
    business_process = db.Column(db.Text)
    threat_description = db.Column(db.Text)
    vulnerability_detail = db.Column(db.Text)

    # ── Threat Intelligence ──────────────────────────────────────────────────
    threat_actor_type = db.Column(db.String(100))
    attack_vector = db.Column(db.String(100))
    threat_intel_source = db.Column(db.String(255))

    # ── Risk Scoring (inputs) ────────────────────────────────────────────────
    likelihood = db.Column(db.Integer)   # 1-5
    impact = db.Column(db.Integer)       # 1-5

    # ── Controls & Assurance ─────────────────────────────────────────────────
    existing_controls = db.Column(db.Text)
    control_type = db.Column(db.String(100))      # Preventive|Detective|Corrective|Compensating
    control_effectiveness = db.Column(db.Integer)  # 1-5
    last_control_test_date = db.Column(db.Date)
    control_test_result = db.Column(db.String(50))  # Pass|Fail|Not Tested
    assurance_source = db.Column(db.String(100))

    # ── Velocity & Detection ─────────────────────────────────────────────────
    risk_velocity = db.Column(db.String(50))        # Rapid|Moderate|Slow
    detection_capability = db.Column(db.String(50)) # Full|Partial|Minimal|None

    # ── Governance & Appetite ────────────────────────────────────────────────
    risk_owner = db.Column(db.String(255))
    escalation_path = db.Column(db.String(255))
    acceptance_sign_off_by = db.Column(db.String(255))
    acceptance_sign_off_date = db.Column(db.Date)

    # ── Financial & Business Impact ──────────────────────────────────────────
    min_financial_exposure = db.Column(db.Float)
    max_financial_exposure = db.Column(db.Float)
    regulatory_obligation = db.Column(db.Text)
    related_incident_ref = db.Column(db.String(255))

    # ── Treatment & Actions ──────────────────────────────────────────────────
    treatment = db.Column(db.String(50))        # Mitigate|Accept|Transfer|Avoid
    remediation_action = db.Column(db.Text)
    action_owner = db.Column(db.String(255))
    due_date = db.Column(db.Date)
    status = db.Column(db.String(50), default="Open")  # Open|In Progress|Closed|Accepted

    # ── Operational Metadata ─────────────────────────────────────────────────
    date_identified = db.Column(db.Date, default=date.today)
    last_reviewed = db.Column(db.Date)
    review_frequency = db.Column(db.String(50))  # Monthly|Quarterly|Annually
    board_reporting_flag = db.Column(db.Boolean, default=False)
    evidence_links = db.Column(db.Text)
    notes_history = db.Column(db.Text)

    # ── NIST CSF 2.0 Mapping ─────────────────────────────────────────────────
    nist_csf_function = db.Column(db.String(10))
    nist_csf_category = db.Column(db.String(20))
    nist_csf_subcategory = db.Column(db.String(20))

    # ── Record metadata ──────────────────────────────────────────────────────
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    trend_entries = db.relationship("TrendLog", backref="risk", lazy="dynamic",
                                    cascade="all, delete-orphan",
                                    order_by="TrendLog.review_date")
    audit_log = db.relationship("AuditLog", backref="risk", lazy="dynamic",
                                cascade="all, delete-orphan",
                                order_by="AuditLog.timestamp.desc()")

    # ── Computed properties ──────────────────────────────────────────────────
    @property
    def inherent_risk_score(self):
        if self.likelihood and self.impact:
            return self.likelihood * self.impact
        return None

    @property
    def residual_risk_score(self):
        inherent = self.inherent_risk_score
        if inherent is None:
            return None
        if not self.control_effectiveness:
            return float(inherent)
        reductions = {1: 0.10, 2: 0.25, 3: 0.35, 4: 0.50, 5: 0.65}
        reduction = reductions.get(self.control_effectiveness, 0)
        return round(inherent * (1 - reduction), 1)

    @property
    def rag_status(self):
        from flask import current_app
        score = self.residual_risk_score
        if score is None:
            return "UNKNOWN"
        red = current_app.config.get("RAG_RED_THRESHOLD", 15)
        amber = current_app.config.get("RAG_AMBER_THRESHOLD", 9)
        if score >= red:
            return "RED"
        elif score >= amber:
            return "AMBER"
        return "GREEN"

    @property
    def exceeds_risk_appetite(self):
        from flask import current_app
        score = self.residual_risk_score
        if score is None:
            return False
        threshold = current_app.config.get("RISK_APPETITE_THRESHOLD", 8)
        return score > threshold

    @property
    def age_days(self):
        if self.date_identified:
            return (date.today() - self.date_identified).days
        return None

    @property
    def is_overdue(self):
        if self.due_date and self.status not in ("Closed", "Accepted"):
            return date.today() > self.due_date
        return False

    @property
    def days_overdue(self):
        if self.is_overdue:
            return (date.today() - self.due_date).days
        return None

    def __repr__(self):
        return f"<Risk {self.risk_id}>"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("risks.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(50), nullable=False)   # created|updated|deleted
    field_name = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class TrendLog(db.Model):
    __tablename__ = "trend_log"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("risks.id"), nullable=False)
    review_date = db.Column(db.Date, nullable=False, default=date.today)
    residual_score = db.Column(db.Float)
    rag_status = db.Column(db.String(10))
    change_vs_prior = db.Column(db.Float)
    reviewer = db.Column(db.String(255))
    control_test_result = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class LookupItem(db.Model):
    """Configurable dropdown values managed from the Settings page."""
    __tablename__ = "lookup_items"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("category", "value", name="uq_lookup_category_value"),
    )

    def __repr__(self):
        return f"<LookupItem {self.category}: {self.value}>"


class NISTCSFReference(db.Model):
    __tablename__ = "nist_csf_reference"

    id = db.Column(db.Integer, primary_key=True)
    function_code = db.Column(db.String(10), index=True)
    function_name = db.Column(db.String(100))
    category_code = db.Column(db.String(20), index=True)
    category_name = db.Column(db.String(255))
    subcategory_code = db.Column(db.String(20), unique=True)
    description = db.Column(db.Text)

    def __repr__(self):
        return f"<NIST {self.subcategory_code}>"
