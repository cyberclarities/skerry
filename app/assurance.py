"""What needs attention in the register, worked out in one place.

The dashboard's Needs attention panel, the Control Assurance and Reviews
Due reports, the daily snapshot, and the review-due emails all read these
rules from here, so they cannot drift apart.

Every rule works on active risks: anything not Closed. Accepted risks are
active; accepting a risk does not make it go away.
"""
from datetime import date, timedelta

from app import scoring

# Days between reviews, by the risk's review frequency. A month is 30 days
# and a quarter 90, so a date is the same whichever page computes it.
REVIEW_INTERVAL_DAYS = {"Monthly": 30, "Quarterly": 90, "Annually": 365}

# A passed control test older than this no longer counts as assurance.
STALE_TEST_DAYS = 365

# How far ahead "acceptances due" looks.
ACCEPTANCE_WINDOW_DAYS = 30

# Control assurance states. Only "Tested" is assurance; the rest are claims.
FAILED, NEVER_TESTED, NO_RESULT, STALE, TESTED = (
    "Failed", "Never tested", "No result recorded", "Stale", "Tested")
UNPROVEN = (FAILED, NEVER_TESTED, NO_RESULT, STALE)


def is_active(risk):
    return risk.status != "Closed"


def is_accepted(risk):
    return risk.status == "Accepted" or risk.treatment == "Accept"


# ── Reviews ──────────────────────────────────────────────────────────────
def next_review_date(risk):
    """When the risk is next due for review, or None with no frequency set.

    Counted from the latest review on record: the last review, or the
    acceptance sign-off, which is itself a review. A risk never reviewed
    counts from the day it was identified, so it is not silently exempt.
    """
    days = REVIEW_INTERVAL_DAYS.get(risk.review_frequency or "")
    if not days:
        return None
    signed = getattr(risk, "acceptance_sign_off_date", None)
    reviewed = [d for d in (risk.last_reviewed, signed) if d]
    anchor = max(reviewed) if reviewed else risk.date_identified
    if not anchor:
        return None
    return anchor + timedelta(days=days)


def review_due(risk, today, lead_days=7):
    """True within lead_days of the next review, or past it (the emails)."""
    due = next_review_date(risk)
    return due is not None and today >= due - timedelta(days=lead_days)


def reviews_past_due(risks, today):
    """[(risk, due date, days past due)], most overdue first."""
    rows = []
    for r in risks:
        due = next_review_date(r)
        if is_active(r) and due and due < today:
            rows.append((r, due, (today - due).days))
    rows.sort(key=lambda row: row[2], reverse=True)
    return rows


def acceptances_due(risks, today, window_days=ACCEPTANCE_WINDOW_DAYS):
    """Accepted risks due for another look: [(risk, due date or None, note)].

    Included when the next review is past or within the window, or when
    there is no review frequency at all: an acceptance with no review date
    never expires on its own.
    """
    rows = []
    horizon = today + timedelta(days=window_days)
    for r in risks:
        if not (is_active(r) and is_accepted(r)):
            continue
        due = next_review_date(r)
        if due is None:
            rows.append((r, None, "No review frequency set"))
        elif due < today:
            rows.append((r, due, f"Past due by {(today - due).days} days"))
        elif due <= horizon:
            rows.append((r, due, f"Due in {(due - today).days} days"))
    rows.sort(key=lambda row: (row[1] is not None, row[1] or date.min))
    return rows


# ── Controls ─────────────────────────────────────────────────────────────
def control_assurance(risk, today):
    """How well the controls behind the risk's residual score are proven.

    None when the risk claims no control effectiveness, since then nothing
    leans on controls. Otherwise one of: Failed, Never tested, No result
    recorded, Stale (a pass older than a year), or Tested.
    """
    if not risk.control_effectiveness:
        return None
    result = (risk.control_test_result or "").strip()
    if result == "Fail":
        return FAILED
    if not risk.last_control_test_date or result in ("", "Not Tested"):
        return NEVER_TESTED if result in ("", "Not Tested") else NO_RESULT
    if (today - risk.last_control_test_date).days > STALE_TEST_DAYS:
        return STALE
    if result != "Pass":
        return NO_RESULT
    return TESTED


def inherent_rag(risk, red_threshold, amber_threshold):
    """The RAG rating before controls, from likelihood x impact."""
    return scoring.rag_status(risk.inherent_risk_score, red_threshold, amber_threshold)


def unproven_controls(risks, today, red_threshold, amber_threshold):
    """Active risks whose residual score leans on controls not proven.

    [dict(risk, status, inherent_rag, reduction)], worst first: highest
    score before controls, then the largest reduction the controls claim.
    """
    rows = []
    for r in risks:
        status = control_assurance(r, today)
        if not is_active(r) or status not in UNPROVEN:
            continue
        inherent = r.inherent_risk_score
        residual = r.residual_risk_score
        rows.append(dict(
            risk=r,
            status=status,
            inherent_rag=inherent_rag(r, red_threshold, amber_threshold),
            reduction=round(inherent - residual, 1) if inherent is not None and residual is not None else None,
        ))
    rows.sort(key=lambda row: (row["risk"].inherent_risk_score or 0, row["reduction"] or 0),
              reverse=True)
    return rows


# ── Spotlight ────────────────────────────────────────────────────────────
def kev_past_due_query(today):
    """Open, unsuppressed Spotlight findings in the CISA KEV catalog whose
    CISA due date has passed, whatever their triage state."""
    from app.models_spotlight import SpotlightFinding
    return SpotlightFinding.query.filter(
        SpotlightFinding.spotlight_status.in_(("open", "reopen")),
        SpotlightFinding.is_suppressed.is_(False),
        SpotlightFinding.is_cisa_kev.is_(True),
        SpotlightFinding.cisa_due_date < today,
    )


# ── The panel ────────────────────────────────────────────────────────────
def needs_attention(risks, today, red_threshold, amber_threshold):
    """Counts for the dashboard panel and the daily snapshot."""
    active = [r for r in risks if is_active(r)]
    unproven = unproven_controls(active, today, red_threshold, amber_threshold)
    return dict(
        overdue_actions=sum(1 for r in active if r.is_overdue),
        reviews_past_due=len(reviews_past_due(active, today)),
        acceptances_due=len(acceptances_due(active, today)),
        unproven_controls=len(unproven),
        unproven_on_red=sum(1 for row in unproven if row["inherent_rag"] == "RED"),
        kev_past_due=kev_past_due_query(today).count(),
    )
