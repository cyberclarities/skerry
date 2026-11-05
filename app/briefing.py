"""The one-page Cyber Risk Briefing, built live from the register.

Written for executives and trustees on the same page, in Smart Brevity
order: a headline with its number, why it matters, four figures with their
change over 30 days, two charts, how we are treating the risks,
how long open vulnerabilities have been on our hosts, what needs attention, the top risks,
and what's next.

Every sentence here is generated from the figures beside it, so the page
never claims more than the data shows: "nothing waiting" appears only when
nothing is. The 30-day comparisons come from the daily snapshot
(app/snapshots.py) and are left off until a snapshot that old exists.

The charts are inline SVG built here, not drawn by a script in the browser,
so the page prints to PDF exactly as it looks on screen.
"""
from datetime import date, datetime, timedelta, timezone

from flask import current_app

from app import assurance
from app.models import RegisterSnapshot, Risk

COMPARE_DAYS = 30
COMPARE_PHRASE = "a month ago"   # how COMPARE_DAYS reads in a sentence
TREND_DAYS = 90
TOP_RISKS = 5

# Colors from the PB-000 template (its theme accents for the ratings). No yellow.
RAG_COLORS = {"RED": "#C00000", "AMBER": "#E97132", "GREEN": "#196B24", "UNKNOWN": "#7F7F7F"}
ZONE_FILLS = {"RED": "#F4CCCC", "AMBER": "#FBE0CF", "GREEN": "#D6E9D8"}


def _s(n, one="", many="s"):
    return one if n == 1 else many


def _delta(now, then, lower_is_better=True):
    """{'text', 'tone'} for a change since the comparison date, or None."""
    if then is None:
        return None
    diff = now - then
    if diff == 0:
        return dict(text=f"no change from {COMPARE_PHRASE}", tone="flat")
    arrow = "▲" if diff > 0 else "▼"
    good = (diff < 0) if lower_is_better is True else (diff > 0) if lower_is_better is False else None
    tone = "flat" if good is None else ("good" if good else "bad")
    return dict(text=f"{arrow} {abs(diff)} from {COMPARE_PHRASE}", tone=tone)


# ── Charts as SVG geometry ───────────────────────────────────────────────
def _trend(snapshots, width=330, height=82, pad_l=24, pad_b=16, pad_t=6, pad_r=6):
    """Polylines for RED / AMBER / GREEN counts per snapshot day."""
    if len(snapshots) < 2:
        return None
    series = {k: [getattr(s, k.lower()) or 0 for s in snapshots] for k in ("RED", "AMBER", "GREEN")}
    top = max(max(v) for v in series.values()) or 1
    top = top + (-top % 5) if top > 5 else 5          # round the axis up to a multiple of 5
    n = len(snapshots)
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    x = lambda i: pad_l + plot_w * i / (n - 1)        # noqa: E731
    y = lambda v: pad_t + plot_h * (1 - v / top)      # noqa: E731
    lines = [dict(color=RAG_COLORS[k], label=k,
                  points=" ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(vals)),
                  last=vals[-1], last_y=y(vals[-1]))
             for k, vals in series.items()]
    grid = [dict(y=y(v), label=v) for v in (0, top // 2, top)]
    return dict(width=width, height=height, lines=lines, grid=grid,
                x0=pad_l, x1=width - pad_r, y_base=height - pad_b,
                first=snapshots[0].snapshot_date.strftime("%b %d"),
                last=snapshots[-1].snapshot_date.strftime("%b %d"))


def _heatmap(active, red_t, amber_t, cell=16, gap=2):
    """5x5 grid: active risk counts by likelihood x impact, shaded by zone."""
    counts = {}
    for r in active:
        if r.likelihood and r.impact:
            counts[(r.likelihood, r.impact)] = counts.get((r.likelihood, r.impact), 0) + 1
    cells = []
    for row, impact in enumerate((5, 4, 3, 2, 1)):
        for col, lik in enumerate((1, 2, 3, 4, 5)):
            score = lik * impact
            zone = "RED" if score >= red_t else "AMBER" if score >= amber_t else "GREEN"
            cells.append(dict(x=14 + col * (cell + gap), y=row * (cell + gap),
                              fill=ZONE_FILLS[zone], n=counts.get((lik, impact), 0)))
    size = 5 * cell + 4 * gap
    return dict(cells=cells, cell=cell, width=14 + size, height=size + 14,
                placed=sum(counts.values()))


TREATMENTS = ("Mitigate", "Accept", "Transfer", "Avoid")
AGE_BANDS = ((0, 30, "0-30"), (31, 60, "31-60"), (61, 90, "61-90"), (91, None, "Over 90"))
ELEVATE_AFTER_DAYS = 60   # matches the CVE review's default age in ingest_routes


def _treatment(active, width=250):
    """Active risks by treatment, each with the one note that matters for it."""
    groups = {}
    for r in active:
        key = (r.treatment or "").strip().title() or "Not set"
        groups.setdefault(key, []).append(r)
    order = list(TREATMENTS) + sorted(k for k in groups if k not in TREATMENTS and k != "Not set") + ["Not set"]
    top = max((len(v) for v in groups.values()), default=0)
    rows = []
    for key in order:
        members = groups.get(key, [])
        if not members and key not in TREATMENTS:
            continue
        n = len(members)
        note, hot = "", False
        if key == "Mitigate":
            late = sum(1 for r in members if r.is_overdue)
            note, hot = (f"{late} past target date", True) if late else ("", False)
        elif key == "Accept":
            unsigned = sum(1 for r in members if not r.acceptance_sign_off_by)
            note, hot = (f"{unsigned} without sign-off", True) if unsigned else ("", False)
        elif key == "Not set" and n:
            note, hot = "needs a decision", True
        rows.append({"label": key, "n": n, "w": width * n / top if top else 0,
                     "note": note, "hot": hot})
    return {"rows": rows, "width": width}


def _vuln_aging(today, width=250, height=64):
    """Open, unsuppressed Spotlight findings by days since first seen on our
    hosts, split Critical and High. Counted in SQL: a tenant can hold far
    more findings than this page should load."""
    from sqlalchemy import case, func

    from app.models_spotlight import SpotlightFinding
    from app.spotlight.ingest import OPEN

    def since(days):   # midnight at the start of the day `days` ago
        return datetime.combine(today - timedelta(days=days), datetime.min.time())

    created = SpotlightFinding.created_timestamp
    whens = []
    for lo, hi, label in AGE_BANDS:   # age in whole days: today minus the day first seen
        cond = created < since(lo - 1) if lo else created.isnot(None)
        if hi is not None:
            cond = cond & (created >= since(hi))
        whens.append((cond, label))
    band = case(*whens, else_="unknown")
    sev = func.upper(SpotlightFinding.cve_severity)
    rows = (SpotlightFinding.query
            .with_entities(band.label("band"), sev.label("sev"), func.count().label("n"))
            .filter(SpotlightFinding.spotlight_status.in_(OPEN),
                    SpotlightFinding.is_suppressed.is_(False),
                    sev.in_(("CRITICAL", "HIGH")))
            .group_by("band", "sev").all())
    counts = {(b, s): n for b, s, n in rows}
    total = sum(counts.values())
    if not total:
        return {"total": 0}

    pad_l, pad_b, pad_t = 4, 14, 10
    slot = (width - pad_l) / len(AGE_BANDS)
    bar_w = slot * 0.56
    peak = max(counts.get((label, "CRITICAL"), 0) + counts.get((label, "HIGH"), 0)
               for _lo, _hi, label in AGE_BANDS) or 1
    plot_h = height - pad_b - pad_t
    bars = []
    for i, (lo, _hi, label) in enumerate(AGE_BANDS):
        crit, high = counts.get((label, "CRITICAL"), 0), counts.get((label, "HIGH"), 0)
        x = pad_l + slot * i + (slot - bar_w) / 2
        h_high, h_crit = plot_h * high / peak, plot_h * crit / peak
        base = height - pad_b
        bars.append({"label": label, "x": x, "w": bar_w, "cx": x + bar_w / 2,
                     "crit": crit, "high": high, "n": crit + high,
                     "y_high": base - h_high, "h_high": h_high,
                     "y_crit": base - h_high - h_crit, "h_crit": h_crit,
                     "past_line": lo > ELEVATE_AFTER_DAYS})
    past = sum(b["n"] for b in bars if b["past_line"])
    # the 60-day line sits between the 31-60 and 61-90 bars
    line_x = pad_l + slot * 2
    return {"total": total, "bars": bars, "width": width, "height": height,
            "base": height - pad_b, "line_x": line_x, "past": past,
            "unknown": counts.get(("unknown", "CRITICAL"), 0) + counts.get(("unknown", "HIGH"), 0),
            "critical": sum(b["crit"] for b in bars), "high": sum(b["high"] for b in bars)}


# ── The page ─────────────────────────────────────────────────────────────
def build_briefing():
    today = date.today()
    red_t = current_app.config.get("RAG_RED_THRESHOLD", 15)
    amber_t = current_app.config.get("RAG_AMBER_THRESHOLD", 9)

    risks = Risk.query.all()
    active = [r for r in risks if assurance.is_active(r)]
    rag = [r.rag_status for r in active]
    red, amber, green = rag.count("RED"), rag.count("AMBER"), rag.count("GREEN")
    att = assurance.needs_attention(risks, today, red_t, amber_t)
    tiles = [
        ("RED on unproven controls", att["unproven_on_red"]),
        ("KEV past CISA due", att["kev_past_due"]),
        ("Overdue actions", att["overdue_actions"]),
        ("Reviews past due", att["reviews_past_due"]),
        ("Acceptances due", att["acceptances_due"]),
    ]
    waiting = sum(n for _l, n in tiles)

    snapshots = (RegisterSnapshot.query
                 .filter(RegisterSnapshot.snapshot_date >= today - timedelta(days=TREND_DAYS))
                 .order_by(RegisterSnapshot.snapshot_date).all())
    base = (RegisterSnapshot.query
            .filter(RegisterSnapshot.snapshot_date <= today - timedelta(days=COMPARE_DAYS))
            .order_by(RegisterSnapshot.snapshot_date.desc()).first())
    first = RegisterSnapshot.query.order_by(RegisterSnapshot.snapshot_date).first()
    base_waiting = (sum((getattr(base, k) or 0) for k in
                        ("unproven_on_red", "kev_past_due", "overdue_actions",
                         "reviews_past_due", "acceptances_due")) if base else None)

    # ── Headline and why it matters ──
    headline = f"{red} of {len(active)} active risk{_s(len(active))} {_s(red, 'is', 'are')} RED after controls"
    if base is not None and base.red is not None and base.red != red:
        headline += f", {'down' if red < base.red else 'up'} from {base.red} {COMPARE_PHRASE}"
    headline += "."

    unproven_all = att["unproven_controls"]
    if not active:
        headline = "No active risks in the register."
        why = "Add risks to the register, and this page fills in from them."
    elif att["unproven_on_red"]:
        n = att["unproven_on_red"]
        why = (f"{n} risk{_s(n)} rated RED before controls {_s(n, 'depends', 'depend')} on controls "
               f"nobody has proven. If those controls fail, our exposure is higher than this page shows.")
    elif att["kev_past_due"]:
        n = att["kev_past_due"]
        why = (f"{n} vulnerabilit{_s(n, 'y', 'ies')} attackers are known to exploit "
               f"{_s(n, 'is', 'are')} past CISA's fix-by date.")
    elif waiting:
        why = f"{waiting} item{_s(waiting)} {_s(waiting, 'needs', 'need')} a decision or action; none is a RED risk on unproven controls."
    elif unproven_all:
        why = (f"Nothing is overdue, but {unproven_all} risk score{_s(unproven_all)} "
               f"{_s(unproven_all, 'rests', 'rest')} on controls not yet tested.")
    else:
        why = "Nothing is waiting on a decision, and every control our scores rely on has been tested."

    # ── What's next: up to three actions, most serious first ──
    actions = []
    if att["unproven_on_red"]:
        n = att["unproven_on_red"]
        actions.append(f"Test the controls behind {n} risk{_s(n)} rated RED before controls, "
                       f"or rescore {_s(n, 'it', 'them')} without those controls.")
    if att["kev_past_due"]:
        n = att["kev_past_due"]
        actions.append(f"Patch {n} known-exploited vulnerabilit{_s(n, 'y', 'ies')} past the CISA date.")
    if att["overdue_actions"]:
        n = att["overdue_actions"]
        actions.append(f"Close or re-plan {n} overdue remediation action{_s(n)}.")
    if att["reviews_past_due"]:
        n = att["reviews_past_due"]
        actions.append(f"Review {n} risk{_s(n)} past {_s(n, 'its', 'their')} review date.")
    if att["acceptances_due"]:
        n = att["acceptances_due"]
        actions.append(f"Re-confirm or end {n} risk acceptance{_s(n)} coming due.")

    # ── Top risks: highest after controls, then before ──
    top = sorted(active, key=lambda r: (r.residual_risk_score or 0, r.inherent_risk_score or 0),
                 reverse=True)[:TOP_RISKS]
    top_rows = [dict(
        risk=r,
        title=((r.threat_description or r.asset_system or "Untitled").strip()[:64]
               + ("..." if len((r.threat_description or r.asset_system or "")) > 64 else "")),
        unproven=assurance.control_assurance(r, today) in assurance.UNPROVEN,
    ) for r in top]

    kpis = [
        dict(label="Active risks", value=len(active),
             delta=_delta(len(active), base.active if base else None, lower_is_better=None),
             note=f"{len(risks) - len(active)} closed, not counted"),
        dict(label="RED after controls", value=red, tone="bad" if red else "good",
             delta=_delta(red, base.red if base else None),
             note=f"{amber} AMBER · {green} GREEN"),
        dict(label="Need action", value=waiting, tone="bad" if waiting else "good",
             delta=_delta(waiting, base_waiting),
             note="See Needs attention"),
        dict(label="KEV past CISA due", value=att["kev_past_due"],
             tone="bad" if att["kev_past_due"] else "good",
             delta=_delta(att["kev_past_due"], base.kev_past_due if base else None),
             note="Known-exploited, still open"),
    ]

    return dict(
        as_of=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        today=today,
        headline=headline,
        why=why,
        kpis=kpis,
        tiles=tiles,
        waiting=waiting,
        actions=actions[:3],
        top_rows=top_rows,
        trend=_trend(snapshots),
        first_snapshot=first.snapshot_date if first else None,
        compare_ready=base is not None,
        heatmap=_heatmap(active, red_t, amber_t),
        treatment=_treatment(active),
        aging=_vuln_aging(today),
        elevate_after=ELEVATE_AFTER_DAYS,
        rag_colors=RAG_COLORS,
        compare_days=COMPARE_DAYS,
        compare_phrase=COMPARE_PHRASE,
        trend_days=TREND_DAYS,
        red_t=red_t,
        amber_t=amber_t,
    )
