"""Turn Spotlight findings into a suggested likelihood and impact.

Read this section before trusting the numbers it produces.

The register scores risk as likelihood x impact on a 1-5 scale, applied by a
person who knows the business. A vulnerability scanner knows none of that. So
what follows is a **suggestion with its reasoning attached**, pre-filled into
the elevation form for an operator to accept or overrule. It is not an
automatic score, and nothing here writes a risk without a human pressing the
button.

Likelihood is built from CrowdStrike ExPRT.AI rather than the CVSS base
score. ExPRT weighs observed exploitation in the wild; CVSS base score does
not change no matter what attackers are actually doing. CISA KEV listing and
internet exposure push it further, because a known-exploited flaw on an
internet-facing host is a different proposition from the same CVE on a
laptop behind a VPN.

Impact is built from CVSS base score and asset context, because impact is
about what breaks -- and a domain controller breaking is not the same event
as a workstation breaking.

Every rule below is stated in the rationale string that ships with the
suggestion, so the operator sees the arithmetic and can argue with it.

Sources for the rating scales:
  ExPRT.AI ratings and exploit_status codes: CrowdStrike Falcon Spotlight
    API documentation (/spotlight/combined/vulnerabilities/v1, cve facet).
  CVSS v3.1 qualitative severity ranges: FIRST, "Common Vulnerability
    Scoring System v3.1: Specification Document", section 5 --
    https://www.first.org/cvss/v3.1/specification-document
  CISA Known Exploited Vulnerabilities catalog:
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

# ExPRT.AI rating -> base likelihood. CrowdStrike's rating already folds in
# exploitation activity, so this is the strongest single signal available.
EXPRT_LIKELIHOOD = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
}

# Fallback when ExPRT is absent (older findings, some third-party products).
# CVSS v3.1 qualitative ranges, FIRST specification section 5.
CVSS_LIKELIHOOD_FALLBACK = [
    (9.0, 4),   # Critical -- one below the ExPRT equivalent, on purpose:
    (7.0, 3),   # a base score with no exploitation signal deserves less
    (4.0, 2),   # confidence than a rating that has one.
    (0.1, 1),
]

# exploit_status codes returned in the cve facet.
EXPLOIT_ACTIVELY_USED = 90
EXPLOIT_EASILY_ACCESSIBLE = 60

# CVSS v3.1 qualitative severity ranges -> impact.
CVSS_IMPACT = [
    (9.0, 5),
    (7.0, 4),
    (4.0, 3),
    (0.1, 2),
]

# Falcon asset criticality, when the tenant populates it.
CRITICALITY_BUMP = {"CRITICAL": 1, "HIGH": 1}

SERVER_TYPES = {"Server", "Domain Controller"}


def _clamp(value, low=1, high=5):
    return max(low, min(high, value))


def _from_bands(score, bands, default=1):
    if score is None:
        return None
    for threshold, value in bands:
        if score >= threshold:
            return value
    return default


def suggest_scores(findings, hosts=None):
    """Suggest (likelihood, impact, rationale) for a set of staged findings.

    `findings` is the list being elevated; `hosts` the distinct SpotlightHost
    rows they sit on. Worst-case drives both scores -- a risk covering ten
    hosts is at least as bad as its worst host, and averaging would hide the
    one that matters.

    Returns (likelihood, impact, rationale_text). Both scores are 1-5, or
    None when there is genuinely nothing to score from -- in which case the
    form is left blank rather than filled with a fabricated number.
    """
    findings = [f for f in findings if f is not None]
    if not findings:
        return None, None, "No findings supplied; nothing to score."

    hosts = hosts or []
    reasons = []

    # -- Likelihood --------------------------------------------------------
    exprt_values = [
        EXPRT_LIKELIHOOD[(f.exprt_rating or "").upper()]
        for f in findings
        if (f.exprt_rating or "").upper() in EXPRT_LIKELIHOOD
    ]
    if exprt_values:
        likelihood = max(exprt_values)
        worst = max(findings, key=lambda f: EXPRT_LIKELIHOOD.get(
            (f.exprt_rating or "").upper(), 0))
        reasons.append(
            f"Likelihood starts at {likelihood} from the highest ExPRT.AI rating "
            f"in scope ({(worst.exprt_rating or '').capitalize()}, {worst.cve_id})."
        )
    else:
        scores = [f.cve_base_score for f in findings if f.cve_base_score]
        fallback = _from_bands(max(scores), CVSS_LIKELIHOOD_FALLBACK) if scores else None
        likelihood = fallback
        if likelihood:
            reasons.append(
                f"No ExPRT.AI rating on these findings, so likelihood starts at "
                f"{likelihood} from the highest CVSS base score ({max(scores)}). "
                f"A base score carries no exploitation signal, so this is "
                f"deliberately one band lower than the ExPRT equivalent."
            )
        else:
            reasons.append(
                "No ExPRT.AI rating and no CVSS base score on these findings -- "
                "likelihood left blank for you to set."
            )

    if likelihood:
        kev = [f for f in findings if f.is_cisa_kev]
        if kev:
            likelihood = _clamp(likelihood + 1)
            reasons.append(
                f"+1: {len(kev)} finding(s) are on the CISA Known Exploited "
                f"Vulnerabilities catalog ({kev[0].cve_id}"
                + (f" and {len(kev) - 1} more" if len(kev) > 1 else "")
                + ") -- exploitation is documented, not theoretical."
            )
        else:
            active = [f for f in findings
                      if (f.exploit_status or 0) >= EXPLOIT_ACTIVELY_USED]
            accessible = [f for f in findings
                          if (f.exploit_status or 0) >= EXPLOIT_EASILY_ACCESSIBLE]
            if active:
                likelihood = _clamp(likelihood + 1)
                reasons.append(
                    f"+1: {len(active)} finding(s) carry exploit status "
                    f"'Actively used'."
                )
            elif accessible:
                reasons.append(
                    f"No bump applied, but note {len(accessible)} finding(s) have "
                    f"exploit code easily accessible."
                )

        exposed = [h for h in hosts
                   if (h.internet_exposure or "").lower() in ("yes", "true")]
        if exposed:
            likelihood = _clamp(likelihood + 1)
            reasons.append(
                f"+1: {len(exposed)} of {len(hosts)} host(s) are flagged "
                f"internet-facing in Falcon."
            )

    # -- Impact ------------------------------------------------------------
    scores = [f.cve_base_score for f in findings if f.cve_base_score]
    if scores:
        impact = _from_bands(max(scores), CVSS_IMPACT)
        reasons.append(
            f"Impact starts at {impact} from the highest CVSS v3.1 base score "
            f"in scope ({max(scores)})."
        )
    else:
        severities = {(f.cve_severity or "").upper() for f in findings}
        impact = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}.get(
            next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in severities),
                 ""), None)
        if impact:
            reasons.append(
                f"No CVSS base score present; impact starts at {impact} from the "
                f"highest CVE severity band in scope."
            )
        else:
            reasons.append("No CVSS score or severity band -- impact left blank.")

    if impact:
        crit_hosts = [h for h in hosts
                      if (h.asset_criticality or "").upper() in CRITICALITY_BUMP]
        servers = [h for h in hosts if h.product_type_desc in SERVER_TYPES]
        if crit_hosts:
            impact = _clamp(impact + 1)
            reasons.append(
                f"+1: {len(crit_hosts)} host(s) carry a Critical/High asset "
                f"criticality in Falcon."
            )
        elif servers:
            impact = _clamp(impact + 1)
            reasons.append(
                f"+1: {len(servers)} host(s) are servers or domain controllers "
                f"({', '.join(sorted({h.product_type_desc for h in servers}))})."
            )

        if len(hosts) >= 10:
            impact = _clamp(impact + 1)
            reasons.append(
                f"+1: the scope covers {len(hosts)} hosts -- a shared failure "
                f"across that many assets is a wider business event than a "
                f"single machine."
            )

    reasons.append(
        "These are suggestions built from scanner data only. Scanner data does "
        "not know your business process, your compensating controls, or your "
        "regulatory exposure. Set the final numbers yourself."
    )
    return likelihood, impact, "\n".join(f"- {r}" for r in reasons)


def suggest_velocity(findings):
    """Risk velocity from exploitation signal, not from CVSS."""
    if any(f.is_cisa_kev for f in findings):
        return "Rapid"
    if any((f.exploit_status or 0) >= EXPLOIT_ACTIVELY_USED for f in findings):
        return "Rapid"
    if any((f.exploit_status or 0) >= EXPLOIT_EASILY_ACCESSIBLE for f in findings):
        return "Moderate"
    return "Slow"
