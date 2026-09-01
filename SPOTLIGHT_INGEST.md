# Spotlight Ingest — Setup and Operation

CrowdStrike Falcon Spotlight findings land in a staging queue. A person
reviews them. Some become risks in the register. Nothing becomes a risk on
its own.

---

## 1. Background — why a queue and not a direct import

Skerry's register holds a few dozen risks that people have thought about.
Spotlight on a mid-size estate returns tens of thousands of findings a night.
Piping one into the other turns the register into a scanner report, and a
register nobody trusts is a register nobody reads.

So the shape is a queue in front of the register:

```
Falcon Spotlight API
        │  nightly pull, FQL-filtered
        ▼
  spotlight_findings          ← staging. One row per host+CVE. Deduped on
  spotlight_hosts               Spotlight's own finding id.
        │
        │  an operator reviews and decides
        ▼
  spotlight_elevations        ← the decision record: what was elevated,
        │                       by whom, what the suggested scores were
        ▼
      risks  +  vulnerability_findings   ← the register, unchanged
```

The last arrow is a **copy**, not a link. Elevation writes ordinary
`VulnerabilityFinding` rows against the new risk, so every existing export,
Decision Request, open/High count, and "oldest open" line keeps working with
no change at all. The staging row remembers which risk it became and which
copied row carries its data — that is what makes "where did this number come
from?" answerable later.

---

## 2. Issue — the database upgrade path

Skerry has no Alembic and no migration history; `create_app()` calls
`db.create_all()` on boot. That method creates tables that do not exist and
leaves alone the ones that do.

**So the upgrade is: pull the code, restart. There is no migration step.**

The four new tables (`spotlight_hosts`, `spotlight_findings`,
`spotlight_elevations`, `spotlight_sync_runs`) are created on first boot. Not
one column is added to, removed from, or altered on `users`, `risks`,
`audit_log`, `trend_log`, `vulnerability_findings`, `lookup_items`, or
`nist_csf_reference`.

That constraint is enforced by a test, not by good intentions:
`tests/test_spotlight_ingest.py::test_existing_schema_and_data_survive_the_upgrade`
builds a database from the pre-change models, adds rows, boots with the new
models, and asserts that every legacy `CREATE TABLE` statement is
byte-identical and every row unchanged. Run it before you deploy.

Two consequences worth knowing:

- `spotlight_findings.risk_id` and `spotlight_findings.vuln_finding_id`
  are **plain indexed integers, not foreign keys**. A real FK to `risks`
  would change how the existing admin delete-risk route behaves. Referential
  integrity is handled in the application: `SpotlightElevation.risk`
  resolves to `None` when the risk has been deleted, and the elevation row
  keeps the risk reference (`SKR-014`) so the history stays readable.
- Take a copy of `data/risk_register.db` before the first boot anyway.
  Free, and it costs you nothing to have it.

### Rollback

Revert the code and restart. The new tables stay in the file, unread and
unreferenced — SQLite does not care, and neither does the old code. If you
want them gone, `DROP TABLE` the four `spotlight_*` tables on a copy first
and check the app still starts.

---

## 3. Configuration

### 3.1 CrowdStrike API client

In the Falcon console: **Support and resources → API clients and keys → Create
API client.**

Grant exactly one scope:

| Scope | Permission |
|---|---|
| Spotlight vulnerabilities | **Read** |

Nothing in this integration writes back to CrowdStrike. A key with more than
read on one service is more key than the job needs — and it is the key that
ends up in a `.env` file on a server.

Note the **base URL** the console shows you when the client is created. The
wrong region returns a 401 with a perfectly valid key, which is a confusing
half hour.

### 3.2 Environment

Add to `.env` (docker-compose already passes the whole file through):

```dotenv
# --- CrowdStrike Falcon Spotlight ---------------------------------------
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret

# us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2
FALCON_CLOUD_REGION=us-1
# Or set the base URL directly and ignore the region:
# FALCON_BASE_URL=https://api.us-2.crowdstrike.com

# The Spotlight API requires an FQL filter — there is no "everything" query.
SPOTLIGHT_FQL_FILTER=status:'open',status:'reopen'

SPOTLIGHT_PAGE_SIZE=400
SPOTLIGHT_SYNC_ENABLED=true
SPOTLIGHT_SYNC_HOUR=5
SPOTLIGHT_SYNC_MINUTE=30
FALCON_HTTP_TIMEOUT=60
```

Restart, then go to **Admin → Spotlight Sync** and press **Test connection**.
It pulls exactly one record and reports what it found or what went wrong.

### 3.3 Choosing an FQL filter

The default pulls every open and reopened finding. On a large estate that is
a queue no one can work. Narrow it until the New count is a number a person
can actually get through.

FQL joins with `+` for AND and `,` for OR:

| Goal | Filter |
|---|---|
| Open findings (default) | `status:'open',status:'reopen'` |
| Open, High and Critical only | `status:'open'+cve.severity:['HIGH','CRITICAL']` |
| Open, CISA KEV only | `status:'open'+cve.is_cisa_kev:true` |
| Open on servers | `status:'open'+host_info.product_type_desc:'Server'` |
| Open, ExPRT High or above | `status:'open'+cve.exprt_rating:['HIGH','CRITICAL']` |
| Open, seen in the last 30 days | `status:'open'+last_seen_within:'30'` |

Filterable fields, per the CrowdStrike API definition: `aid`, `cid`,
`last_seen_within`, `status`, `cve.id`, `cve.is_cisa_kev`,
`cve.remediation_level`, `cve.cps_rating`, `cve.exprt_rating`,
`cve.exploit_status_to_include`, `cve.severity`, `cve.base_score`,
`cve.types`, `host_info.asset_criticality`, `host_info.asset_roles`,
`host_info.internet_exposure`, `host_info.tags`, `host_info.groups`,
`host_info.product_type_desc`, `host_info.platform_name`,
`suppression_info.is_suppressed`, `suppression_info.reason`,
`host_info.instance_state`. Wildcards are not supported.

You can override the filter for a single run from the Spotlight Sync page
without changing `.env`.

---

## 4. How the sync behaves

Endpoint: `GET /spotlight/combined/vulnerabilities/v1`, facets `cve`,
`host_info`, `remediation`. Paged on the `after` token, 400 records a page.

| Situation | What happens |
|---|---|
| Finding seen for the first time | New row, state **New** |
| Same finding on a later pull | Row updated in place. No duplicate. |
| Spotlight now reports it closed | `spotlight_status` set to closed. **Row kept.** |
| Operator already triaged or dismissed it | Triage state **left alone.** A sync never undoes a human decision. |
| One malformed record | Counted as skipped, sync continues |
| Token expires mid-run | Re-authenticates and continues |
| Rate limited (429) | Waits the `X-RateLimit-RetryAfter` the API asks for |
| Any failure | Run recorded as **failed** with the error. It does not leave yesterday's numbers looking current. |

Closed findings are kept, not deleted. A closed finding that was once
elevated is evidence, and deleting evidence to tidy a queue is how you lose
the ability to answer a question six months later.

**Reconcile remediated findings** (Spotlight Sync page) pushes Spotlight's
closures onto the copied register findings — it flips them to *Remediated*
and touches nothing else. It will not overwrite a severity or a date an
operator corrected by hand.

---

## 5. Working the queue

**Spotlight Ingest** in the sidebar opens the host rollup: one row per host,
ordered by KEV count, then worst severity, then highest CVSS. That ordering
is the point — it puts the thing being exploited today above the thing with
the prettiest CVSS number.

Three routes into a decision:

- **Host view → Review.** The normal case. One host's open findings become
  one risk.
- **CVE view.** Click any CVE to see every host it affects. This is the path
  for a widely-discovered issue: one CVE, many hosts, one risk.
- **Finding view.** A flat filterable list. Select any rows and elevate the
  selection.

Then either:

- **Elevate** — opens a pre-filled risk form.
- **Mark triaged** — looked at, not yet decided.
- **Dismiss** — needs a reason, and records who and when. A queue where
  things disappear with no reason attached is a queue nobody trusts.

---

## 6. The suggested scores, and where they come from

The elevation form arrives with likelihood and impact filled in, and the
arithmetic printed above them. They are suggestions. You set the final
numbers.

**Likelihood** starts from the CrowdStrike **ExPRT.AI** rating, not the CVSS
base score, because ExPRT weighs observed exploitation and a base score does
not change no matter what attackers are actually doing.

| ExPRT.AI rating | Starting likelihood |
|---|---|
| Critical | 5 |
| High | 4 |
| Medium | 3 |
| Low | 2 |

With no ExPRT rating present, it falls back to the CVSS base score one band
lower than the ExPRT equivalent — a score with no exploitation signal
deserves less confidence than a rating that has one.

Then, capped at 5:

- **+1** if any CVE in scope is on the CISA KEV catalog
- **+1** (if not KEV) if any CVE has exploit status *Actively used*
- **+1** if any host in scope is flagged internet-facing in Falcon

**Impact** starts from the highest CVSS v3.1 base score in scope, using the
FIRST qualitative bands (9.0+ → 5, 7.0+ → 4, 4.0+ → 3, 0.1+ → 2), then:

- **+1** if any host carries Critical or High asset criticality in Falcon
- **+1** (if not the above) if any host is a server or domain controller
- **+1** if the scope covers 10 or more hosts

Worst case drives both, deliberately — a risk covering ten hosts is at least
as bad as its worst host, and averaging would hide the one that matters.

**Control effectiveness is left blank on purpose.** A control you have not
tested is not a control you can claim, and the scanner has no opinion on
yours.

**Business process is left blank too**, and it is the one field that matters
most. Spotlight cannot tell you what the host does for the business. Leave it
empty and the executive summary reads like a scan report instead of a risk.

Every suggestion, and the rationale that produced it, is written to the
elevation record and appended to the risk's notes. So when someone asks in
six months why `SKR-014` was scored 5 × 5, the answer is in the record rather
than in someone's memory.

Sources for the scales:

- ExPRT.AI ratings and `exploit_status` codes — CrowdStrike Falcon Spotlight
  API, `/spotlight/combined/vulnerabilities/v1`, `cve` facet.
- CVSS v3.1 qualitative severity ranges — FIRST, *Common Vulnerability
  Scoring System v3.1: Specification Document*, section 5.
  https://www.first.org/cvss/v3.1/specification-document
- CISA Known Exploited Vulnerabilities catalog —
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## 7. What elevation writes

For a selection of staged findings, one **Risk** with:

| Risk field | Filled from |
|---|---|
| `asset_system` | Hostname, or a host summary for a multi-host risk |
| `threat_description` | Plain-language summary — counts, KEV status, oldest finding |
| `vulnerability_detail` | One line per CVE, worst-first, with the API endpoint cited |
| `threat_intel_source` | `CrowdStrike Falcon Spotlight` |
| `assurance_source` | `Vulnerability Scan` |
| `risk_velocity` | Rapid / Moderate / Slow, from exploitation signal |
| `remediation_action` | The remediations Spotlight identifies |
| `date_identified` | Earliest Spotlight `created_timestamp` in scope |
| `nist_csf_subcategory` | `ID.RA-01`, so CSF Coverage is populated by default |
| `notes_history` | Ingest provenance and the full score rationale |

Plus one `VulnerabilityFinding` per staged finding, with `vulnerable_product`
prefixed by the hostname — because on a multi-host risk, "OpenSSL 1.1.1k"
eleven times tells the reader nothing, and "web03 | OpenSSL 1.1.1k" tells
them where to go.

Plus audit log entries, exactly as a manually-created risk gets.

A finding already on a risk cannot be elevated a second time. Selecting it
again is not an error — it is skipped, and you are told how many were.

---

## 8. Permissions

| Action | Role |
|---|---|
| View the ingest queue | Any logged-in user |
| Elevate, triage, dismiss | Operator or Admin |
| Run a sync, test the connection, reconcile | Admin |

Sync is admin-only because it touches an external system with a stored key.

---

## 9. Running the tests

```bash
python -m pytest tests/ -q
```

Nineteen tests, no network, no CrowdStrike tenant required. They cover the
schema-safety guarantee, the normalizer against a saved payload, dedupe
across repeated syncs, the "sync never undoes a triage decision" rule, the
scoring suggestions, the elevation copy, double-elevation refusal, and what
happens to an elevation record when its risk is deleted.

The API response shape in `tests/sample_spotlight_payload.json` is built from
the published CrowdStrike endpoint definition. **Before you trust the first
real sync, run one against your own tenant with a narrow filter** — something
like `status:'open'+cve.is_cisa_kev:true` — and check the parsed fields on a
host you know. Field names vary between Falcon tenants and API versions, and
the honest position is that this has been tested against a saved payload, not
against your CID.
