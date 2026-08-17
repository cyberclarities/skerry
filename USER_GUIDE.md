# Skerry — User Guide

**Version:** 1.0  
**Platform:** Skerry — `skerry.example.com`  
**Audience:** Everyone with an account — Viewer, Operator, and Admin

---

## Who This Guide Is For

Every user role is covered here — find your section and start there. Viewers start at [Part 1](#part-1-all-users). Operators add [Part 2](#part-2-operators). Admins add [Part 3](#part-3-admins).

You do not need a cybersecurity background to use this tool. The concepts are explained where they come up.

---

## Table of Contents

**Part 1 — All Users (Viewer and above)**
1. [Logging In](#1-logging-in)
2. [The Dashboard](#2-the-dashboard)
3. [Browsing the Register](#3-browsing-the-register)
4. [Reading a Risk Record](#4-reading-a-risk-record)
5. [Reports](#5-reports)
6. [Exporting Data](#6-exporting-data)

**Part 2 — Operators and Admins**
7. [Creating a New Risk](#7-creating-a-new-risk)
8. [Editing a Risk](#8-editing-a-risk)
9. [Understanding Risk Scoring](#9-understanding-risk-scoring)
10. [NIST CSF 2.0 Mapping](#10-nist-csf-20-mapping)
11. [Adding a Trend Log Entry](#11-adding-a-trend-log-entry)
12. [Tracking Vulnerability Findings](#12-tracking-vulnerability-findings)

**Part 3 — Admins Only**
13. [User Management](#13-user-management)
14. [Lookup Lists](#14-lookup-lists)
15. [Accepting and Closing Risks](#15-accepting-and-closing-risks)
16. [Database Backup and Restore](#16-database-backup-and-restore)

---

# Part 1 — All Users

## 1. Logging In

Open a browser and navigate to:

```
https://skerry.example.com
```

On first visit from a new workstation, the browser may show a security certificate warning. Click **Advanced → Proceed to site**. This is a known condition on internal tools and is not a sign of a problem — contact your administrator if you want to eliminate the warning permanently.

### Local Login

Enter your username and password and click **Sign In**. Your username is lowercase with no spaces — it was set by an administrator when your account was created.

If you have forgotten your password, contact your administrator. There is no self-service reset.

### SSO Login (if configured)

If your organization uses Azure AD single sign-on, click **Sign in with SSO** and complete the Microsoft authentication prompt. Your account is provisioned automatically on first SSO login — no separate setup is needed.

### After Login

You land on the Dashboard. The left sidebar shows navigation options based on your role. If you cannot see an option you expect, your role may not include that access — ask your administrator.

---

## 2. The Dashboard

The Dashboard gives you a current-state picture of the risk register without requiring you to dig into individual records.

### KPI Row

The top row of cards shows counts by RAG status — Red, Amber, Green — along with three additional indicators:

- **Exceeds Appetite** — risks where the residual score is above the organization's defined risk appetite threshold
- **Overdue Actions** — risks where the due date has passed and the status is still open
- **Board Flagged** — risks marked for board-level reporting

These numbers are live — they reflect the current state of the register every time the page loads.

### Risk Heat Map

The grid maps Likelihood (columns, left to right, 1–5) against Impact (rows, bottom to top, 1–5). Each cell shows how many risks fall at that combination. Darker or more populated cells toward the top-right corner indicate the most severe concentration of risk. Empty cells are not a sign of good news — they may mean risks in those areas have not been identified yet.

### Control Test Status

A three-part breakdown of control test results across all risks: Pass, Fail, and Not Tested. A high Not Tested count warrants attention — controls that are not tested are controls that are not verified.

### Financial Exposure

Aggregate totals of minimum and maximum financial exposure across all risks that have exposure estimates entered. The average max exposure for RED risks is called out separately.

### Recent Activity

The five most recently updated risk records, with direct links. Useful for picking up where you left off.

---

## 3. Browsing the Register

Navigate to **Register** in the left sidebar.

The full register loads by default, sorted by Risk ID. You do not need to know a Risk ID to find what you are looking for.

### Search

The search bar at the top matches against Risk ID, threat description, asset/system, and risk owner. Type any part of a phrase and press Enter or click the search button. The results update in place.

### Filters

Five filters are available alongside the search bar:

- **RAG Status** — filter to Red, Amber, or Green risks only
- **Category** — filter by risk category (Infrastructure, Application, Data, etc.)
- **Status** — filter by workflow status (Open, In Progress, Closed, Accepted)
- **Owner** — partial text match against the Risk Owner field
- **Exceeds Appetite** — show only risks that exceed the risk appetite threshold (Yes) or those that do not (No)

Filters can be combined. Clear them by selecting the blank option from each dropdown.

### Risk List Columns

Each row in the register shows the essential fields at a glance — Risk ID, category, asset, likelihood, impact, inherent and residual scores, RAG status, owner, due date, and current status. Click any row to open the full record.

---

## 4. Reading a Risk Record

Click any risk in the list to open its detail view.

The record is organized into sections that follow the lifecycle of a risk from identification through treatment.

### Header

The top of the record shows the Risk ID, RAG status badge, and the key scores — inherent and residual. These are calculated from the values entered in the scoring section and update automatically when those values change.

### Core Identification

What the risk is: the affected asset or system, the business process it supports, what the threat is, and what vulnerability the threat would exploit. This section answers the basic "what are we talking about" question.

### Threat Intelligence

Context around the threat: the actor type (who is likely behind it), the attack vector (how they would execute it), and the intel source (what told us about it). These fields pull from the organization's configured lookup lists.

### Risk Scoring

Likelihood and impact ratings on a 1–5 scale. The inherent score (Likelihood × Impact) and residual score (inherent score adjusted for control effectiveness) are calculated from these values and the control effectiveness rating. See [Section 9](#9-understanding-risk-scoring) for a full explanation.

### Controls & Assurance

What controls are in place, what type they are, how effective they are rated, when they were last tested, and the test result. This section is where you see whether the controls that are supposed to reduce the risk have been verified as working.

### Velocity & Detection

Risk velocity (how quickly a threat could materialize — Rapid, Moderate, or Slow) and detection capability (whether the organization could detect the threat in time to respond — Full, Partial, Minimal, or None). These are qualitative context fields; they do not affect the calculated score.

### Governance

Who owns the risk, the escalation path, review frequency, and the date the risk was last reviewed. The board reporting flag, if set, means this risk is included in board-level reporting and in board escalation notifications.

### Treatment & Actions

The treatment decision (Mitigate, Accept, Transfer, or Avoid), the remediation action being taken, who owns that action, and the due date. Status reflects where the risk is in its lifecycle.

### Financial & Business Impact

Estimated minimum and maximum financial exposure, any regulatory obligations tied to this risk, and any related incident references.

### NIST CSF 2.0 Mapping

Which NIST Cybersecurity Framework function, category, and subcategory this risk maps to. This is used in the CSF Coverage report to show where risks are concentrated against the framework.

### Trend Log

A history of every time the residual score was recorded — automatically on each save, and manually when a reviewer logs a review entry. Shows the residual score, RAG status, change versus the prior entry, and any notes. This is the documentary record of whether the risk is improving, worsening, or holding steady over time.

### Audit Log

A field-level change history — every edit, what field changed, what the old value was, what the new value is, and who made the change. You cannot edit or delete audit log entries. They are the record of what happened and when.

---

## 5. Reports

Navigate to **Reports** in the left sidebar. All three reports are available to all roles.

### Overdue Actions

Lists every open risk where the due date has passed, sorted by days overdue — most critical at the top. This is the right starting point for a weekly status review. If a risk appears here, someone is past their committed date and needs to be contacted.

A risk stays on this list until its status is changed to Closed or Accepted, or its due date is extended with a documented reason.

### Risk Trend

Shows the score history for every risk that has trend log entries. A line chart traces each risk's residual score over time. This report answers the question leadership will always ask: is the program moving risk in the right direction? A flat or rising line on a RED risk is a problem that needs an explanation.

### CSF Coverage

Maps the risk register against the six NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) and their sub-categories. Shows where risks are documented and where there are gaps.

A gap on this report does not necessarily mean a security gap — it may mean risks in that area have not been documented yet. Both are worth understanding. Risks with no CSF mapping at all are listed at the bottom.

---

## 6. Exporting Data

The Excel export is available to all roles, accessible from **Export** in the left sidebar.

### Excel Export

Downloads the full risk register as a formatted `.xlsx` workbook. Two sheets are included:

- **Risk Register** — all risks with all fields, color-coded by RAG status, with Residual Score and RAG columns at the right edge
- **Overdue Actions** — a focused sheet of just the overdue risks with the key action fields

The Excel export is appropriate for offline analysis, sharing with stakeholders who do not have system access, or building custom charts and pivot tables on top of the data.

For a single-risk document suitable for routing to leadership and signature, see [Generating a Decision / Acceptance Form](#generating-a-decision--acceptance-form) in Section 14.

---

# Part 2 — Operators and Admins

## 7. Creating a New Risk

Navigate to **Register → New Risk** (button in the top-right corner). This option is visible to Operators and Admins.

A Risk ID is assigned automatically using the configured prefix (`CR-001`, `CR-002`, etc.). You will see the next available ID displayed before you save.

### What Is Required

Threat Description is the only required field. Everything else can be filled in as your understanding of the risk develops. Do not let the form size stop you from logging a risk you know about — a partial record is better than nothing in the register.

That said, a record with only a threat description is not a managed risk. Work toward completing Likelihood, Impact, Existing Controls, Control Effectiveness, Risk Owner, Treatment, and Due Date. Those six fields are what makes the record actionable.

### Filling in the Form

The form is divided into sections that match the detail view layout. A few that warrant explanation:

**Risk Category** — choose the category that best represents where this risk lives: Infrastructure, Application, Data, Identity & Access, Supply Chain, Compliance, Physical, People, or Third Party. If a risk spans multiple categories, choose the primary one.

**Threat Actor Type, Attack Vector, Threat Intel Source** — these pull from your organization's configured lookup lists. If the value you need is not there, ask an admin to add it in Settings.

**Likelihood and Impact** — both are rated 1–5. See [Section 9](#9-understanding-risk-scoring) for the scale and what the scores mean. The inherent and residual scores calculate live as you enter or change these values.

**Control Effectiveness** — rates how well the existing controls reduce the risk, on a 1–5 scale. This is not a rating of how many controls exist — it is a rating of how well they are working. A bank vault is a 5. A policy document that nobody reads is a 1.

**Last Control Test Date and Test Result** — when controls were last verified and whether they passed. If controls have not been tested, enter "Not Tested." Untested controls do not count.

**Risk Owner** — pulls from the Risk Owners lookup list. This name must match the user's Full Name in the system for email notifications to reach them.

**NIST CSF Mapping** — three cascading dropdowns: Function → Category → Subcategory. See [Section 10](#10-nist-csf-20-mapping).

**Board Reporting Flag** — check this if the risk should surface in board-level reporting. Risks with this flag set will also trigger escalation email notifications to administrators when they exceed risk appetite.

### Saving

Click **Save Risk** at the bottom. You are redirected to the detail view. The trend log is automatically updated with the initial residual score.

---

## 8. Editing a Risk

From the risk detail view, click **Edit Risk** in the top-right corner.

### Who Can Edit What

Operators can edit risks they created, or risks where the Risk Owner field matches their display name. All other edits require Admin access.

This is not a bureaucratic hurdle — it is a control. Risk records carry weight with auditors and leadership. Changes need to be authorized.

If you need to update a risk you do not own, contact an admin.

### Tracking Changes

Every field change is recorded in the audit log automatically — old value, new value, who changed it, when. You do not need to add a note to document what you changed; the system does it. The notes/history field is for context that a field change alone would not capture: why a due date was extended, what the outcome of a conversation with the risk owner was, what changed in the environment that prompted the score adjustment.

### After Editing

Save returns you to the detail view. The trend log is updated automatically with the new residual score. The audit log shows the changes.

---

## 9. Understanding Risk Scoring

The scoring model is straightforward and consistent. Once you understand the three inputs, the rest follows.

### Likelihood (1–5)

How likely is it that this threat materializes within a meaningful timeframe?

| Score | Label | What It Means |
|---|---|---|
| 1 | Rare | Could happen but there is little to no reason to expect it |
| 2 | Unlikely | Has happened in the industry but not common |
| 3 | Possible | Could reasonably occur; some indicators present |
| 4 | Likely | More likely than not to occur; credible threat with known vectors |
| 5 | Almost Certain | Expected to occur; active targeting or known active exploitation |

### Impact (1–5)

What would the damage be if this threat materialized?

| Score | Label | What It Means |
|---|---|---|
| 1 | Negligible | Minimal disruption; handled through normal operations |
| 2 | Minor | Limited impact; recoverable with modest effort |
| 3 | Moderate | Significant disruption; requires dedicated response effort |
| 4 | Major | Serious harm to operations, finances, or reputation |
| 5 | Critical | Severe or catastrophic impact; existential threat to operations |

### Inherent Risk Score

Likelihood × Impact. This is the risk before any controls are applied — the raw exposure. Range is 1–25.

A 5×5 = 25 means this threat is almost certain to occur and would be catastrophic. A 1×1 = 1 means it is vanishingly unlikely and would barely register.

### Control Effectiveness (1–5)

How well are the existing controls reducing the risk?

| Score | Label | Reduction Applied |
|---|---|---|
| 1 | Minimal | 10% reduction |
| 2 | Low | 25% reduction |
| 3 | Moderate | 35% reduction |
| 4 | High | 50% reduction |
| 5 | Full | 65% reduction |

Note that even "Full" effectiveness only reduces the residual score by 65%, not 100%. No control set eliminates a risk entirely — it reduces it. A risk that truly has no remaining exposure should have its status set to Closed, not scored at 5 for effectiveness.

### Residual Risk Score

Inherent Score × (1 − Control Reduction). This is the risk after controls are applied.

Example: Likelihood 4, Impact 4 = Inherent 16. Control effectiveness 3 (Moderate, 35% reduction) = Residual 16 × 0.65 = 10.4.

### RAG Status

Residual score determines the color:

| Color | Threshold | What It Means |
|---|---|---|
| RED | Score ≥ 15 | High risk — requires active attention and escalation |
| AMBER | Score 9–14 | Elevated risk — being actively managed |
| GREEN | Score ≤ 8 | Within acceptable range |

Thresholds are configured by your administrator and may differ from the defaults above.

### Risk Appetite

The risk appetite threshold is a separate marker — typically set at 8 by default. Residual scores above this threshold are flagged as "exceeds risk appetite," regardless of RAG color. A GREEN risk can still exceed appetite if the threshold is set lower than 8. These risks are candidates for treatment escalation or formal acceptance.

---

## 10. NIST CSF 2.0 Mapping

Mapping risks to the NIST Cybersecurity Framework is not a compliance checkbox — it is a tool for understanding where your risk exposure is concentrated against a recognized structure. The CSF Coverage report depends on this data being filled in.

### The Six Functions

| Code | Function | What It Covers |
|---|---|---|
| GV | Govern | Policies, roles, oversight, supply chain risk management |
| ID | Identify | Asset management, risk assessment, improvement processes |
| PR | Protect | Access control, awareness, data security, platform security |
| DE | Detect | Continuous monitoring, adverse event analysis |
| RS | Respond | Incident management, analysis, mitigation, communication |
| RC | Recover | Recovery plan execution, recovery communication |

### How to Map a Risk

On the risk form, three cascading dropdowns handle the mapping:

1. Select the **Function** (e.g., PR — Protect)
2. Select the **Category** within that function (e.g., PR.DS — Data Security)
3. Select the **Subcategory** within that category (e.g., PR.DS-01 — Data at rest is protected)

Each subcategory has a full description available in the dropdown to help you choose the right one. If a risk maps to multiple subcategories, choose the most specific and most relevant one.

### If You Are Not Sure

Map to the function level at minimum. A risk mapped to a function is more useful than an unmapped risk. Refine to category and subcategory as your understanding develops.

Risks with no mapping appear in the "Unmapped" section at the bottom of the CSF Coverage report. That list is worth working through periodically.

---

## 11. Adding a Trend Log Entry

The trend log is updated automatically every time a risk is saved. Manual entries are for deliberate reviews — periodic check-ins where you are assessing the risk, testing controls, and recording the outcome.

### When to Add a Manual Entry

- After completing a scheduled review of a risk (monthly, quarterly, or annual)
- After a control test
- After a significant change in the risk environment that is worth documenting even if the scores did not change

### How to Add an Entry

From the risk detail view, scroll to the **Trend Log** section and click **Add Review Entry**.

Fill in:

- **Review Date** — defaults to today; change it if you are logging a review that occurred on a different date
- **Reviewer** — defaults to your name
- **Control Test Result** — Pass, Fail, or Not Tested; should reflect a real test, not an assumption
- **Notes** — what was observed, what changed, what action was agreed, why the score stayed the same if it did

Click **Add Entry**. The entry is saved with the current residual score and RAG status at the time of logging.

The trend chart on the detail view plots these entries over time.

---

## 12. Tracking Vulnerability Findings

Vulnerability findings are individual scanner results — typically one CVE apiece — tied to a risk. This is deliberately narrow: it exists to give the Decision / Acceptance Form (§15) real numbers to report instead of typed-in ones, not to replace a vulnerability management platform. There's no rescan workflow beyond marking a finding Remediated.

### Adding a Finding

From the risk detail view, scroll to **Add Vulnerability Finding** and fill in:

- **CVE / Finding ID** — the CVE number or scanner finding ID
- **Severity (CVSS)** and **ExPRT rating** — your scanner's severity and, if it reports one, its exploit-prediction rating; these can differ and both are tracked
- **Vulnerable product** — what the finding is against
- **Date found** — when the finding first appeared; this is what "days open" is computed from, so back-date it to match the scanner if you're entering historical findings, not the date you happened to be entering data
- **Remediation** — the fix, in scanner or vendor language
- **Status** — Open or Remediated

Click **Add Finding**. It appears in the **Vulnerability Findings** table below, along with a rolling count of open findings, how many are High severity, and the oldest open finding's age.

### Removing a Finding

Click the trash icon on any row. Do this when a finding was entered in error — for a finding that's actually been fixed, change its status to Remediated instead, so the register keeps a record that it existed.

### Where This Shows Up

The open/High counts and oldest-open figure feed the Executive Summary's Risk at a Glance table; the full list, with remediation and days open per finding, feeds the Supporting Evidence document's Vulnerability Evidence table (§15). Keep this list current before generating a Decision / Acceptance Form — that's the whole reason it's here.

---

# Part 3 — Admins Only

## 13. User Management

Navigate to **Admin → User Management** in the left sidebar.

### Adding a User

Click **Add User**. Complete all fields — username, full name, email, role, and initial password.

The username is what the person types at login. Keep it lowercase and simple. Full name is what appears throughout the system and is used for email notification routing — it must match exactly what gets entered in Risk Owner and Action Owner fields on risk records.

Set the password to something temporary and communicate it through a secure channel. Remind the user to note it somewhere safe.

### Editing a User

Click the pencil icon on any user row. You can change the username, name, role, active status, and password. Leave the password field blank to leave it unchanged.

You cannot demote the last active admin. The system blocks it.

### Deactivating a User

Click the deactivate icon on a user row. The account is disabled — the user cannot log in — but their name and any risks or audit entries they created remain intact. Do not ask for a hard delete; the system does not support it, by design. Deleting a user would corrupt audit trail references.

When someone leaves the organization or changes roles, deactivate first, then adjust role if needed. Do not share accounts.

### Passwords

Minimum length is 12 characters. There is no self-service reset — an admin sets a new temporary password through the edit form.

---

## 14. Lookup Lists

Navigate to **Admin → Settings** in the left sidebar.

Lookup lists control what appears in the dropdowns on the risk entry form. Four lists are configurable: Threat Actor Types, Attack Vectors, Threat Intel Sources, and Risk Owners.

### Risk Owners List — This One Matters Most

The Risk Owners list controls who appears in the Risk Owner dropdown when creating or editing a risk. Keep this list current with the people who are actually accountable for risks in your organization.

The names in this list need to match user Full Names in the system exactly — spelling, spacing, capitalization. When a notification triggers for an overdue action or review due, the system looks up the Risk Owner name against the user database. A mismatch means the notification goes nowhere. No error, no bounce — just silence.

### Adding a Value

Type the new entry in the Add field at the bottom of the relevant tab and click Add.

### Editing a Value

Click the pencil icon on any entry. Editing a value updates the list going forward — it does not change the stored value on any existing risk records that already have the old value. If you rename an owner, you will also need to update their name on existing risk records manually.

### Removing a Value

Click the trash icon. The value is soft-deleted — it disappears from the dropdown but is still stored on any existing risks. Risk records are not affected.

### Reordering

Use the up/down chevrons to control the order values appear in the dropdown.

---

## 15. Accepting and Closing Risks

Accepting and closing risks are admin-only actions because they carry authority. They are not status changes — they are decisions.

### Closing a Risk (Status: Closed)

Set the status to **Closed** when the risk has been fully remediated — the threat no longer exists or the vulnerability has been eliminated. Closed risks are excluded from overdue and notification logic.

If a closed risk becomes relevant again, reopen it by setting the status back to Open or In Progress. Do not create a new record for a risk that has already been through the register.

### Accepting a Risk (Treatment: Accept / Status: Accepted)

Setting treatment to **Accept** is a formal decision that the organization has assessed this risk, the residual score is known, and leadership has determined the risk is within acceptable bounds or not worth treating further. This is not the same as ignoring it.

Admins can complete two additional fields that document the authorization:

- **Acceptance Sign-Off By** — the name of the person authorizing the acceptance
- **Acceptance Sign-Off Date** — the date authorization was given

These fields create an accountable record. If a risk that was formally accepted later materializes, this record shows that the decision was deliberate and documented. That matters.

Do not mark a risk as Accepted because no one got around to treating it. Accept it when someone has reviewed it and made a conscious decision to carry the exposure.

### Generating a Decision / Acceptance Form

Operators and admins can generate a routable decision packet for any risk from the **Decision / Acceptance Form** button on the risk detail page. It downloads as a `.zip` containing two documents, built to escalate a risk to leadership for a treatment decision and to carry a signature — the risk owner's, and the Executive Core Team's if the treatment is Accept:

- **Executive Summary Decision Request** — one page. A Risk at a Glance table, Why This Matters and Recommended Action bullets, a four-option decision block (Mitigate / Accept / Avoid / Transfer) with checkboxes, and two signature lines. This is what goes in front of the Executive Core Team.
- **Supporting Evidence** — the full record behind that ask: risk narrative, business impact, risk mechanics, the vulnerability evidence table, treatment options with pros/trade-offs, RACI, and the risk owner sign-off block.

Everything the register already knows about the risk — scores, controls, treatment, owner, financial exposure, NIST CSF mapping, and vulnerability findings (see §11a) — is pulled in automatically; nothing here is retyped. A form asks for the handful of things that belong to that specific decision rather than to the risk record itself: who the request is routed to, the priority, the RACI, a one-sentence "ask" for the Evidence document and a fuller Executive Ask paragraph for the Summary (both drafted for you, editable before you generate), the Why This Matters / Recommended Action bullets, and a risk narrative.

If the register's stored Treatment differs from what you're actually recommending, set **Suggested treatment direction** on the form — both documents will show the register's value as the current state and your suggestion as the recommended action, rather than silently picking one. If Avoid or Transfer genuinely aren't options for this risk (a system that has to keep running, for instance), fill in why — that reason becomes the "not viable" language on both documents instead of a live checkbox.

Generating the form does not change the risk record or its status — it produces documents. If the Executive Core Team decides to accept the risk, come back and set Treatment to Accept and fill in the Acceptance Sign-Off fields above so the register and the signed documents agree.

### Deleting a Risk

Click **Delete** on the risk detail page. This is a hard delete — the record, trend log, and audit entries are permanently removed. Use it only for test records or obvious duplicates. For real risks that have been resolved, close them instead.

---

## 16. Database Backup and Restore

Navigate to **Admin → Settings → Database** tab.

### Downloading a Backup

Click **Download .db file**. The database downloads as a timestamped file (`risk_register_YYYYMMDD_HHMMSS.db`). Do this regularly — at minimum weekly, more often if the register is actively updated.

Store the file somewhere off the host: a network share, cloud storage, or your organization's backup system. A backup that lives only on the same server as the database is not a backup.

### Importing a Database

The Import & Replace function uploads a `.db` file and replaces the live database with it. This is how you restore from backup or migrate data from another instance.

Before the replace happens, the system:

1. Validates the uploaded file is a real SQLite database
2. Checks that all required tables are present
3. Creates an automatic backup of the current database

After a successful import, the application reconnects to the new database without requiring a restart.

**Use this for:** restoring from backup, migrating from another host, loading a test database for validation.

**Do not use this casually.** Importing replaces everything — all risks, all users, all settings. There is a confirmation prompt and an auto-backup, but there is no undo beyond restoring the auto-backup manually.

---

## Quick Reference — What Can Each Role Do?

| Action | Viewer | Operator | Admin |
|---|:---:|:---:|:---:|
| View all risks and reports | ✓ | ✓ | ✓ |
| Download Excel export | ✓ | ✓ | ✓ |
| Generate Decision / Acceptance Form | — | ✓ | ✓ |
| Create new risks | — | ✓ | ✓ |
| Edit risks they created or own | — | ✓ | ✓ |
| Add trend log entries | — | ✓ | ✓ |
| Edit any risk | — | — | ✓ |
| Delete risks | — | — | ✓ |
| Set treatment to Accept | — | — | ✓ |
| Sign off on risk acceptance | — | — | ✓ |
| Close risks | — | — | ✓ |
| Manage users | — | — | ✓ |
| Manage lookup lists | — | — | ✓ |
| Download / import database | — | — | ✓ |

---

*Questions about access or platform administration — contact your risk register administrator.*
