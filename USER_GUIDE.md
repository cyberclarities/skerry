# Skerry User Guide

**Version:** 1.8  
**Platform:** Skerry, at the address your administrator gives you  
**Audience:** Everyone with an account: Viewer, Operator, and Admin

---

## Who This Guide Is For

Every user role is covered here. Find your section and start there. Viewers start at [Part 1](#part-1-all-users). Operators add [Part 2](#part-2-operators-and-admins). Admins add [Part 3](#part-3-admins-only).

You do not need a cybersecurity background to use this tool. The concepts are explained where they come up.

---

## Table of Contents

**Part 1: All Users (Viewer and above)**
1. [Logging In](#1-logging-in)
2. [The Dashboard](#2-the-dashboard)
3. [Browsing the Register](#3-browsing-the-register)
4. [Reading a Risk Record](#4-reading-a-risk-record)
5. [Reports](#5-reports)
6. [Exporting Data](#6-exporting-data)

**Part 2: Operators and Admins**
7. [Creating a New Risk](#7-creating-a-new-risk)
8. [Editing a Risk](#8-editing-a-risk)
9. [Understanding Risk Scoring](#9-understanding-risk-scoring)
10. [NIST CSF 2.0 Mapping](#10-nist-csf-20-mapping)
11. [Adding a Trend Log Entry](#11-adding-a-trend-log-entry)
12. [Tracking Vulnerability Findings](#12-tracking-vulnerability-findings)
13. [Working the Spotlight Ingest Queue](#13-working-the-spotlight-ingest-queue)

**Part 3: Admins Only**
14. [User Management](#14-user-management)
15. [Lookup Lists](#15-lookup-lists)
16. [Accepting and Closing Risks](#16-accepting-and-closing-risks)
17. [Database Backup and Restore](#17-database-backup-and-restore)

---

# Part 1: All Users

## 1. Logging In

Open a browser and go to the address your administrator gave you. It looks like this; the `:8443` is part of it unless your administrator moved Skerry to the standard port:

```
https://skerry.example.com:8443
```

On first visit from a new workstation, the browser may show a security certificate warning. Click **Advanced → Proceed to site**. This is a known condition on internal tools and is not a sign of a problem. Contact your administrator if you want to eliminate the warning permanently.

### Local Login

Enter your username and password and click **Sign In**. Your username is lowercase with no spaces. It was set by an administrator when your account was created.

If you have forgotten your password, contact your administrator. There is no self-service reset.

### SSO Login (if configured)

If your organization uses Azure AD single sign-on, click **Sign in with SSO** and complete the Microsoft authentication prompt. Your account is provisioned automatically on first SSO login; no separate setup is needed.

### After Login

You land on the Dashboard. The left sidebar shows navigation options based on your role. The **Reports** and **Admin** groups collapse: click the heading to fold or open one. Your browser remembers which you left closed, and a group always opens when you are on one of its pages. If you cannot see an option you expect, check for a collapsed group first; otherwise your role may not include that access. Ask your administrator.

The version number under the logo is the release of Skerry you are on. Include it when you report a problem.

### If Something Looks Wrong

**The page looks plain, or icons and charts are missing.** Skerry's styling, icons, and charts load from an outside site, `cdn.jsdelivr.net`, and the browser checks each file before using it. If your network blocks that site, or a file arrives altered, the browser leaves it out. The register and everything in it are fine. But the page will look bare and the charts will not draw. Tell your administrator; it is a network setting, not a fault in the register.

**"502 Bad Gateway" for a minute or so.** Skerry is restarting, usually for an upgrade. Wait a minute and reload. Anything already saved is safe. If you were in the middle of saving, open the record and check that your change is there.

---

## 2. The Dashboard

The Dashboard gives you a current picture of the register without opening individual records. Every figure on it counts active risks only: anything not Closed. Accepted risks count, because accepting a risk does not make it go away.

### Needs Attention

The panel at the top holds only things someone has to act on. Each tile shows a count and opens the list behind it; a tile with work waiting turns red.

- **Overdue actions:** remediation past its due date. Opens the Overdue Actions report.
- **Reviews past due:** risks past their review date (see Reviews Due, below).
- **Acceptances due:** accepted risks due for another look within 30 days, or with no review frequency at all.
- **RED on unproven controls:** risks that are RED before controls, whose score after controls rests on controls never tested, last tested more than a year ago, or failed. Opens Control Assurance. A risk can look AMBER or GREEN on the rest of the dashboard and still count here; that is the point of the tile.
- **KEV past CISA due:** open Spotlight findings in the CISA Known Exploited Vulnerabilities catalog past their CISA due date, whatever their triage state. Opens the CVE view filtered to them.

When nothing is waiting, the panel says so.

### KPI Row

Active risks (with how many closed risks are left out), counts by RAG rating (Red, Amber, Green), risks that exceed the risk appetite, and risks flagged for board reporting. Overdue actions live in the Needs Attention panel above.

### Risk Heat Map

The grid maps Likelihood (columns, left to right, 1 to 5) against Impact (rows, bottom to top, 1 to 5). Each cell shows how many active risks sit at that combination, shaded by the score before controls. Hover over a cell to see how its risks are rated after controls. A line under the map shows how many active risks are on it, and how many cannot be placed because likelihood or impact is not set.

### Register Trend

Active risks by rating, one point per day. Skerry records the register's counts once a day, just after midnight UTC (see Daily Snapshot below). The chart appears from the second day of snapshots; until then the card says when collecting began.

### Control Test Results

A three-part breakdown of control test results across active risks: Pass, Fail, and Not Tested (a risk with no result recorded counts as Not Tested). A high Not Tested count warrants attention: controls that are not tested are controls that are not verified.

### Risk Velocity

Active risks by how fast the threat could materialize: Rapid, Moderate, or Slow.

### Financial Exposure

Totals of minimum and maximum financial exposure across active risks that have estimates entered. The average maximum exposure for RED risks is called out separately.

### By Category

Active risks by risk category, with risks that have none counted as Uncategorized.

### Recent Activity

The five most recently updated risk records, with direct links. Unlike the rest of the dashboard, this includes risks just closed. Useful for picking up where you left off.

---

## 3. Browsing the Register

Navigate to **Register** in the left sidebar.

The full register loads by default, in Risk ID order. You do not need to know a Risk ID to find what you are looking for.

### Search

The search bar at the top matches against Risk ID, threat description, asset/system, and risk owner. Type any part of a phrase and press Enter or click the search button. The results update in place.

### Filters

These filters sit alongside the search bar:

- **RAG Status:** Red, Amber, or Green risks only.
- **Category:** one risk category (Infrastructure, Application, Data, and so on).
- **Status:** tick one or more statuses (Open, In Progress, Closed, Accepted). None ticked shows all.
- **Exceeds Appetite:** risks over the risk appetite threshold (Yes), or under it (No).
- **Hide closed:** hides Closed risks whatever else is picked.

Filters can be combined. They are kept in the page address, so a refresh, the Back button, or a bookmark brings back the same view.

### Risk List Columns

Each row shows Risk ID, category, threat, asset, inherent and residual scores, RAG status, owner, due date, status, and the NIST CSF subcategory the risk maps to. Click a Risk ID to open the full record.

### Setting the CSF Mapping

Operators and admins can set a risk's NIST CSF mapping from the register, without opening the risk:

- **One risk:** click its code in the **CSF** column (or **Set** when it has none). Pick a subcategory and save.
- **Several risks:** tick their checkboxes, or the box in the header for every risk on the page, then **Set CSF for selected**. The subcategory you pick goes on every risk you ticked.

In the picker, type a code such as `ID.RA-01` to jump to it. You pick the subcategory only; its category and function are filled in from it, so the three always agree. **Not set** at the top clears the mapping.

Operators can only change risks they created or own, so only those rows show a checkbox and an editable code. Every change is recorded in the risk's audit log, the same as an edit.

---

## 4. Reading a Risk Record

Click any risk in the list to open its detail view.

The record is organized into sections that follow the lifecycle of a risk from identification through treatment.

### Header

The top of the record shows the Risk ID, RAG status badge, and the key scores, inherent and residual. These are calculated from the values entered in the scoring section and update automatically when those values change.

### Core Identification

What the risk is: the affected asset or system, the business process it supports, what the threat is, and what vulnerability the threat would exploit. This section answers the basic "what are we talking about" question.

### Threat Intelligence

Context around the threat: the actor type (who is likely behind it), the attack vector (how they would execute it), and the intel source (what told us about it). These fields pull from the organization's configured lookup lists.

### Risk Scoring

Likelihood and impact ratings on a 1–5 scale. The inherent score (Likelihood × Impact) and residual score (inherent score adjusted for control effectiveness) are calculated from these values and the control effectiveness rating. See [Section 9](#9-understanding-risk-scoring) for a full explanation.

### Controls & Assurance

What controls are in place, what type they are, how effective they are rated, when they were last tested, and the test result. This section is where you see whether the controls that are supposed to reduce the risk have been verified as working.

### Velocity & Detection

Risk velocity (how quickly a threat could materialize: Rapid, Moderate, or Slow) and detection capability (whether the organization could detect the threat in time to respond: Full, Partial, Minimal, or None). These are qualitative context fields; they do not affect the calculated score.

### Governance

Who owns the risk, the escalation path, review frequency, and the date the risk was last reviewed. The board reporting flag, if set, means this risk is included in board-level reporting and in board escalation notifications.

### Treatment & Actions

The treatment decision (Mitigate, Accept, Transfer, or Avoid), the remediation action being taken, who owns that action, and the due date. Status reflects where the risk is in its lifecycle.

### Financial & Business Impact

Estimated minimum and maximum financial exposure, any regulatory obligations tied to this risk, and any related incident references.

### NIST CSF 2.0 Mapping

Which NIST Cybersecurity Framework function, category, and subcategory this risk maps to. This is used in the CSF Coverage report to show where risks are concentrated against the framework.

### Trend Log

A history of every time the residual score was recorded: automatically on each save, and manually when a reviewer logs a review entry. Shows the residual score, RAG status, change versus the prior entry, and any notes. This is the documentary record of whether the risk is improving, worsening, or holding steady over time.

### Audit Log

A field-level change history: every edit, what field changed, what the old value was, what the new value is, and who made the change. You cannot edit or delete audit log entries. They are the record of what happened and when.

---

## 5. Reports

Navigate to **Reports** in the left sidebar. All six reports and the Excel export are available to all roles. Click the **Reports** heading to collapse or expand the list; the sidebar remembers your choice in that browser, and the list always opens when you are on a report.

### One-Page Briefing

A single page for executives and trustees, built live from the register in Smart Brevity order: a headline with the main number, why it matters, four figures with their change from a month ago, the 90-day trend by rating, where risks sit, how we are treating them, how long open Critical and High vulnerabilities have been on our hosts, what needs attention, the top five risks, and up to three next steps. A short glossary at the foot explains RAG, KEV, tested controls, and findings for readers outside security.

Every sentence is generated from the figures beside it, so it never claims more than the data shows. The month comparisons appear once the daily snapshot is a month old. Use **Print / Save as PDF** to send it; it fits one Letter page.

### Overdue Actions

Lists every risk that is not Closed or Accepted whose due date has passed, sorted by days overdue, most overdue at the top. This is the right starting point for a weekly status review. If a risk appears here, someone is past their committed date and needs to be contacted.

A risk stays on this list until its status is changed to Closed or Accepted, or its due date is extended with a documented reason.

### Risk Trend Log

Shows the score history for every risk that has trend log entries. A line chart traces each risk's residual score over time. This report answers the question leadership will always ask: is the program moving risk in the right direction? A flat or rising line on a RED risk is a problem that needs an explanation.

### CSF Coverage

Maps the risk register against the six NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) and their sub-categories. Shows where risks are documented and where there are gaps.

A gap on this report does not necessarily mean a security gap. It may mean risks in that area have not been documented yet. Both are worth understanding. Risks with no CSF mapping at all are listed at the bottom.

### Control Assurance

Risks whose score after controls depends on controls nobody has proven: never tested, last tested more than 365 days ago, or failed. A risk "depends on controls" when it has a control effectiveness rating, because that rating is what lowers its score. Each row shows the score before and after controls and how much the controls lower it; if those controls do not hold, the risk is back at its score before controls. **RED before controls** narrows the list to the risks that would be RED.

To clear a row, test the control and record the test date and result on the risk, or lower its control effectiveness to what you can show.

### Reviews Due

Two lists. **Past due:** active risks past their review date. A risk is due its review frequency after its last review (Monthly every 30 days, Quarterly every 90, Annually every 365); an acceptance sign-off counts as a review, and a risk never reviewed counts from the day it was identified. **Acceptances due:** accepted risks whose next review is within 30 days or already past, plus accepted risks with no review frequency, since an acceptance with no review date never expires on its own. The page also says how many active risks have no review frequency set; those never come due. The same rule drives the review-due emails.

### Daily Snapshot

Once a day, just after midnight UTC, Skerry records one row of counts: active and closed risks, risks by rating, appetite and board flags, every Needs Attention figure, and open Spotlight findings. It is taken by the first request of the day; Docker's health check makes one every 30 seconds, so it happens whether or not anyone signs in. A day's row is never changed afterward. This is what the Register Trend chart and the One-Page Briefing's comparisons draw from. History starts the day version 1.6 was installed; nothing before that can be filled in.

---

## 6. Exporting Data

The Excel export is available to all roles, listed last under **Reports** in the left sidebar.

### Excel Export

Downloads the full risk register as a formatted `.xlsx` workbook. Two sheets are included:

- **Risk Register:** all risks with all fields, color-coded by RAG status, with Residual Score and RAG columns at the right edge
- **Overdue Actions:** a focused sheet of just the overdue risks with the key action fields

The Excel export is appropriate for offline analysis, sharing with stakeholders who do not have system access, or building custom charts and pivot tables on top of the data.

For a single-risk document that asks the CIO and CISO to mandate a course of action, see [Generating a Risk Action Request](#generating-a-risk-action-request) in Section 16.

---

# Part 2: Operators and Admins

## 7. Creating a New Risk

Click **New Risk** in the top-right corner of any page. The button is visible to Operators and Admins.

A Risk ID is assigned automatically using the configured prefix (`SKR-001`, `SKR-002`, etc., unless your administrator set a different one). You will see the next available ID displayed before you save.

### What Is Required

Threat Description is the only required field. Everything else can be filled in as your understanding of the risk develops. Do not let the form size stop you from logging a risk you know about. A partial record is better than nothing in the register.

That said, a record with only a threat description is not a managed risk. Work toward completing Likelihood, Impact, Existing Controls, Control Effectiveness, Risk Owner, Treatment, and Due Date. Those seven fields are what make the record actionable.

### Filling in the Form

The form is divided into sections that match the detail view layout. A few that warrant explanation:

**Risk Category:** choose the category that best represents where this risk lives: Infrastructure, Application, Data, Identity & Access, Supply Chain, Compliance, Physical, People, or Third Party. If a risk spans multiple categories, choose the primary one.

**Threat Actor Type, Attack Vector, Threat Intel Source:** these pull from your organization's configured lookup lists. If the value you need is not there, ask an admin to add it in Settings.

**Likelihood and Impact:** both are rated 1–5. See [Section 9](#9-understanding-risk-scoring) for the scale and what the scores mean. The inherent and residual scores calculate live as you enter or change these values.

**Control Effectiveness:** rates how well the existing controls reduce the risk, on a 1–5 scale. This is not a rating of how many controls exist. It is a rating of how well they are working. A bank vault is a 5. A policy document that nobody reads is a 1.

**Last Control Test Date and Test Result:** when controls were last verified and whether they passed. If controls have not been tested, choose "Not Tested." Untested controls do not count: a risk that leans on them shows up on the Control Assurance report, and on the dashboard if it is RED before controls.

**Risk Owner:** pulls from the Risk Owners lookup list. This name must match the owner's Full Name in Skerry (capitalization aside) for two things to work: their notification email, and their right to edit the risk if they are an Operator.

**NIST CSF Mapping:** three cascading dropdowns: Function → Category → Subcategory. See [Section 10](#10-nist-csf-20-mapping).

**Board Reporting Flag:** check this if the risk should surface in board-level reporting. Risks with this flag set will also trigger escalation email notifications to administrators when they exceed risk appetite.

**Acceptance Sign-Off By / Date:** only an Admin can fill these in. See [Section 16](#16-accepting-and-closing-risks).

### Saving

Click **Save Risk** at the bottom. You are redirected to the detail view. The trend log is automatically updated with the initial residual score.

---

## 8. Editing a Risk

From the risk detail view, click **Edit Risk** in the top-right corner.

### Who Can Edit What

Operators can edit risks they created, or risks where the Risk Owner field matches their display name (capitalization and surrounding spaces aside). That covers everything on the risk: its fields, status, treatment, review entries, vulnerability findings, CSF mapping, and Action Requests. All other edits require Admin access.

This is not a bureaucratic hurdle. It is a control. Risk records carry weight with auditors and leadership. Changes need to be authorized.

If you need to update a risk you do not own, contact an admin.

### Tracking Changes

Every field change is recorded in the audit log automatically: old value, new value, who changed it, when. You do not need to add a note to document what you changed; the system does it. The **Notes / History** field is for context that a field change alone would not capture: why a due date was extended, what the outcome of a conversation with the risk owner was, what changed in the environment that prompted the score adjustment.

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

Likelihood × Impact. This is the risk before any controls are applied: the raw exposure. Range is 1–25.

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

Note that even "Full" effectiveness only reduces the residual score by 65%, not 100%. No control set eliminates a risk entirely. It reduces it. A risk that truly has no remaining exposure should have its status set to Closed, not scored at 5 for effectiveness.

### Residual Risk Score

Inherent Score × (1 − Control Reduction). This is the risk after controls are applied.

Example: Likelihood 4, Impact 4 = Inherent 16. Control effectiveness 3 (Moderate, 35% reduction) = Residual 16 × 0.65 = 10.4.

### RAG Status

Residual score determines the color:

| Color | Threshold | What It Means |
|---|---|---|
| RED | 15 or higher | High risk. Requires active attention and escalation |
| AMBER | 9 up to 15 | Elevated risk, being actively managed |
| GREEN | Below 9 | Within acceptable range |

Residual scores can carry a decimal (10.4 in the example above), so the bands are written as ranges: 8.5 is GREEN, 14.9 is AMBER. A risk without likelihood or impact has no score and shows as UNKNOWN.

Thresholds are configured by your administrator and may differ from the defaults above.

### Risk Appetite

The risk appetite threshold is a separate marker, set at 8 by default. Residual scores above this threshold are flagged as "exceeds risk appetite," regardless of RAG color. A GREEN risk can still exceed appetite if the threshold is set lower than 8. These risks are candidates for treatment escalation or formal acceptance.

---

## 10. NIST CSF 2.0 Mapping

Mapping risks to the NIST Cybersecurity Framework is not a compliance checkbox. It is a tool for understanding where your risk exposure is concentrated against a recognized structure. The CSF Coverage report depends on this data being filled in.

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

1. Select the **Function** (e.g., PR: Protect)
2. Select the **Category** within that function (e.g., PR.DS: Data Security)
3. Select the **Subcategory** within that category (e.g., PR.DS-01: Data at rest is protected)

Each subcategory has a full description available in the dropdown to help you choose the right one. If a risk maps to multiple subcategories, choose the most specific and most relevant one.

### If You Are Not Sure

Map to the function level at minimum. A risk mapped to a function is more useful than an unmapped risk. Refine to category and subcategory as your understanding develops.

Risks with no mapping appear in the "Unmapped" section at the bottom of the CSF Coverage report. That list is worth working through periodically.

---

## 11. Adding a Trend Log Entry

The trend log is updated automatically every time a risk is saved. Manual entries are for deliberate reviews: periodic check-ins where you are assessing the risk, testing controls, and recording the outcome.

### When to Add a Manual Entry

- After completing a scheduled review of a risk (monthly, quarterly, or annual)
- After a control test
- After a significant change in the risk environment that is worth documenting even if the scores did not change

### How to Add an Entry

From the risk detail view, find the **Log Review** card in the right-hand column.

Fill in:

- **Review Date:** defaults to today; change it if you are logging a review that occurred on a different date
- **Reviewer:** defaults to your name
- **Control Test Result:** Pass, Fail, or Not Tested; should reflect a real test, not an assumption
- **Notes:** what was observed, what changed, what action was agreed, why the score stayed the same if it did

Click **Log Review**. The entry is saved with the current residual score and RAG status at the time of logging.

Logging a review also sets the risk's **Last Reviewed** date to the review date, which restarts its review clock. That is what takes a risk off the Reviews Due report and stops the review-due emails.

The control test result you log here is part of the review record only. It does not update the risk's own Last Control Test Date and Test Result. To clear a risk from the Control Assurance report, edit the risk and record the test there too.

The trend chart on the detail view plots these entries over time.

---

## 12. Tracking Vulnerability Findings

Vulnerability findings are individual scanner results, typically one CVE apiece, tied to a risk. This is deliberately narrow: it exists to give the Risk Action Request (§16) real numbers to report instead of typed-in ones, not to replace a vulnerability management platform.

Findings come in two ways: typed in by hand, as below, or copied in when a Spotlight finding is elevated to a risk ([Section 13](#13-working-the-spotlight-ingest-queue)). The Spotlight ones keep themselves current. When the nightly sync sees one fixed, it flips to Remediated on its own.

### Adding a Finding

From the risk detail view, scroll to **Add Vulnerability Finding** and fill in:

- **CVE / Finding ID:** the CVE number or scanner finding ID
- **Severity (CVSS)** and **ExPRT rating:** your scanner's severity and, if it reports one, its exploit-prediction rating; these can differ and both are tracked
- **Vulnerable product:** what the finding is against
- **Date found:** when the finding first appeared; this is what "days open" is computed from, so back-date it to match the scanner if you're entering historical findings, not the date you happened to be entering data
- **Remediation:** the fix, in scanner or vendor language
- **Status:** Open or Remediated. Set it right when you add the finding; there is no edit button afterward.

Click **Add Finding**. It appears in the **Vulnerability Findings** table below, along with a rolling count of open findings, how many are High severity, and the oldest open finding's age.

### Removing a Finding

Click the trash icon on any row. Do this when a finding was entered in error. A finding from Spotlight that you remove goes back to the Spotlight queue as New, because the CVE is still on the host.

A hand-entered finding that has since been fixed cannot be edited to Remediated. Leave it, or remove it and add it again as Remediated with the original date found, so the register keeps a record that it existed.

### Where This Shows Up

The open/High counts and oldest-open figure feed the Risk at a Glance table on the one-page Risk Action Request; the full list, with remediation and days open per finding, feeds the Supporting Evidence document's Vulnerability Evidence table (§16). Keep this list current before generating an action request. That's the whole reason it's here.

---

## 13. Working the Spotlight Ingest Queue

If your organization connects Skerry to CrowdStrike Falcon Spotlight, a sync (usually nightly) pulls in open Critical and High vulnerabilities from every managed host. They land in a queue, not in the register. A person decides what becomes a risk. Everyone can view the queue; Operators and Admins work it. The full detail is in `SPOTLIGHT_INGEST.md`, which your administrator has.

### Finding Your Way Around

Click **Spotlight Ingest** in the sidebar. Three views:

- **Hosts** (the default): one row per host, worst first: known-exploited (KEV) count, then severity, then CVSS score. **Review** on a host shows its open findings.
- **CVE view**: one row per CVE, oldest exposure on our hosts first. By default it shows CVEs open **60 days or more** and says how many younger ones it is holding back; change that with **Open on our hosts**. Click the **Product** header to group CVEs by the software they affect.
- **Findings**: a flat list of every host and CVE pair.

Filters (search by host or CVE, severity, ExPRT rating, triage state, host Type, KEV, internet-facing) carry across the views. Age always means how long the CVE has been on our hosts, not when it was published.

### Deciding What to Do

For each finding, or a selection of them:

- **Elevate:** turn it into a risk. From the CVE view, **Review** a CVE, untick any host that does not belong, and press **Elevate**. You get a risk form already filled in from the CVE: what it is, affected software, host count, ratings, KEV status and CISA deadline, and suggested likelihood and impact. Change anything you like; nothing is saved until you press **Create**. The findings are copied onto the new risk as vulnerability findings.
- **Mark triaged:** you have looked at it and not decided yet.
- **Dismiss:** not acting on it. A reason is required, and Skerry records who and when.
- **Delete:** noise. The finding leaves the queue and goes on the **Deleted findings** list with who, when, and your reason.

**Bulk delete by CVE.** One product often carries a dozen CVEs that one patch fixes. In the CVE view, group by **Product**, keep the CVE you will track, tick the rest, and press **Delete selected CVEs**. Only what your filters show is deleted. Up to 500 CVEs at a time.

### What the Next Sync Does

- **Dismissed or triaged** findings keep their state. A sync never undoes a person's decision.
- **Deleted** findings stay out of the queue while Spotlight still reports them open. If Spotlight later reports one fixed, and it comes back after that, it returns as New. **Restore** on the Deleted findings list brings one back on the next sync.
- **Fixed** findings (Spotlight stops reporting them) are marked closed and drop out of the queue. If one was elevated, it flips to Remediated on its risk.
- A finding already on a risk cannot be deleted or elevated again; it is that risk's evidence. Removing it from the risk, or deleting the risk, sends it back to the queue as New.

The **KEV past CISA due** tile on the dashboard counts open known-exploited findings past CISA's fix-by date, whatever their state in the queue.

---

# Part 3: Admins Only

## 14. User Management

Navigate to **Admin → User Management** in the left sidebar.

### Adding a User

Click **Add User**. Complete all fields: username, full name, email, role, and initial password.

The username is what the person types at login. Keep it lowercase and simple. Full name is what appears throughout the system. It must match what gets entered in Risk Owner and Action Owner fields on risk records, capitalization aside, because that match decides who gets notification email and which risks an Operator can edit.

Set the password to something temporary and communicate it through a secure channel. Remind the user to note it somewhere safe.

### Editing a User

Click the pencil icon on any user row. You can change the username, name, role, active status, and password. Email cannot be changed after the account is created. Leave the password field blank to leave it unchanged.

You cannot demote or deactivate the last active admin, and you cannot remove your own admin access. The system blocks both; ask another admin.

### Deactivating a User

Click the deactivate icon on a user row. The account is disabled, so the user cannot log in, but their name and any risks or audit entries they created remain intact. Do not ask for a hard delete; the system does not support it, by design. Deleting a user would corrupt audit trail references.

When someone leaves the organization or changes roles, deactivate first, then adjust role if needed. Do not share accounts.

### Passwords

Minimum length is 12 characters. There is no self-service reset. An admin sets a new temporary password through the edit form.

---

## 15. Lookup Lists

Navigate to **Admin → Settings** in the left sidebar.

Lookup lists control what appears in the dropdowns on the risk entry form. Four lists are configurable: Threat Actor Types, Attack Vectors, Threat Intel Sources, and Risk Owners.

### Risk Owners List: This One Matters Most

The Risk Owners list controls who appears in the Risk Owner dropdown when creating or editing a risk. Keep this list current with the people who are actually accountable for risks in your organization.

The names in this list need to match user Full Names in the system: same spelling, same middle initial. Capitalization and spaces at either end do not matter. When a notification triggers for an overdue action or review due, the system looks up the Risk Owner name against active users. A mismatch means the notification goes nowhere, and the owner cannot edit the risk if they are an Operator. Nobody sees an error; the administrator can find a warning in the application log.

### Adding a Value

Type the new entry in the Add field at the bottom of the relevant tab and click Add.

### Editing a Value

Click the pencil icon on any entry. Editing a value updates the list going forward. It does not change the stored value on any existing risk records that already have the old value. If you rename an owner, you will also need to update their name on existing risk records manually.

### Removing a Value

Click the trash icon. The value is soft-deleted: it disappears from the dropdown but is still stored on any existing risks. Risk records are not affected.

### Reordering

Use the up/down chevrons to control the order values appear in the dropdown.

---

## 16. Accepting and Closing Risks

Accepting and closing risks are decisions, not status changes. An Operator can set Status and Treatment on the risks they can edit; recording **who authorized an acceptance, and when**, is Admin-only. That sign-off is what carries the authority.

### Closing a Risk (Status: Closed)

Set the status to **Closed** when the risk has been fully remediated: the threat no longer exists or the vulnerability has been eliminated. Closed risks are excluded from overdue and notification logic.

If a closed risk becomes relevant again, reopen it by setting the status back to Open or In Progress. Do not create a new record for a risk that has already been through the register.

### Accepting a Risk (Treatment: Accept / Status: Accepted)

Setting treatment to **Accept** is a formal decision that the organization has assessed this risk, the residual score is known, and leadership has determined the risk is within acceptable bounds or not worth treating further. This is not the same as ignoring it.

Admins can complete two additional fields that document the authorization:

- **Acceptance Sign-Off By:** the name of the person authorizing the acceptance
- **Acceptance Sign-Off Date:** the date authorization was given

These fields create an accountable record. If a risk that was formally accepted later materializes, this record shows that the decision was deliberate and documented. That matters.

Do not mark a risk as Accepted because no one got around to treating it. Accept it when someone has reviewed it and made a conscious decision to carry the exposure.

### Generating a Risk Action Request

A Risk Action Request asks the CIO and CISO to mandate a course of action on one risk. The analysis is already done; the request lays out the options, marks the one we recommend, and gives both executives a place to sign the mandate.

Operators (on risks they can edit) and Admins generate one from the **Action Request** button on the risk detail page. It downloads as a `.zip` containing two Word documents:

- **Risk Action Request**, one page. It opens with the ask: what we are asking them to mandate, by when, and what happens if they do not. Then it follows Background, Issue, Options, Recommendation:
  1. **Background:** your background paragraph and a Risk at a Glance table.
  2. **Issue:** why this needs action now, as bullets.
  3. **Options:** four boxes (Mitigate, Accept, Avoid, Transfer), each worded as a mandate. The recommended one is marked ★ RECOMMENDED; any you mark not viable say why.
  4. **Recommendation:** the recommended option and steps, the accountable executive, who is responsible for delivery, and the funding and resources to authorize.

  Under that is the mandate block: a line for conditions or changes, the accountable executive, complete-by and review dates, and signature lines for the **CIO** and the **CISO**. The mandate stands when both have signed. The risk owner acknowledges it on the line below.
- **Supporting Evidence**, the full record behind the request: risk narrative, business impact, risk mechanics, the vulnerability evidence table, treatment options with pros and trade-offs, what the mandate covers, RACI, and the risk owner sign-off.

Everything the register already knows about the risk (scores, controls, treatment, owner, financial exposure, NIST CSF mapping, and vulnerability findings, see §12) is pulled in automatically; nothing is retyped. The form asks only for what belongs to this request: who it goes to (the CIO and CISO by default), the accountable executive, the date the mandate is needed by, priority, the ask in one paragraph and in one sentence (both drafted for you), background, the issue, the recommended steps, RACI, and a risk narrative. The form follows the same Background, Issue, Options, Recommendation order as the one-page request.

If the register's stored Treatment differs from what you are recommending, set **Recommended option** on the form. Both documents then show the register's value as the current treatment, not recommended, and your choice as the recommendation, rather than silently picking one. If Avoid or Transfer genuinely aren't options for this risk (a system that has to keep running, for instance), fill in why; that reason replaces the live checkbox with "not viable" on both documents.

Generating the request does not change the risk record or its status; it produces documents and adds one audit entry. Once the CIO and CISO have signed, come back and record what they mandated. If they mandated Accept, set Treatment to Accept and fill in the Acceptance Sign-Off fields above, so the register and the signed documents agree.

The old address, `/risks/<id>/decision-request`, redirects to the new one, so existing bookmarks still work.

### Deleting a Risk

Click **Delete** on the risk detail page. The risk itself is gone for good. Its trend log and audit entries are kept, with a final entry recording the deletion, but they no longer appear anywhere in the application; recovering them takes an administrator and the database. Any Spotlight findings on the risk go back to the queue as New. Use delete only for test records or obvious duplicates. For real risks that have been resolved, close them instead.

---

## 17. Database Backup and Restore

Navigate to **Admin → Settings → Database** tab.

### Downloading a Backup

Click **Download .db file**. The database downloads as a timestamped file (`risk_register_YYYYMMDD_HHMMSS.db`). Do this regularly: at minimum weekly, more often if the register is actively updated.

Store the file somewhere off the host: a network share, cloud storage, or your organization's backup system. A backup that lives only on the same server as the database is not a backup.

### Upgrade Backups

When Skerry is upgraded, the upgrade takes its own copy of the database on the server first. That copy exists to roll back an upgrade that goes wrong. It is not a substitute for downloading backups here. It lives on the same server, and it is only taken when someone upgrades.

### Importing a Database

The Import & Replace function uploads a `.db` file and replaces the live database with it. This is how you restore from backup or migrate data from another instance.

Before the replace happens, the system:

1. Validates the uploaded file is a real SQLite database
2. Checks that all required tables are present (a file from before the Spotlight ingest or the daily snapshot is accepted; those tables start empty)
3. Creates an automatic backup of the current database

After a successful import, the application reconnects to the new database without requiring a restart.

**Use this for:** restoring from backup, migrating from another host, loading a test database for validation.

**Do not use this casually.** Importing replaces everything: all risks, all users, all settings, the Spotlight queue, and the daily snapshot history. There is a confirmation prompt and an auto-backup, but there is no undo beyond restoring the auto-backup manually.

---

## Quick Reference: What Can Each Role Do?

| Action | Viewer | Operator | Admin |
|---|:---:|:---:|:---:|
| View all risks and reports | ✓ | ✓ | ✓ |
| Download Excel export | ✓ | ✓ | ✓ |
| View the Spotlight Ingest queue | ✓ | ✓ | ✓ |
| Create new risks | — | ✓ | ✓ |
| Edit risks they created or own: fields, status, treatment, CSF mapping, findings | — | ✓ | ✓ |
| Log reviews (trend log entries) on those risks | — | ✓ | ✓ |
| Generate a Risk Action Request for those risks | — | ✓ | ✓ |
| Set treatment to Accept, or status to Closed, on those risks | — | ✓ | ✓ |
| Elevate, triage, dismiss, delete, or restore Spotlight findings | — | ✓ | ✓ |
| Edit any risk | — | — | ✓ |
| Delete risks | — | — | ✓ |
| Sign off on risk acceptance | — | — | ✓ |
| Run a Spotlight sync | — | — | ✓ |
| Manage users | — | — | ✓ |
| Manage lookup lists | — | — | ✓ |
| Download / import database | — | — | ✓ |

---

*Questions about access or platform administration? Contact your risk register administrator.*
