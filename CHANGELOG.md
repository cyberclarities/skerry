# Changelog

Each release, newest first. The version shown under the logo in the app is
kept in `app/version.py`; see that file for how to release a new one.

## 1.4 (2026-11-04)

The first release with a version number. It shows under the logo in the
sidebar.

### Spotlight ingest
- **CVE view.** One row per CVE, longest-open first, showing CVEs open 60
  days or more by default. Review a CVE, then elevate it as one risk built
  from the CVE's own data.
- **Bulk delete by CVE.** Sort by product, keep the CVE you will track, and
  delete the rest. Only what the filters show is deleted.
- **Type filter** on the host, finding, and CVE views.
- **Manual sync runs in the background.** The page returns at once and
  refreshes until the sync finishes; a second sync is refused while one runs.
- **Fixed:** a CVE rescored below High was marked closed while still open,
  and shown Remediated on its risk. It now stays open.
- **Fixed:** deleting a risk, or removing a finding from one, left its
  Spotlight findings stuck as Elevated. They now return to the queue as New.
- **Fixed:** one record that failed to save could fail the whole sync.
- **Fixed:** large tenants could run the app out of memory.

### Register and dashboard
- **Register:** hide closed risks, filter on several statuses at once, and
  keep filters in the address so a refresh or bookmark keeps them.
- **Heat map:** one count per cell; hover for the split by rating.
- **Dashboard:** every figure counts active risks only, so the top row and
  the heat map agree.

### Exports
- **Risk Action Request** replaces the Decision Request. It asks the CIO and
  CISO to mandate a course of action: Background, Issue, Options,
  Recommendation, four mandate boxes, and signature lines for both. The
  signers can be changed per request.
- Both documents use the PB-000 template colors.

### Security
- Authlib 1.9.1 and dnspython 2.9.0. `pip-audit` reports no known
  vulnerabilities.

### Upgrading
- Rebuild: `docker compose up -d --build`. A restart alone does not pick up
  the new dependencies or templates.
- `GUNICORN_TIMEOUT` now defaults to 300. If your `.env` sets 1800 from the
  October stopgap, change it to 300 or remove the line.
