# Software Bill of Materials — Skerry

**SBOM Format:** SPDX 2.3 (tag-value schema, markdown rendering)
**SPDX Version:** SPDX-2.3
**Data License:** CC0-1.0
**Document Namespace:** skerry-sbom-v4
**Document Created:** 2026-07-08
**Document Updated:** 2026-11-09
**Creator:** Organization: CyberClarities
**Creator Tool:** `uv pip compile --universal --python-version 3.12 --generate-hashes` (requirements.lock), plus distribution metadata from PyPI

---

## Table of Contents

1. [Application Overview](#1-application-overview)
2. [Container Images](#2-container-images)
3. [Direct Python Dependencies](#3-direct-python-dependencies)
4. [Transitive Python Dependencies](#4-transitive-python-dependencies)
5. [Alpine Linux System Libraries](#5-alpine-linux-system-libraries)
6. [Front-End Libraries (CDN)](#6-front-end-libraries-cdn)
7. [Embedded / Bundled Data](#7-embedded--bundled-data)
8. [License Summary](#8-license-summary)
9. [Known Vulnerability Notes](#9-known-vulnerability-notes)
10. [Document History](#10-document-history)

---

## 1. Application Overview

| Field | Value |
|---|---|
| **PackageName** | skerry |
| **PackageVersion** | 1.8 |
| **PackageSupplier** | Organization: CyberClarities |
| **PackageHomePage** | internal |
| **PackageLicenseDeclared** | MIT |
| **PackageLicenseConcluded** | MIT |
| **FilesAnalyzed** | true |
| **PrimaryLanguage** | Python 3.12 |
| **Runtime** | Gunicorn 26 / Flask 3.1 |
| **Database** | SQLite 3 (embedded in Python stdlib) |
| **Containerization** | Docker Compose 2.x |
| **Reverse Proxy** | Caddy 2.11 (caddy:2.11-alpine) |

**Application components:**

| Component | Type | Description |
|---|---|---|
| app/__init__.py | Application factory | Flask app creation, blueprint registration, ProxyFix middleware, HSTS, APScheduler setup |
| app/config.py | Configuration | Environment-driven config class; refuses to boot on a placeholder SECRET_KEY |
| app/extensions.py | Wiring | Shared extension instances (login manager, CSRF, limiter) |
| app/models.py | Data layer | SQLAlchemy ORM: User, Risk, AuditLog, TrendLog, LookupItem, NISTCSFReference |
| app/scoring.py | Business logic | Inherent / residual score calculation, RAG thresholds, control reduction. The single source for the scoring math; `models.py` calls it |
| app/seed.py | Seed data | NIST CSF 2.0 subcategory data, default lookup values |
| app/email_utils.py | Notification | SMTP notification logic, APScheduler daily job at 07:00 |
| app/decorators.py | Authorization | Role enforcement decorators |
| app/action_request.py | Business logic | Builds the docxtpl render context for the per-risk Risk Action Request (.docx) |
| app/routes/auth_routes.py | Blueprint | Local auth, Azure AD OIDC login / callback, logout |
| app/routes/risk_routes.py | Blueprint | Risk CRUD, trend log, audit log |
| app/routes/dashboard_routes.py | Blueprint | Dashboard |
| app/routes/user_routes.py | Blueprint | User management (admin) |
| app/routes/report_routes.py | Blueprint | CSF coverage, overdue actions, trend reports |
| app/routes/export_routes.py | Blueprint | Excel (.xlsx) workbook export |
| app/routes/settings_routes.py | Blueprint | Lookup list management, database import / export |
| app/routes/ingest_routes.py | Blueprint | CrowdStrike Spotlight ingest queue: triage, elevation to risk, sync history |
| app/models_spotlight.py | Data layer | Spotlight staging tables: hosts, findings, elevations, sync runs |
| app/spotlight/ | Integration | Falcon API client, ingest normalizer, elevation, score suggestions |
| app/static/ | Brand assets | Favicon set, touch and PWA icons, and the Skerry mark (SVG) |
| scripts/build_exec_summary_template.py | Build script | Generates the one-page Risk Action Request .docx template consumed by docxtpl |
| scripts/build_supporting_evidence_template.py | Build script | Generates the Supporting Evidence .docx template consumed by docxtpl |
| scripts/upgrade.sh | Host script | Backs up, rebuilds on fresh base images, verifies, and rolls back an install. Runs on the Docker host; not in the image |
| docker-entrypoint.sh | Container entrypoint | Gives `/app/data` to the app user, then drops from root before Gunicorn starts |
| run.py | Entrypoint | Gunicorn WSGI entrypoint |

---

## 2. Container Images

| SPDXID | PackageName | Tag | Resolved on 2026-11-09 | Supplier | License | Source |
|---|---|---|---|---|---|---|
| SPDXRef-img-python | python | 3.12-alpine3.24 | Python 3.12.16 on Alpine 3.24 | Docker Official Images | PSF-2.0 | hub.docker.com/_/python |
| SPDXRef-img-caddy | caddy | 2.11-alpine | Caddy 2.11.9 on Alpine 3.24 | Caddy Maintainers | Apache-2.0 | hub.docker.com/_/caddy |

Both tags pin the minor release and move on patch rebuilds, so `--pull` brings Python
3.12.x, Caddy 2.11.x, and Alpine 3.24 security fixes. The resolved column comes from the
`docker-library/official-images` manifests. For what a given host is actually running,
`scripts/upgrade.sh` writes it to `state-after.txt` on every run. For a fully reproducible
image, pin by digest: `python@sha256:<digest>`.

**Alpine Linux base** (inherited by both images):

| Package | Version | License |
|---|---|---|
| Alpine Linux | 3.24.x | MIT |
| musl libc | per Alpine 3.24 | MIT |
| BusyBox | per Alpine 3.24 | GPL-2.0 |
| OpenSSL | per Alpine 3.24 | Apache-2.0 |

Exact versions of the base packages were not verified for this update; the Alpine
package index was not reachable. On a built image, `docker compose exec web apk info -v`
lists them.

---

## 3. Direct Python Dependencies

The 17 packages pinned in `requirements.txt`.

| SPDXID | PackageName | Version | License | Purpose |
|---|---|---|---|---|
| SPDXRef-flask | Flask | 3.1.3 | BSD-3-Clause | Web framework |
| SPDXRef-flask-sqlalchemy | Flask-SQLAlchemy | 3.1.1 | BSD-3-Clause | ORM integration |
| SPDXRef-flask-login | Flask-Login | 0.6.3 | MIT | Session / auth management |
| SPDXRef-flask-wtf | Flask-WTF | 1.3.0 | BSD-3-Clause | CSRF protection, form rendering |
| SPDXRef-flask-limiter | Flask-Limiter | 4.1.1 | MIT | Failed-login rate limiting on POST /login |
| SPDXRef-wtforms | WTForms | 3.3.2 | BSD-3-Clause | Form validation |
| SPDXRef-sqlalchemy | SQLAlchemy | 2.0.57 | MIT | ORM / database abstraction |
| SPDXRef-werkzeug | Werkzeug | 3.1.9 | BSD-3-Clause | WSGI utilities, ProxyFix middleware |
| SPDXRef-authlib | Authlib | 1.9.5 | BSD-3-Clause | OIDC / OAuth2 client (Entra ID SSO) |
| SPDXRef-requests | requests | 2.34.2 | Apache-2.0 | HTTP client (OIDC discovery, Falcon API) |
| SPDXRef-openpyxl | openpyxl | 3.1.5 | MIT | Excel (.xlsx) export |
| SPDXRef-docxtpl | docxtpl | 0.20.2 | LGPL-2.1 | Word (.docx) rendering for the Risk Action Request |
| SPDXRef-apscheduler | APScheduler | 3.11.3 | MIT | Background scheduler (daily email, snapshot, Spotlight sync) |
| SPDXRef-python-dotenv | python-dotenv | 1.2.4 | BSD-3-Clause | .env file loading |
| SPDXRef-email-validator | email-validator | 2.3.0 | Unlicense | Email address validation |
| SPDXRef-dnspython | dnspython | 2.9.2 | ISC | DNS for email-validator; pinned directly (CVE-2026-114605 floor) |
| SPDXRef-gunicorn | gunicorn | 26.2.0 | MIT | WSGI HTTP server |

---

## 4. Transitive Python Dependencies

The 24 packages pulled in by the direct dependencies above, 41 in total on Linux.
Generated from `requirements.lock`, which pins every package with hashes; the image
installs it with `pip install --require-hashes`, so this table is what a rebuild installs,
not a snapshot that drifts. Licenses are each distribution's own metadata, with "BSD
License" read as BSD-3-Clause.

`requirements.lock` also lists tzdata 2026.6 (Apache-2.0), required by tzlocal on Windows
only. It is not installed in the image and is not counted here.

| PackageName | Version | License | Required By |
|---|---|---|---|
| blinker | 1.9.0 | MIT | Flask |
| certifi | 2026.10.23 | MPL-2.0 | requests |
| cffi | 2.1.1 | MIT-0 | cryptography (on CPython) |
| charset-normalizer | 3.5.2 | MIT | requests |
| click | 8.5.1 | BSD-3-Clause | Flask |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | Authlib; joserfc |
| Deprecated | 3.0.1 | MIT | limits |
| et-xmlfile | 2.0.0 | MIT | openpyxl |
| greenlet | 3.5.6 | MIT AND PSF-2.0 | SQLAlchemy |
| idna | 3.20 | BSD-3-Clause | email-validator; requests |
| itsdangerous | 2.2.0 | BSD-3-Clause | Flask; Flask-WTF |
| Jinja2 | 3.1.6 | BSD-3-Clause | docxtpl; Flask |
| joserfc | 1.8.0 | BSD-3-Clause | Authlib |
| limits | 5.8.0 | MIT | Flask-Limiter |
| lxml | 6.1.3 | BSD-3-Clause | docxtpl; python-docx |
| MarkupSafe | 3.0.4 | BSD-3-Clause | Flask; Jinja2; Werkzeug; WTForms |
| ordered-set | 4.1.0 | MIT | Flask-Limiter |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | limits |
| pycparser | 3.12 | BSD-3-Clause | cffi (on CPython) |
| python-docx | 1.2.0 | MIT | docxtpl |
| typing-extensions | 4.16.0 | PSF-2.0 | Flask-Limiter; limits; python-docx; SQLAlchemy |
| tzlocal | 5.4.5 | MIT | APScheduler |
| urllib3 | 2.8.0 | MIT | requests |
| wrapt | 2.5.2 | BSD-2-Clause | Deprecated |

---

## 5. Alpine Linux System Libraries

Installed via `apk add` in the `web` container Dockerfile, from the Alpine 3.24 branch.

| PackageName | Alpine Package | License | Purpose |
|---|---|---|---|
| libffi | libffi | MIT | Foreign function interface (required by cffi / cryptography, used via Authlib for OIDC) |
| curl | curl | curl | Health check probe in docker-compose |
| su-exec | su-exec | MIT | Lets the entrypoint drop from root to the app user |

> **Version note:** Alpine package versions resolve at image build time from the pinned
> Alpine branch, so they track that branch's security updates. That is intended.

**Build-time only (removed after pip install):**

| PackageName | Alpine Package | License | Purpose |
|---|---|---|---|
| GCC | gcc | GPL-3.0 | C compiler, used only if a package has no prebuilt wheel |
| musl-dev | musl-dev | MIT | C headers |
| libffi-dev | libffi-dev | MIT | FFI headers |

Every package in `requirements.lock` has a prebuilt musllinux wheel for x86_64 and aarch64
(checked 2026-11-09), so the compiler is not used on a normal build.

---

## 6. Front-End Libraries (CDN)

Loaded at runtime from CDN. Not bundled in the container image — they require outbound
internet access from the client browser.

| PackageName | Version | License | CDN URL | Purpose |
|---|---|---|---|---|
| Bootstrap | 5.3.8 | MIT | cdn.jsdelivr.net/npm/bootstrap@5.3.8 | UI framework |
| Bootstrap Icons | 1.13.2 | MIT | cdn.jsdelivr.net/npm/bootstrap-icons@1.13.2 | Icon font |
| Chart.js | 4.6.1 | MIT | cdn.jsdelivr.net/npm/chart.js@4.6.1/dist/chart.umd.js | Dashboard charts |
| htmx | 1.9.12 | BSD-2-Clause | cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js | Partial-page updates |

> **Integrity note:** Every tag carries an `integrity="sha384-..."` hash and
> `crossorigin="anonymous"`, so a modified file is refused by the browser. The hashes
> were computed from the npm package of each version (`npm pack`); the Bootstrap values
> match the ones Bootstrap publishes. A version bump needs new hashes.
> The pages still depend on the CDN being reachable; for air-gapped deployments, vendor
> the files under `app/static/vendor/` and update the tags.

htmx 1.9.12 is the last 1.x release (April 2024); 2.x is current. The move is tracked
separately because it changes page behavior.

---

## 7. Embedded / Bundled Data

| Component | Source | License | Notes |
|---|---|---|---|
| NIST CSF 2.0 subcategory definitions | NIST CSF 2.0 public framework | Public Domain (U.S. Government work) | Seeded into the `nist_csf_reference` table at first start via `app/seed.py` |
| Default lookup list values | Internal (CyberClarities) | MIT | Threat actor types, attack vectors, threat intel sources seeded into `lookup_items` |
| Skerry brand assets | Internal (CyberClarities) | MIT | `app/static/` — favicon set (SVG + ICO), apple-touch and PWA icons, and the mark in light and dark variants |
| SQLite | Python stdlib (`sqlite3` module) | Public Domain | Embedded database engine; no separate install |

---

## 8. License Summary

Counted across every component listed in this document — 61 in total.

| License | Count |
|---|---|
| MIT | 26 |
| BSD-3-Clause | 15 |
| Apache-2.0 | 3 |
| BSD-2-Clause | 2 |
| PSF-2.0 | 2 |
| Public Domain | 2 |
| Apache-2.0 OR BSD-2-Clause | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| GPL-2.0 | 1 |
| GPL-3.0 | 1 |
| ISC | 1 |
| LGPL-2.1 | 1 |
| MIT AND PSF-2.0 | 1 |
| MIT-0 | 1 |
| MPL-2.0 | 1 |
| Unlicense | 1 |
| curl | 1 |

No GPL-licensed component is linked into the application at runtime. BusyBox is part of
the Alpine base OS and is neither imported nor executed by the application; GCC is a
build-time package removed from the final image. docxtpl (LGPL-2.1) is used as a Python
library — imported, not modified or statically linked — which satisfies LGPL terms for
dynamic use.

Dual-licensed packages (`cryptography`, `packaging`) are counted once, under the
expression their own metadata declares.

---

## 9. Known Vulnerability Notes

This document is a point-in-time reference, not a scan result. On 2026-11-09, `pip-audit`
against `requirements.lock` and `npm audit` against the four front-end packages reported
no known vulnerabilities. Run a current scan against the deployed image before each
production release.

**Recommended tools:**

- `pip-audit` — Python packages against the OSV / PyPI Advisory Database
- `grype` or `trivy` — container image layers, including Alpine packages
- `syft` — machine-readable SPDX or CycloneDX SBOM from the live image

```bash
# Scan Python dependencies (every pinned package, transitive ones included)
pip-audit -r requirements.lock --disable-pip --no-deps

# Scan the container image (requires Docker)
trivy image skerry-web:latest

# Generate a machine-readable SBOM from the live image
syft skerry-web:latest -o spdx-json > sbom.spdx.json
```

> Compose names the image after the install folder: `skerry-web` for a folder named
> `skerry`. `docker compose images` shows the exact name.

The advisory feed can lag a release. Authlib's four security releases of 2026-11-01 to
2026-11-05 were not in it when they shipped. Read the changelogs of anything on the
sign-in path, not only the scanner output.

**Front-end CVE tracking:** Bootstrap, Bootstrap Icons, Chart.js, and htmx load from CDN
and are invisible to container image scanners. Track them separately.

---

## 10. Document History

| Date | Change |
|---|---|
| 2026-07-08 | Initial SBOM, v2.0 of the application. |
| 2026-08-11 | Removed WeasyPrint and its Alpine runtime libraries (Pango, Cairo, GDK-PixBuf, HarfBuzz, Fontconfig, ttf-dejavu). Added docxtpl for the Decision / Acceptance Form export. |
| 2026-08-11 | Version bump to 4.0 and rename to Skerry. Corrected three packages listed as dependencies that pip does not install (oauthlib, PyJWT, python-dateutil). Added the nine-package Flask-Limiter subtree, which was absent. Refreshed all transitive versions and licences from distribution metadata. |
| 2026-10-16 | Security fixes from the pre-push review. Bumped Flask 3.1.0 → 3.1.3, Werkzeug 3.1.3 → 3.1.9, Authlib 1.3.2 → 1.6.12, requests 2.32.3 → 2.33.0, python-dotenv 1.0.1 → 1.2.2; `pip-audit` reports no known vulnerabilities in the direct dependencies. Added su-exec. Added subresource integrity to the CDN assets and moved htmx from unpkg to jsDelivr. Added the Spotlight components to the component list. Section 4 was **not** regenerated in this update; its transitive versions are still the 2026-08-11 resolution and may differ from what the bumped packages pull in. |
| 2026-11-03 | Security fixes from the 2026-11-03 review. Bumped Authlib 1.6.12 → 1.9.1 and pinned dnspython 2.9.0, which clears CVE-2026-114605; `pip-audit` reports no known vulnerabilities. dnspython 2.9 requires Python 3.11 or newer; the container runs 3.12. Section 4 was updated for these two packages only. |
| 2026-11-04 | The per-risk export was renamed from Decision / Acceptance Form to Risk Action Request; `app/decision_request.py` became `app/action_request.py`. No dependency change. |
| 2026-11-04 | Application version set to 1.4, now shown in the app and kept in `app/version.py`. This replaces the 4.0 recorded here on 2026-08-11; the numbering restarts by the owner's decision, and `CHANGELOG.md` records each release from 1.4 on. |

| 2026-11-04 to 2026-11-05 | Releases 1.5 through 1.7.4. No dependency change. |
| 2026-11-09 | Release 1.8, from the 2026-11-06 dependency review. Authlib 1.9.5, gunicorn 26.2.0, dnspython 2.9.2, SQLAlchemy 2.0.57, Flask-Limiter 4.1.1, docxtpl 0.20.2, APScheduler 3.11.3, WTForms 3.3.2, Flask-WTF 1.3.0, requests 2.34.2, email-validator 2.3.0, python-dotenv 1.2.4. Eight packages left the image (rich, markdown-it-py, mdurl, Pygments, pytz, six, docxcompose, babel); joserfc, which Authlib needs, was missing and is added. Added `requirements.lock`; section 4 is now generated from it. Images pinned to `python:3.12-alpine3.24` and `caddy:2.11-alpine`; Alpine 3.21, recorded here before, is out of support. Bootstrap 5.3.8, Bootstrap Icons 1.13.2, Chart.js 4.6.1. Added `scripts/upgrade.sh`. The scan commands use the image name Compose gives a `skerry` folder. |
---

*Regenerate after any change to `requirements.txt`, `requirements.lock`, the image tags,
or the CDN tags. Section 4 comes from `requirements.lock`; sections 2 and 5 resolve at
build time within the pinned Alpine branch.*
