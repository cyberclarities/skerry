# Software Bill of Materials — Skerry

**SBOM Format:** SPDX 2.3 (tag-value schema, markdown rendering)
**SPDX Version:** SPDX-2.3
**Data License:** CC0-1.0
**Document Namespace:** skerry-sbom-v4
**Document Created:** 2026-07-08
**Document Updated:** 2026-08-11
**Creator:** Organization: CyberClarities
**Creator Tool:** pip install --dry-run --python-version 3.12 --report, plus distribution metadata

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
| **PackageVersion** | 4.0 |
| **PackageSupplier** | Organization: CyberClarities |
| **PackageHomePage** | internal |
| **PackageLicenseDeclared** | MIT |
| **PackageLicenseConcluded** | MIT |
| **FilesAnalyzed** | true |
| **PrimaryLanguage** | Python 3.12 |
| **Runtime** | Gunicorn 22 / Flask 3.1 |
| **Database** | SQLite 3 (embedded in Python stdlib) |
| **Containerization** | Docker Compose 2.x |
| **Reverse Proxy** | Caddy (caddy:alpine) |

**Application components:**

| Component | Type | Description |
|---|---|---|
| app/__init__.py | Application factory | Flask app creation, blueprint registration, ProxyFix middleware, HSTS, APScheduler setup |
| app/config.py | Configuration | Environment-driven config class; refuses to boot on a placeholder SECRET_KEY |
| app/extensions.py | Wiring | Shared extension instances (login manager, CSRF, limiter) |
| app/models.py | Data layer | SQLAlchemy ORM: User, Risk, AuditLog, TrendLog, LookupItem, NISTCSFReference |
| app/scoring.py | Business logic | Inherent / residual score calculation, RAG thresholds, control reduction, risk ID formatting |
| app/seed.py | Seed data | NIST CSF 2.0 subcategory data, default lookup values |
| app/email_utils.py | Notification | SMTP notification logic, APScheduler daily job at 07:00 |
| app/decorators.py | Authorization | Role enforcement decorators |
| app/decision_request.py | Business logic | Builds the docxtpl render context for the per-risk Decision / Acceptance Form (.docx) |
| app/routes/auth_routes.py | Blueprint | Local auth, Azure AD OIDC login / callback, logout |
| app/routes/risk_routes.py | Blueprint | Risk CRUD, trend log, audit log |
| app/routes/dashboard_routes.py | Blueprint | Dashboard, health endpoint |
| app/routes/user_routes.py | Blueprint | User management (admin) |
| app/routes/report_routes.py | Blueprint | CSF coverage, overdue actions, trend reports |
| app/routes/export_routes.py | Blueprint | Excel (.xlsx) workbook export |
| app/routes/settings_routes.py | Blueprint | Lookup list management, database import / export |
| app/static/ | Brand assets | Favicon set, touch and PWA icons, and the Skerry mark (SVG) |
| scripts/build_decision_request_template.py | Build script | Generates the .docx template consumed by docxtpl |
| run.py | Entrypoint | Gunicorn WSGI entrypoint |

---

## 2. Container Images

| SPDXID | PackageName | Version | Supplier | License | Source |
|---|---|---|---|---|---|
| SPDXRef-img-python | python | 3.12-alpine | Docker Official Images | PSF-2.0 | hub.docker.com/_/python |
| SPDXRef-img-caddy | caddy | latest (alpine tag) | Caddy Maintainers | Apache-2.0 | hub.docker.com/_/caddy |

> **Note:** `caddy:alpine` resolves to the latest stable Caddy release on Alpine Linux at pull time. For reproducible builds, pin to a digest: `caddy@sha256:<digest>`.

**Alpine Linux base** (inherited by both images):

| Package | Version | License |
|---|---|---|
| Alpine Linux | 3.21.x | MIT |
| musl libc | 1.2.x | MIT |
| BusyBox | 1.37.x | GPL-2.0 |
| OpenSSL | 3.x | Apache-2.0 |

---

## 3. Direct Python Dependencies

The 16 packages declared in `requirements.txt`.

| SPDXID | PackageName | Version | License | Purpose |
|---|---|---|---|---|
| SPDXRef-flask | Flask | 3.1.0 | BSD-3-Clause | Web framework |
| SPDXRef-flask-sqlalchemy | Flask-SQLAlchemy | 3.1.1 | BSD-3-Clause | ORM integration |
| SPDXRef-flask-login | Flask-Login | 0.6.3 | MIT | Session / auth management |
| SPDXRef-flask-wtf | Flask-WTF | 1.2.2 | BSD-3-Clause | CSRF protection, form rendering |
| SPDXRef-flask-limiter | Flask-Limiter | 3.8.0 | MIT | Failed-login rate limiting on POST /login |
| SPDXRef-wtforms | WTForms | 3.2.1 | BSD-3-Clause | Form validation |
| SPDXRef-sqlalchemy | SQLAlchemy | 2.0.36 | MIT | ORM / database abstraction |
| SPDXRef-werkzeug | Werkzeug | 3.1.3 | BSD-3-Clause | WSGI utilities, ProxyFix middleware |
| SPDXRef-authlib | Authlib | 1.3.2 | BSD-3-Clause | OIDC / OAuth2 client (Azure AD SSO) |
| SPDXRef-requests | requests | 2.32.3 | Apache-2.0 | HTTP client (OIDC discovery) |
| SPDXRef-openpyxl | openpyxl | 3.1.5 | MIT | Excel (.xlsx) export |
| SPDXRef-docxtpl | docxtpl | 0.19.1 | LGPL-2.1 | Word (.docx) rendering for the Decision / Acceptance Form |
| SPDXRef-apscheduler | APScheduler | 3.10.4 | MIT | Background scheduler (daily email notifications) |
| SPDXRef-python-dotenv | python-dotenv | 1.0.1 | BSD-3-Clause | .env file loading |
| SPDXRef-email-validator | email-validator | 2.2.0 | Unlicense | Email address validation |
| SPDXRef-gunicorn | gunicorn | 22.0.0 | MIT | WSGI HTTP server |

---

## 4. Transitive Python Dependencies

The 32 packages pip installs to satisfy the direct dependencies above —
48 in total. Versions are the resolution for Python 3.12 on
2026-08-11; licences are read from each distribution's own metadata.

Version pinning applies to `requirements.txt` only, so a rebuild resolves transitive
versions afresh. Treat the versions in this section as the state on the document date,
not as a lock. If you need reproducibility, generate a hash-pinned lock file and say so
here.

### 4.1 Flask ecosystem

| PackageName | Version | License | Required By |
|---|---|---|---|
| Jinja2 | 3.1.6 | BSD-3-Clause | Flask; docxtpl |
| MarkupSafe | 3.0.3 | BSD-3-Clause | Jinja2 |
| itsdangerous | 2.2.0 | BSD-3-Clause | Flask (sessions) |
| click | 8.4.2 | BSD-3-Clause | Flask (CLI) |
| blinker | 1.9.0 | MIT | Flask (signals) |
| greenlet | 3.5.5 | MIT AND PSF-2.0 | SQLAlchemy |

### 4.2 Flask-Limiter

| PackageName | Version | License | Required By |
|---|---|---|---|
| limits | 5.8.0 | MIT | Flask-Limiter (storage backends, rate parsing) |
| ordered-set | 4.1.0 | MIT | Flask-Limiter |
| rich | 13.9.4 | MIT | Flask-Limiter (console output) |
| markdown-it-py | 4.2.0 | MIT | rich |
| mdurl | 0.1.2 | MIT | markdown-it-py |
| Pygments | 2.20.0 | BSD-2-Clause | rich |
| Deprecated | 1.3.1 | MIT | limits |
| wrapt | 2.3.0 | BSD-2-Clause | Deprecated |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | limits |

### 4.3 Authlib / OIDC

| PackageName | Version | License | Required By |
|---|---|---|---|
| cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause | Authlib (TLS / JWK) |
| cffi | 2.1.1 | MIT-0 | cryptography |
| pycparser | 3.0 | BSD-3-Clause | cffi |

### 4.4 requests

| PackageName | Version | License | Required By |
|---|---|---|---|
| certifi | 2026.7.22 | MPL-2.0 | requests (CA bundle) |
| charset-normalizer | 3.4.9 | MIT | requests |
| idna | 3.18 | BSD-3-Clause | requests; email-validator |
| urllib3 | 2.7.0 | MIT | requests |

### 4.5 docxtpl

| PackageName | Version | License | Required By |
|---|---|---|---|
| python-docx | 1.2.0 | MIT | docxtpl (.docx read/write) |
| docxcompose | 2.2.0 | MIT | docxtpl (subdocument composition) |
| lxml | 6.1.1 | BSD-3-Clause | docxtpl; python-docx; docxcompose |
| babel | 2.18.0 | BSD-3-Clause | docxcompose (i18n utilities) |
| typing_extensions | 4.16.0 | PSF-2.0 | python-docx; SQLAlchemy; Flask-Limiter |

### 4.6 openpyxl

| PackageName | Version | License | Required By |
|---|---|---|---|
| et_xmlfile | 2.0.0 | MIT | openpyxl |

### 4.7 APScheduler

| PackageName | Version | License | Required By |
|---|---|---|---|
| pytz | 2026.3.post1 | MIT | APScheduler (timezone handling) |
| tzlocal | 5.4.4 | MIT | APScheduler |
| six | 1.17.0 | MIT | APScheduler |

### 4.8 email-validator

| PackageName | Version | License | Required By |
|---|---|---|---|
| dnspython | 2.8.0 | ISC | email-validator |

---

## 5. Alpine Linux System Libraries

Installed via `apk add` in the `web` container Dockerfile.

| PackageName | Alpine Package | License | Purpose |
|---|---|---|---|
| libffi | libffi | MIT | Foreign function interface (required by cffi / cryptography, used via Authlib for OIDC) |
| curl | curl | curl | Health check probe in docker-compose |

> **Version note:** Alpine package versions resolve at image build time from the Alpine
> package index. To lock them, use `apk add libffi=<version>` and commit the exact
> version string to the Dockerfile.

**Build-time only (removed after pip install):**

| PackageName | Alpine Package | License | Purpose |
|---|---|---|---|
| GCC | gcc | GPL-3.0 | C compiler for cffi / cryptography wheels |
| musl-dev | musl-dev | MIT | C headers |
| libffi-dev | libffi-dev | MIT | FFI headers |

---

## 6. Front-End Libraries (CDN)

Loaded at runtime from CDN. Not bundled in the container image — they require outbound
internet access from the client browser.

| PackageName | Version | License | CDN URL | Purpose |
|---|---|---|---|---|
| Bootstrap | 5.3.3 | MIT | cdn.jsdelivr.net/npm/bootstrap@5.3.3 | UI framework |
| Bootstrap Icons | 1.11.3 | MIT | cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3 | Icon font |
| Chart.js | 4.4.4 | MIT | cdn.jsdelivr.net/npm/chart.js@4.4.4 | Dashboard charts |
| htmx | 1.9.12 | BSD-2-Clause | unpkg.com/htmx.org@1.9.12 | Partial-page updates |

> **Integrity note:** These tags carry no `integrity="sha384-..."` attribute, so a
> compromised CDN would be served and executed without complaint. For air-gapped or
> high-assurance deployments, vendor the files under `app/static/vendor/` and update the
> `<script>` / `<link>` tags in `app/templates/base.html`.

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

Counted across every component listed in this document — 66 in total.

| License | Count |
|---|---|
| MIT | 30 |
| BSD-3-Clause | 15 |
| Apache-2.0 | 3 |
| BSD-2-Clause | 3 |
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

This document is a point-in-time reference, not a scan result. Run a current scan against
the deployed image before each production release.

**Recommended tools:**

- `pip-audit` — Python packages against the OSV / PyPI Advisory Database
- `grype` or `trivy` — container image layers, including Alpine packages
- `syft` — machine-readable SPDX or CycloneDX SBOM from the live image

```bash
# Scan Python dependencies
pip-audit -r requirements.txt

# Scan container image (requires Docker)
trivy image risk-register-web:latest

# Generate a machine-readable SBOM from the live image
syft risk-register-web:latest -o spdx-json > sbom.spdx.json
```

> The image tag is still `risk-register-web` because Compose derives it from the project
> directory, which keeps its original name so the existing named volumes — and Caddy's
> issued certificates — survive. The application is Skerry; the image tag is a path.

**Front-end CVE tracking:** Bootstrap, Bootstrap Icons, Chart.js, and htmx load from CDN
and are invisible to container image scanners. Track them separately.

---

## 10. Document History

| Date | Change |
|---|---|
| 2026-07-08 | Initial SBOM, v2.0 of the application. |
| 2026-08-11 | Removed WeasyPrint and its Alpine runtime libraries (Pango, Cairo, GDK-PixBuf, HarfBuzz, Fontconfig, ttf-dejavu). Added docxtpl for the Decision / Acceptance Form export. |
| 2026-08-11 | Version bump to 4.0 and rename to Skerry. Corrected three packages listed as dependencies that pip does not install (oauthlib, PyJWT, python-dateutil). Added the nine-package Flask-Limiter subtree, which was absent. Refreshed all transitive versions and licences from distribution metadata. |

---

*Regenerate after any dependency change, base image rebuild, or Alpine package version
change. The versions in section 4 were resolved on 2026-08-11 and will drift on the next
rebuild unless you pin them.*
