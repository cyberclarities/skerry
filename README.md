# Skerry

A self-hosted cybersecurity risk register for small security programs. Flask,
SQLite, and a container you can stand up on one host in an afternoon.

A skerry is a rock lying just under the surface, charted. The hazard does not go
away because you drew it on the map; what changes is that you know where it sits
and you steer accordingly.

Most teams run their risk register in a spreadsheet. That works right up until
two people open it at once, or an auditor asks who changed a residual score in
March and why. This is the same register with an audit trail, a review history,
and role-based access underneath it — not a platform, and not trying to be one.

## What it does

- **Risk records** with inherent and residual scoring, control effectiveness,
  velocity, detection capability, and financial exposure ranges
- **NIST CSF 2.0 mapping** at function, category, and subcategory level, with a
  coverage report that shows where you have nothing recorded
- **Audit log** — every field change, who made it, when, old value and new
- **Trend log** — residual score over time per risk, with change against prior
- **Dashboard** — RAG counts, likelihood/impact heat map, overdue actions,
  control test results, threat actor and category breakdowns
- **Exports** — formatted Excel workbook, and a per-risk Decision / Acceptance
  form (.docx) for routing to leadership and signature
- **Email notifications** — daily overdue, review-due, and board escalation
  notices (optional; off unless SMTP is configured)
- **Access control** — viewer, operator, and admin roles, with local accounts or
  Azure AD / OIDC single sign-on and group-to-role mapping

## Requirements

Docker and Docker Compose. That is the whole list for the supported path.

For local development without containers: Python 3.12. No extra system
libraries are required.

## Getting started

```bash
git clone <your-repo-url> risk-register
cd risk-register
cp .env.example .env
```

Generate a signing key and put it in `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

`SECRET_KEY` is required. The application refuses to start without one, and
refuses to start on a known placeholder value. A predictable signing key means
a forgeable session cookie, so this is a hard stop rather than a log warning.

Set `SERVER_NAME` and `BASE_URL` to the hostname you will actually serve, then:

```bash
docker compose up -d --build
```

Caddy terminates TLS and reverse-proxies to Gunicorn. On first boot the
application creates a bootstrap admin. If you left `ADMIN_PASSWORD` blank, a
strong random password is generated and printed **once** to the startup log:

```bash
docker compose logs web | grep -A4 "Bootstrap admin created"
```

Sign in, change that password, and clear it from your logs.

For plain-HTTP local development, set `SESSION_COOKIE_SECURE=false` in `.env`.
Session cookies are marked `Secure` by default and will not be sent over HTTP.
Set it back for anything anyone else can reach.

## Documentation

| Document | Audience |
|---|---|
| [`SETUP.md`](SETUP.md) | Getting a first instance running |
| [`ADMIN_GUIDE.md`](ADMIN_GUIDE.md) | Configuration, SSO, SMTP, backup and restore, user management |
| [`USER_GUIDE.md`](USER_GUIDE.md) | Day-to-day use — creating risks, scoring, reviews, reports |
| [`SBOM.md`](SBOM.md) | Software bill of materials, SPDX 2.3 |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability, and the known limitations below |

## Scoring model

Inherent score is likelihood times impact, both on a 1–5 scale. Residual score
applies a reduction based on recorded control effectiveness:

| Effectiveness | Reduction |
|---|---|
| 1 — Minimal | 10% |
| 2 — Low | 25% |
| 3 — Moderate | 35% |
| 4 — High | 50% |
| 5 — Full | 65% |

RAG bands and the risk appetite threshold are configurable in `.env`. The
defaults are red at 15, amber at 9, and appetite exceeded above 8.

A word on what those reductions are: they are a defensible convention, not a
measurement. If your organization has calibrated numbers, change them in
`app/scoring.py` and `app/models.py` and document why.

## Known limitations

Stated plainly, because you should know these before you put real risk data in
it. Fuller detail is in [`SECURITY.md`](SECURITY.md).

- **Single-worker by design.** The scheduler runs in-process and the login
  throttle counts in memory. Running more than one Gunicorn worker duplicates
  notification emails and splits the throttle counters. Scaling out means
  moving both to shared backends first.
- **SQLite.** Correct for a few dozen concurrent users and one host. Not a
  clustered database.
- **No pagination.** List, dashboard, and report views load the full register
  and filter in Python. Comfortable in the hundreds of risks; it will drag well
  before it breaks.
- **Front-end libraries load from public CDNs** without subresource integrity
  hashes. Vendor them locally if your threat model includes CDN compromise.
- **The container runs as root.** Fine behind Caddy on a host you control;
  worth changing before you expose it more widely.
- **No automated test suite yet.** Changes are verified by hand.

## Contributing

Issues and pull requests are welcome. If you are reporting a security problem,
read [`SECURITY.md`](SECURITY.md) first and do not open a public issue.

## License

MIT. See [`LICENSE`](LICENSE).
