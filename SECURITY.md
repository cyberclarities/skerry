# Security

## Reporting a vulnerability

Do not open a public issue for a security problem.

Report it privately through GitHub's **Security → Report a vulnerability**
advisory workflow on this repository. Include what you found, how to reproduce
it, and what you believe the impact is. You will get an acknowledgment within
five business days.

This is a small project maintained alongside other work. Fixes for anything
that lets an unauthenticated user in, or lets one role act as another, take
priority over everything else.

## Supported versions

The `main` branch is the supported version. There is no backport branch.

## Security posture

What the application does today. Each item marked *(tested)* has a regression
test in `tests/test_security_fixes.py`.

- Passwords hashed with Werkzeug's `generate_password_hash` (scrypt, the
  Werkzeug 3 default), minimum 12 characters on both create and change, and
  used exactly as typed *(tested)*
- Changing a user's password ends every session and remember-me cookie issued
  before the change *(tested)*
- CSRF protection on every state-changing form, including HTMX requests
- Session and remember-me cookies marked `Secure`, `HttpOnly`, `SameSite=Lax`
  by default; `Secure` is opt-out for local HTTP development only
- Failed-login throttling per source IP, failed attempts written to the log
  with username and source address, and equal-cost checks for unknown
  usernames so response timing does not reveal which accounts exist
- `SECRET_KEY` is required at startup; the application refuses to boot on an
  empty or placeholder value
- Bootstrap admin password is randomly generated when not supplied, and printed
  once to the startup log
- Role-based access control at the route level: viewer, operator, admin.
  Operators can change only risks they created or own, and that one rule
  covers editing, trend entries, vulnerability findings, and Decision Request
  exports *(tested)*. Deleting a risk is admin-only *(tested)*
- Field-level audit log on every risk change. The log is not deleted with the
  risk, and the deletion itself is recorded *(tested)*
- Redirect targets (`next` on login, `back` on the ingest queue) are limited
  to paths on this host *(tested)*
- Stored values are never placed inside inline JavaScript; confirmation prompts
  read their text from a `data-confirm` attribute *(tested)*
- Excel exports store every value as text, so a field starting with `=` cannot
  run as a formula in the reader's spreadsheet *(tested)*
- Notification email goes only to active users, matched exactly by name or
  email; an owner field cannot route risk details to an outside address
  *(tested)*. SMTP connections verify the server certificate *(tested)*
- Front-end libraries load with subresource integrity hashes, so a modified
  CDN response is refused by the browser *(tested)*
- The container runs as an unprivileged user (uid 10001), and `.dockerignore`
  keeps `.env` and the database out of the image *(tested)*
- Security response headers: `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, and HSTS when the request arrived
  over TLS
- Optional Azure AD / OIDC SSO with group-to-role mapping, which denies login
  outright when group restrictions are configured and the user matches none.
  An SSO identity is bound to an existing account only when the provider
  asserts `email_verified`, and never re-pointed once bound *(tested)*
- The Falcon Spotlight client verifies TLS, never logs the API secret, and
  refuses a `FALCON_BASE_URL` that is not HTTPS on a CrowdStrike API host
  *(tested)*
- Database download and import are written to the application log with the
  admin's identity and source address

## Known limitations

These are real and unaddressed. They are listed so nobody has to discover them
in production.

### Deployment model

The shipped `docker-compose.yml` runs a single Gunicorn worker. That is not
incidental; the notification scheduler runs in-process, and the login throttle
counts in memory. A second worker means duplicate notification emails and
throttle counters that each see a fraction of the traffic. Before scaling out,
move the scheduler to an external trigger and point `RATELIMIT_STORAGE_URI` at
a shared backend.

The non-root container needs to own its data directory. On a host that ran an
earlier image, `./data` is owned by root; run `sudo chown -R 10001:10001 ./data`
once before starting the new image, or the app cannot open its database.

`ProxyFix` trusts one layer of `X-Forwarded-For`. That is correct only while
the `web` service publishes no ports and every request arrives through Caddy.
Publishing the app port directly would let a client spoof its address and
sidestep the login throttle.

### SSO account linking

Microsoft Entra ID does not send an `email_verified` claim, so an existing
local account cannot be linked to SSO automatically. A user who already has a
local account sees a message to contact an administrator, and there is no
admin screen for linking yet; today it means setting `users.oidc_sub` in the
database. New SSO users are unaffected.

### Content Security Policy

There is no CSP header. Templates rely on inline `<script>` blocks, so adding
one means either nonces or extracting that JavaScript to static files first.

### Front-end supply chain

Bootstrap, Bootstrap Icons, htmx, and Chart.js still load from jsDelivr. The
integrity hashes stop a modified file from running, but they do not keep the
pages working if the CDN is down or blocked. Vendoring the files locally
removes that dependency. A version bump means new hashes: compute them from the
npm package (`npm pack <name>@<version>`) rather than copying them from a
third-party page.

### Database import

An admin can upload a SQLite file that replaces the live database. The upload
is validated for SQLite magic bytes and required tables, and the existing
database is backed up first. But this is still an admin handing the
application a new user table, including new password hashes. Treat admin
access as equivalent to database access. Backup files accumulate in the data
directory with no automatic pruning.

### Authorization gaps

Operator edit rights on a risk are decided partly by string-matching the
operator's display name against the risk owner field. Two users with the same
display name would inherit each other's edit rights.

### Audit trail

Database downloads and imports are recorded in the application log, not in the
audit table, because the audit table is keyed to a risk. Keep the container
logs if you need that record.

### Scale

List, dashboard, and report views load the entire register and filter in
Python. There is no pagination and no query-level filtering on computed fields
such as RAG status. This is a performance ceiling, not a correctness problem.

## Testing

`python -m pytest tests/ -q` runs the suite: the Spotlight ingest tests, a
smoke test that boots the real app factory and renders every page, and the
security regression tests named above. It needs no network access and no
CrowdStrike credentials. Two things it does not cover: a live sign-in against
a real identity provider, and a real `docker compose up`. Check both by hand
after changing authentication or the container.
