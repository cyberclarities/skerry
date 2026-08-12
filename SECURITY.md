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

What the application does today:

- Passwords hashed with Werkzeug's `generate_password_hash` (PBKDF2-SHA256),
  minimum 12 characters, enforced on both create and change
- CSRF protection on every state-changing form, including HTMX requests
- Session and remember-me cookies marked `Secure`, `HttpOnly`, `SameSite=Lax`
  by default; `Secure` is opt-out for local HTTP development only
- Failed-login throttling per source IP, and failed attempts written to the log
  with username and source address
- `SECRET_KEY` is required at startup — the application refuses to boot on an
  empty or placeholder value
- Bootstrap admin password is randomly generated when not supplied, and printed
  once to the startup log
- Role-based access control at the route level: viewer, operator, admin
- Field-level audit log on every risk change
- Security response headers: `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, and HSTS when the request arrived
  over TLS
- Optional Azure AD / OIDC SSO with group-to-role mapping, which denies login
  outright when group restrictions are configured and the user matches none

## Known limitations

These are real and unaddressed. They are listed so nobody has to discover them
in production.

### Deployment model

The shipped `docker-compose.yml` runs a single Gunicorn worker. That is not
incidental — the notification scheduler runs in-process, and the login throttle
counts in memory. A second worker means duplicate notification emails and
throttle counters that each see a fraction of the traffic. Before scaling out,
move the scheduler to an external trigger and point `RATELIMIT_STORAGE_URI` at
a shared backend.

The container runs as root. There is no `USER` directive in the `Dockerfile`.

### Content Security Policy

There is no CSP header. Templates rely on inline `<script>` blocks, so adding
one means either nonces or extracting that JavaScript to static files first.

### Front-end supply chain

Bootstrap, Bootstrap Icons, HTMX, and Chart.js load from public CDNs with no
subresource integrity hashes. A compromised CDN response executes in an
authenticated admin session. Vendoring these locally removes the exposure.

### Database import

An admin can upload a SQLite file that replaces the live database. The upload
is validated for SQLite magic bytes and required tables, and the existing
database is backed up first — but this is still an admin handing the
application a new user table, including new password hashes. Treat admin
access as equivalent to database access. Backup files accumulate in the data
directory with no automatic pruning.

### Authorization gaps

Operator edit rights on a risk are decided partly by string-matching the
operator's display name against the risk owner field. Two users with the same
display name would inherit each other's edit rights. Trend entries can be added
by any operator to any risk, without the ownership check that risk editing
applies.

### Scale

List, dashboard, and report views load the entire register and filter in
Python. There is no pagination and no query-level filtering on computed fields
such as RAG status. This is a performance ceiling, not a correctness problem.

### Testing

There is no automated test suite. Changes are verified by hand against a
scratch database.
