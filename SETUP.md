# Skerry — Setup & Deployment

## Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose)
- 5 minutes

---

## Quick Start

### 1. Create your environment file

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

| Variable | What to set |
|---|---|
| `SECRET_KEY` | Any long random string (32+ chars) |
| `ADMIN_USERNAME` | Login username for the bootstrap admin (e.g. `ted`) |
| `ADMIN_EMAIL` | Admin email (used for notifications, not login) |
| `ADMIN_NAME` | Display name |
| `ADMIN_PASSWORD` | Strong password (12+ chars) |

Everything else can stay as-is for a local test run.

### 2. Build and start

```bash
docker compose up --build
```

First build takes a minute or two. Subsequent starts are fast.

### 3. Open the app

```
http://localhost:5000
```

Log in with the `ADMIN_EMAIL` / `ADMIN_PASSWORD` you set in `.env`.

---

## Azure AD / SSO (optional)

To enable SSO via Azure AD:

1. Register an app in Azure Portal → Azure Active Directory → App registrations
2. Set the redirect URI to `http://your-host:5000/auth/oidc/callback`
3. Under **Token configuration**, add a **Groups** claim → select **Security groups**
4. In `.env`:

```env
OIDC_CLIENT_ID=<Application (client) ID>
OIDC_CLIENT_SECRET=<Client secret value>
OIDC_DISCOVERY_URL=https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration

# Optional — restrict by group. Object IDs from Azure Portal → Groups → <group> → Overview
OIDC_ADMIN_GROUP=
OIDC_OPERATOR_GROUP=
OIDC_VIEWER_GROUP=
```

If none of the group vars are set, any authenticated Azure AD user can log in as viewer.
If any group var is set, users not in a listed group are denied.

---

## Email notifications (optional)

```env
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=skerry@yourdomain.com
SMTP_PASSWORD=...
SMTP_FROM=skerry@yourdomain.com
SMTP_USE_TLS=true
```

Notifications run daily at 7 AM (container timezone):
- Overdue actions → action owner (or risk owner)
- Board escalation flags → all admins
- Reviews due within 7 days → risk owner

---

## Stopping / data persistence

```bash
docker compose down          # stop, data preserved in ./data/
docker compose down -v       # stop and wipe database
```

The SQLite database lives in `./data/risk_register.db` on your host. Back that file up.

---

## Roles

| Role | Can do |
|---|---|
| **Viewer** | Read all risks, reports, exports |
| **Operator** | Create risks; edit risks they own or created |
| **Admin** | Full access: all risks, users, delete, sign-off fields |
