# Skerry Administrator Guide

**Version:** 1.7.4  
**Platform:** Flask 3.1 · Gunicorn 22 · Caddy · SQLite · Docker Compose  
**Audience:** IT administrators responsible for deployment, maintenance, and user access

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Installation](#2-installation)
   - 2.1 [Prerequisites](#21-prerequisites)
   - 2.2 [Extract the Package](#22-extract-the-package)
   - 2.3 [Configure Hostname and Port](#23-configure-hostname-and-port)
   - 2.4 [Configure the Remaining Environment Variables](#24-configure-the-remaining-environment-variables)
   - 2.5 [Build and Start](#25-build-and-start)
3. [First Start and Login](#3-first-start-and-login)
4. [User Management](#4-user-management)
5. [Settings and Lookup Lists](#5-settings-and-lookup-lists)
6. [Role Permissions Reference](#6-role-permissions-reference)
7. [Email Notifications](#7-email-notifications)
8. [Azure AD SSO: Full Configuration](#8-azure-ad-sso-full-configuration)
9. [Backups](#9-backups)
10. [Routine Maintenance](#10-routine-maintenance)
11. [Troubleshooting](#11-troubleshooting)
12. [Migration to a New Host](#12-migration-to-a-new-host)
13. [Appendix A: Trusting Caddy's Root CA](#appendix-a-trusting-caddys-root-ca)
14. [Appendix B: Environment Variable Reference](#appendix-b-environment-variable-reference)

---

## 1. Architecture

Two containers, one network, no external dependencies.

```
Browser
   │ HTTPS :8443 (host port; see 2.3)
   ▼
┌──────────────────────────────────────────────┐
│  caddy (caddy:alpine)                        │
│  • Listens on :443 → TLS termination         │
│    (published on the host as :8443)          │
│  • Sets X-Forwarded-Proto: https             │
│  • Proxies to web:{PORT}                     │
└──────────────┬───────────────────────────────┘
               │ HTTP :{PORT} (internal Docker network)
               ▼
┌──────────────────────────────────────────────┐
│  web (python:3.12-alpine)                    │
│  • Gunicorn WSGI server, 1 worker            │
│  • Flask 3.1 application                     │
│  • SQLite database at /app/data/             │
│  • APScheduler: daily email, nightly         │
│    CrowdStrike Spotlight sync                │
└──────────────────────────────────────────────┘

Volumes:
  ./data          → /app/data      (database, host-mounted, survives down)
  caddy_data      → Caddy CA + certs (named volume, survives down)
  caddy_config    → Caddy runtime config
```

**Why single Gunicorn worker:** SQLite does not handle concurrent writes from multiple processes safely, APScheduler must run in exactly one process, and the lock that keeps two Spotlight syncs from running at once lives in that process. One worker is not a performance limitation for an internal tool with a handful of concurrent users.

**Why Caddy:** Caddy runs its own internal certificate authority and issues a TLS certificate for your server on first start. No certificate management, no Let's Encrypt, no external dependencies. The CA root certificate can be distributed to workstations to eliminate browser warnings (see [Appendix A](#appendix-a-trusting-caddys-root-ca)).

The internal port (default: 5000) is only reachable inside Docker's private network, never from outside the host.

**Scheduled work.** Three things run on their own:

| Job | When | Runs only if |
|---|---|---|
| Notification email | 7:00 AM, container time | `SMTP_HOST` is set |
| Spotlight sync | `SPOTLIGHT_SYNC_HOUR`:`SPOTLIGHT_SYNC_MINUTE`, default 05:30 | `SPOTLIGHT_SYNC_ENABLED=true` |
| Register snapshot | The first request of each UTC day | Always |

The register snapshot records the day's counts (active risks by rating, items needing attention, KEV past due) for the dashboard trend and the One-Page Briefing. One row per day, never rewritten. Docker's health check calls the app every 30 seconds, so the snapshot is taken shortly after midnight UTC even when nobody signs in. If neither email nor the Spotlight sync is configured, no scheduler starts.

---

## 2. Installation

### 2.1 Prerequisites

Install on the target host before proceeding:

- Docker Engine (any recent version)
- Docker Compose v2 (`docker compose`, not `docker-compose`)
- An inbound firewall rule permitting TCP 8443 (the shipped port; TCP 443, and 80 for the redirect, if you change it per [Section 2.3](#23-configure-hostname-and-port))
- Your chosen hostname resolvable from client workstations, via DNS or a hosts file entry

No Python, no database server, no build tools on the host. Everything runs inside the containers.

Verify Docker is ready:

```bash
docker version
docker compose version
```

### 2.2 Extract the Package

Clone the repository to the host, or copy and extract a release zip, and change into the folder:

```bash
git clone <repository-url> skerry
cd skerry
```

The folder name matters in one place: Docker Compose names the Caddy volume after it (`skerry_caddy_data` for a folder named `skerry`). The examples in this guide assume `skerry`, installed at `/opt/skerry`.

Directory layout:

```
skerry/
├── app/                    Flask application source
│   ├── models.py           Register schema
│   ├── models_spotlight.py Spotlight ingest schema
│   ├── routes/             Blueprints (auth, risks, dashboard, ingest, reports, users, etc.)
│   ├── spotlight/          CrowdStrike client, sync, and elevation to risks
│   ├── templates/          Jinja2 HTML templates
│   ├── static/             CSS, JS, fonts, Word templates for the action request
│   ├── assurance.py        Shared rules: review dates, control testing, needs attention
│   ├── briefing.py         The One-Page Briefing
│   ├── snapshots.py        The daily register snapshot
│   ├── action_request.py   Risk Action Request documents
│   ├── config.py           Configuration class (reads from env)
│   ├── seed.py             NIST CSF 2.0 data and default lookup values
│   ├── scoring.py          Risk scoring helpers
│   ├── email_utils.py      SMTP notification logic
│   ├── decorators.py       Role enforcement decorators
│   └── version.py          The version shown under the logo
├── data/                   Database volume mount point (start empty)
├── scripts/                upgrade.sh, and builders for the Word templates
├── tests/                  Test suite (pytest)
├── Caddyfile               Caddy reverse proxy config
├── docker-compose.yml
├── docker-entrypoint.sh    Hands ./data to the app user, then drops root
├── Dockerfile
├── requirements.txt
├── run.py                  Application entrypoint for Gunicorn
├── .env.example            Template for your .env
├── CHANGELOG.md            What changed in each version, with upgrade steps
├── SETUP.md                Quick-start card
├── UPGRADE.md              Upgrading, rolling back, and restoring
├── SPOTLIGHT_INGEST.md     CrowdStrike Spotlight setup and behavior
├── USER_GUIDE.md           For people using the register
├── SECURITY.md · SBOM.md   Security notes and software bill of materials
└── ADMIN_GUIDE.md          This document
```

---

### 2.3 Configure Hostname and Port

**This is the most important configuration step.** Three variables in `.env` control how the platform is reached. Get these right before the first start.

```bash
cp .env.example .env
nano .env
```

The three variables:

| Variable | What it controls | Production example | Local dev example |
|---|---|---|---|
| `SERVER_NAME` | The hostname Caddy serves TLS for. This is what users type in the browser. | `skerry.example.com` | `localhost` |
| `BASE_URL` | The public URL used to build links in email notifications. Must match `SERVER_NAME`, plus the port if it is not 443. | `https://skerry.example.com:8443` | `https://localhost:8443` |
| `PORT` | The internal port Gunicorn binds inside the container. Caddy proxies to this port. Change only if 5000 conflicts on your host. | `5000` | `5001` |

**How the values flow**

You set them once in `.env`. Docker Compose reads `.env` and injects `SERVER_NAME` and `PORT` into the Caddy container as environment variables. The `Caddyfile` reads them at startup:

```
{$SERVER_NAME} {
    tls internal
    reverse_proxy web:{$PORT}
}
```

You never need to edit the `Caddyfile` or `docker-compose.yml`. The `.env` file is the single point of control.

**Production deployment:**

```env
SERVER_NAME=skerry.example.com
BASE_URL=https://skerry.example.com:8443
PORT=5000
```

Users open `https://skerry.example.com:8443`. Caddy issues a TLS cert for `skerry.example.com`. Email notification links point to `https://skerry.example.com:8443`.

**Local development or testing:**

```env
SERVER_NAME=localhost
BASE_URL=https://localhost:8443
PORT=5000
```

Open `https://localhost:8443`. You will get a certificate warning on first visit because the Caddy internal CA is not yet trusted. Click **Advanced → Proceed** or follow [Appendix A](#appendix-a-trusting-caddys-root-ca) to trust it permanently.

**If port 5000 is already in use** (macOS AirPlay Receiver holds 5000 by default):

```env
SERVER_NAME=localhost
BASE_URL=https://localhost:8443
PORT=5001
```

Changing `PORT` only affects the internal Docker network. It does not change the port the browser uses.

**The port users connect to.** The shipped `docker-compose.yml` publishes Caddy's HTTPS listener on host port **8443**, and does not publish port 80:

```yaml
    ports:
      ##- "80:80"
      - "8443:443"
```

So users open `https://<SERVER_NAME>:8443`, and the port belongs in `BASE_URL` too (`BASE_URL=https://skerry.example.com:8443`), or the links in notification email will not work. Plain `http://` does not redirect, because nothing listens on 80.

To serve on the standard port instead, change `"8443:443"` to `"443:443"` and un-comment `"80:80"` for the HTTP redirect, then drop `:8443` from `BASE_URL` and from the SSO redirect URI. This guide writes addresses as `https://<SERVER_NAME>:8443` throughout; leave the port off if you made that change.

> **After any change to these three variables, restart the stack:**
> ```bash
> docker compose down && docker compose up -d
> ```
> Caddy reads the variables only at startup. A running container will not pick up changes without a restart.

---

### 2.4 Configure the Remaining Environment Variables

With the hostname set, fill in the remaining required values:

| Variable | What to set | How to generate |
|---|---|---|
| `SECRET_KEY` | Random 64-char hex string. The app refuses to start when this is empty or a known placeholder. | `openssl rand -hex 32` |
| `ADMIN_USERNAME` | Login username for the bootstrap admin | Your choice: lowercase, no spaces |
| `ADMIN_EMAIL` | Admin email for notifications | Your address |
| `ADMIN_NAME` | Admin display name | Your name as it will appear in the UI |
| `ADMIN_PASSWORD` | Bootstrap admin password, 12 characters or more. If you leave it blank, the app generates one and prints it once to the startup log. | A password manager |

Everything else has defaults that work out of the box. See [Appendix B](#appendix-b-environment-variable-reference) for the full list.

A complete minimal `.env` for production:

```env
# Hostname and URL: edit these for your environment
SERVER_NAME=skerry.example.com
BASE_URL=https://skerry.example.com:8443
PORT=5000

# Security
SECRET_KEY=<output of openssl rand -hex 32>

# Bootstrap admin (used once on first start; ignored after)
ADMIN_USERNAME=ted
ADMIN_EMAIL=ted@example.com
ADMIN_NAME=Ted M.
ADMIN_PASSWORD=YourStr0ng!Password

# Database
DATABASE_URL=sqlite:////app/data/risk_register.db

# Risk ID prefix (set before first run; changing later does not renumber existing records)
RISK_ID_PREFIX=SKR

# Scoring thresholds
RAG_RED_THRESHOLD=15
RAG_AMBER_THRESHOLD=9
RISK_APPETITE_THRESHOLD=8

# SMTP: leave blank to disable email notifications
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=skerry@example.com
SMTP_USE_TLS=true

# Azure AD SSO: leave blank to disable
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
OIDC_DISCOVERY_URL=
OIDC_ADMIN_GROUP=
OIDC_OPERATOR_GROUP=
OIDC_VIEWER_GROUP=

# CrowdStrike Falcon Spotlight: leave blank to disable (see SPOTLIGHT_INGEST.md)
FALCON_CLIENT_ID=
FALCON_CLIENT_SECRET=
FALCON_CLOUD_REGION=us-1
SPOTLIGHT_SYNC_ENABLED=false

# Web server
GUNICORN_TIMEOUT=300
```

`GUNICORN_TIMEOUT` is how many seconds one web request may run before Gunicorn stops the worker and starts a fresh one. The default of 300 covers a large Excel export or a database import. The Spotlight sync is not bound by it, because it runs on a background thread. Raise it only if a page or export is being cut off; a change takes effect when the container is recreated with `docker compose up -d`. CrowdStrike Spotlight settings are covered in `SPOTLIGHT_INGEST.md`.

> The bootstrap admin account is created on first start from `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_NAME`, and `ADMIN_PASSWORD`. After that, manage the account through User Management. Changing the username, name, or password variables later has no effect. **Changing `ADMIN_EMAIL` does**: at startup Skerry looks for an account with that email, and if none exists it creates a second admin account. Leave `ADMIN_EMAIL` alone once the stack has started.
>
> If `ADMIN_PASSWORD` was blank, find the generated password with `docker compose logs web | grep -A3 "Bootstrap admin created"`. Sign in, change it, and clear the container logs; the password is in them in plain text.

---

### 2.5 Build and Start

```bash
docker compose up --build
```

The first build takes a minute or two, mostly the Python dependency install. Subsequent starts take seconds.

Watch the output. When you see both of these, the platform is ready:

```
web-1    | [INFO] Starting gunicorn 22.0.0
web-1    | [INFO] Listening at: http://0.0.0.0:5000
caddy-1  | {"level":"info","msg":"serving initial configuration"}
```

Caddy generates its internal CA and issues the certificate for `SERVER_NAME` in the background. This happens once and persists in the `caddy_data` volume.

To run detached:

```bash
docker compose up --build -d
```

`docker compose ps` shows the `web` container as `healthy` once its health check passes. The check calls `/health` inside the container every 30 seconds.

---

## 3. First Start and Login

Open a browser on any machine that can reach the server:

```
https://<SERVER_NAME>:8443
```

The browser will show a security warning on first visit, because Caddy's CA is not yet trusted by the OS. Click **Advanced → Proceed** to get past it. This is expected; Caddy's internal CA is legitimate but not in the OS trust store yet. To eliminate the warning permanently, follow [Appendix A](#appendix-a-trusting-caddys-root-ca).

Log in with the username and password set in `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`, or the generated password from the startup log if you left `ADMIN_PASSWORD` blank.

With the shipped port mapping, type the `:8443`. Nothing answers on port 80, so `http://` does not redirect. See [Section 2.3](#23-configure-hostname-and-port) to move to 443.

The version number shows under the logo in the sidebar once you are signed in.

Verify the health endpoint responds:

```bash
curl -sk https://<SERVER_NAME>:8443/health
# {"status": "ok"}
```

---

## 4. User Management

Navigate to **Admin → User Management** in the left sidebar. Requires admin role. The Admin group in the sidebar collapses; click its heading if the links are hidden.

### 4.1 Roles

Three roles, not more. Assign the minimum needed.

- **Viewer:** read-only access. Can view all risks, run reports, and download exports. Right role for leadership, auditors, and stakeholders who need visibility but not write access.
- **Operator:** creates and edits risks. Can edit risks they created, or risks where their display name matches the Risk Owner field (ignoring case and surrounding spaces). Works the Spotlight queue: triage, elevate, dismiss, and delete findings. Cannot delete risks, record an acceptance sign-off, run a Spotlight sync, or manage users.
- **Admin:** full access. Manages users, settings, and the database. Keep this small. It is not a reward, it is a responsibility.

### 4.2 Creating a User

Click **Add User** and complete the form:

- **Username:** what the user types at the login screen. Lowercase, no spaces. Used for local auth only; SSO users do not need a username.
- **Full Name:** display name throughout the application. It must match the name entered in a risk's Risk Owner or Action Owner field for two things to work: an operator's right to edit risks they own, and notification email. The match ignores case and surrounding spaces, nothing else. Get this right.
- **Email:** used for system notifications, not login.
- **Role:** viewer, operator, or admin.
- **Password:** minimum 12 characters. Communicate it through a secure channel. The user should change it after first login.

### 4.3 Editing a User

Click the pencil icon on any user row. You can update username, display name, role, active status, and password. Email cannot be changed after creation. Leave the password field blank to leave it unchanged; a new one must be 12 characters or more.

You cannot demote or deactivate the last active admin, and you cannot remove your own admin access. Ask another admin.

### 4.4 Deactivating a User

Click the deactivate icon. This is a soft delete: the account is disabled but not removed. You cannot deactivate your own account. Their name remains on any risks or audit log entries they created. This matters: deleting the record would corrupt the audit trail. Do not hard-delete users.

### 4.5 Password Resets

There is no self-service password reset. An admin sets the new password through the User Management edit form and communicates it to the user.

### 4.6 SSO-Provisioned Users

When Azure AD SSO is active, users who log in through SSO are provisioned automatically. Their role comes from their Azure AD group membership. You cannot set a local password for these accounts; they authenticate through the SSO button only. You can still deactivate them or manually adjust their role from the User Management page if a group-based assignment does not fit.

**Existing local accounts and SSO.** Skerry binds an SSO identity to an existing account with the same email only when the identity provider asserts `email_verified`. Azure AD (Entra ID) does not send that claim, so a user who already has a local account is turned away at the SSO button with a message to contact an administrator. Binding on email alone would let anyone whose token carried that address take over the account. There is no linking screen yet. To link one by hand, find the refusal in the application log (`OIDC login refused for <email>: existing local account ...`), which records the token's `sub` value, and set `users.oidc_sub` to that value for the user. Use the logged value, not the Entra object ID; Entra's `sub` is specific to the app registration and differs from it.

---

## 5. Settings and Lookup Lists

Navigate to **Admin → Settings** in the left sidebar. Requires admin role.

The Settings page manages dropdown values and database administration. Five tabs: one for each of the four lookup lists, and Database.

### 5.1 Lookup Lists

Four lists power dropdowns on the risk entry form:

- **Threat Actor Types:** who is likely behind this risk (e.g., Cybercriminal, Nation State, Malicious Insider)
- **Attack Vectors:** how an attack would be executed (e.g., Phishing, Supply Chain, Network Intrusion)
- **Threat Intel Sources:** where your intelligence came from (e.g., Vulnerability Scan, Threat Intelligence Feed)
- **Risk Owners:** individuals or teams that can be assigned ownership of a risk

Each tab shows active values in display order, with controls to add, edit, remove, and reorder.

**Add:** Type the value and click Add. Duplicate detection is case-sensitive.

**Edit:** Click the pencil icon. Updates take effect immediately for new risk entries. Existing risk records that already have the old value stored are not affected. They keep whatever string was saved.

**Remove:** Soft-delete. The value disappears from the dropdown but remains on existing records. Risk records referencing a removed lookup value are not corrupted; the stored string is still there.

**Reorder:** Use the up/down chevrons. Order here is the order users see in the dropdown.

**Risk Owners list:** This is how you control who appears in the Risk Owner dropdown. Keep it current with your actual team. The names here must match user display names (case aside) for edit rights and notification email to resolve.

### 5.2 Database Tab

Two operations available to admins.

**Download .db file:** streams the live SQLite database as a timestamped download (`risk_register_YYYYMMDD_HHMMSS.db`). Use this for manual backups and before any significant change.

**Import & Replace:** uploads a `.db` file and replaces the live database. Before replacing, the platform validates that the uploaded file is a valid SQLite database containing the register's tables. It also auto-creates a timestamped backup of the current database before overwriting it. A file exported before the Spotlight ingest or the daily snapshot existed is accepted; the missing tables are created empty. The imported file brings its own snapshot history, so the dashboard trend and the briefing's month comparison reflect the imported register. See [Section 12](#12-migration-to-a-new-host) for migration workflow using this feature.

---

### 5.3 CrowdStrike Spotlight

The Spotlight connection is configured in `.env`, not on the Settings page. Setup, the API key's single scope, the FQL filter, and how findings close are all in `SPOTLIGHT_INGEST.md`. Two admin-only pages:

- **Admin → Spotlight Sync:** run a manual sync, test the connection, see sync history, and **Reconcile** findings Falcon no longer reports as open. A manual sync runs in the background; the page refreshes while it runs. Only one sync runs at a time, and the nightly run skips if a manual one is still going. A sync left running by a restart is marked failed as interrupted at the next start.
- The nightly sync runs only with `SPOTLIGHT_SYNC_ENABLED=true`, at `SPOTLIGHT_SYNC_HOUR`:`SPOTLIGHT_SYNC_MINUTE` container time (default 05:30).

Everyone can view the **Spotlight Ingest** queue. Operators and admins work it.

---

## 6. Role Permissions Reference

| Action | Viewer | Operator | Admin |
|---|:---:|:---:|:---:|
| View all risks, audit log, trend history | ✓ | ✓ | ✓ |
| Run all reports | ✓ | ✓ | ✓ |
| Download Excel export | ✓ | ✓ | ✓ |
| Create new risks | — | ✓ | ✓ |
| Edit risks they created or own | — | ✓ | ✓ |
| Edit any risk | — | — | ✓ |
| Delete risks | — | — | ✓ |
| Set treatment to Accept | — | ✓ | ✓ |
| Record acceptance sign-off (who and when) | — | — | ✓ |
| Edit the CSF mapping on the register, one risk or in bulk | — | Own | ✓ |
| Generate a Risk Action Request (.docx) | — | Own | ✓ |
| Add manual trend log entries | — | ✓ | ✓ |
| View the Spotlight queue, hosts, and CVEs | ✓ | ✓ | ✓ |
| Triage, elevate, dismiss, delete, or restore Spotlight findings | — | ✓ | ✓ |
| Run a Spotlight sync, reconcile, test the connection, view sync history | — | — | ✓ |
| Manage users | — | — | ✓ |
| Manage lookup lists | — | — | ✓ |
| Download / import database | — | — | ✓ |

"Own" means the same rule as editing: risks the operator created, or where the Risk Owner matches their display name.

---

## 7. Email Notifications

Email notifications are optional. The scheduler only runs when `SMTP_HOST` is set in `.env`.

When configured, the scheduler fires daily at 7:00 AM (container local time) and sends three types of notifications:

| Trigger | Recipient | Condition |
|---|---|---|
| Overdue action | Action Owner, or Risk Owner if Action Owner is blank | Due date has passed and status is not Closed or Accepted |
| Board escalation | All admin users by email | Board Reporting Flag is set on the risk AND residual score exceeds risk appetite threshold |
| Review due | Risk Owner | Next review date is within 7 days or already past, based on review frequency and the latest of last reviewed and acceptance sign-off. Sent each day until the risk is reviewed. |

**Recipient resolution:** The platform matches the Risk Owner or Action Owner field against the Full Name or email of an **active user**, ignoring case. It never mails an address that is not a user's, so an owner field cannot send risk details outside the user list. With no match, the notification is skipped and a warning is logged (`Cannot resolve notification recipient`). Nobody sees an error, so check the log. Risks that are Closed or Accepted get no notifications.

Configure SMTP in `.env`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=notifications@example.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=skerry@example.com
SMTP_USE_TLS=true
```

Verify notifications are working after 7:00 AM:

```bash
docker compose logs web | grep -i "email\|notif\|smtp"
```

---

## 8. Azure AD SSO: Full Configuration

SSO is optional. Local username/password authentication works independently and is not disabled when SSO is enabled. Both methods operate simultaneously.

### 8.1 What You Need Before Starting

- Access to Azure Portal with permission to register applications
- Your Azure tenant ID (found in Azure Portal → Microsoft Entra ID → Overview)
- The group Object IDs for your admin, operator, and viewer groups (if using group-based role assignment)

### 8.2 Register the Application in Azure Portal

1. Open **Azure Portal → Microsoft Entra ID → App registrations → New registration**

2. Fill in:
   - **Name:** Skerry (or whatever makes sense internally)
   - **Supported account types:** Accounts in this organizational directory only (single tenant)
   - **Redirect URI:** Select **Web** and enter:
     ```
     https://<SERVER_NAME>:8443/auth/oidc/callback
     ```
     Use your actual `SERVER_NAME` value, e.g. `https://skerry.example.com:8443/auth/oidc/callback`. Include the port exactly as users type it; Entra compares the whole string.

3. Click **Register**. Note the **Application (client) ID**. This is `OIDC_CLIENT_ID`.

4. Note the **Directory (tenant) ID** from the Overview page. You will need it for `OIDC_DISCOVERY_URL`.

### 8.3 Create a Client Secret

1. In the app registration, go to **Certificates & secrets → Client secrets → New client secret**
2. Set a description (e.g., "skerry-prod") and an expiration (12 or 24 months)
3. Click **Add** and copy the **Value** immediately. It is not shown again
4. This is `OIDC_CLIENT_SECRET`

Set a calendar reminder to rotate this secret before it expires. When it expires, SSO logins will fail silently.

### 8.4 Configure Token Claims

The platform reads group membership from the ID token. To include groups:

1. In the app registration, go to **Token configuration → Add groups claim**
2. Select **Security groups**
3. Under **ID**, check **Group ID** (this emits the Object ID, not the display name)
4. Click **Add**

> **Group count limit:** Azure AD omits the groups claim entirely when a user belongs to more than 150 groups. If this applies in your environment, create a dedicated small security group for each role and add users to those groups. Do not add users directly to large department groups and expect the claim to come through.

### 8.5 Configure API Permissions (if required)

The default `openid`, `email`, and `profile` scopes are sufficient for basic SSO. If your Azure tenant requires admin consent for these scopes, go to **API permissions → Grant admin consent for [your tenant]** and confirm.

### 8.6 Retrieve Group Object IDs

For each Azure AD security group you want to map to a role:

1. Azure Portal → Microsoft Entra ID → Groups
2. Click the group name
3. On the Overview page, copy the **Object ID**

You will map three groups, one per role. A user is denied access if they are not a member of any of the three groups.

### 8.7 Set Environment Variables

Add these to your `.env`:

```env
# Required for SSO
OIDC_CLIENT_ID=<Application (client) ID from Step 8.2>
OIDC_CLIENT_SECRET=<Client secret value from Step 8.3>
OIDC_DISCOVERY_URL=https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration

# Optional: enable group-based role mapping
OIDC_ADMIN_GROUP=<Object ID of admin security group>
OIDC_OPERATOR_GROUP=<Object ID of operator security group>
OIDC_VIEWER_GROUP=<Object ID of viewer security group>
```

Replace `<tenant-id>` in the discovery URL with your Directory (tenant) ID from Step 8.2.

Restart the stack for the changes to take effect:

```bash
docker compose down && docker compose up -d
```

### 8.8 How Role Assignment Works

When group variables are set, every SSO login re-evaluates role from group membership. The precedence is: admin group → operator group → viewer group. If the user is not in any listed group, they are denied access with an error message directing them to contact an administrator.

If no group variables are set, all successfully authenticated SSO users are assigned the viewer role by default.

Role changes made in Azure AD (adding or removing someone from a group) take effect at the user's next login, not immediately.

### 8.9 Verify SSO is Working

After restarting:

1. Open the login page. The **Sign in with SSO** button should appear
2. Click it and complete the Azure AD authentication flow
3. You should land on the dashboard with the correct role
4. Check `docker compose logs web | grep oidc` for any errors if login fails

Common failure causes: wrong redirect URI in Azure, client secret expired or copied incorrectly, groups claim not configured, user not in any mapped group.

---

## 9. Backups

### 9.1 What to Back Up

Three items, in order of priority:

**The database** (`./data/risk_register.db`): contains everything: all risks, vulnerability findings, users, audit trail, trend history, daily register snapshots, lookup list customizations, NIST reference data, and the Spotlight queue with its sync history. This is the only file that changes during normal operation.

**The `.env` file:** contains your `SECRET_KEY`, SMTP credentials, OIDC secret, and Falcon API key. If you lose the `SECRET_KEY`, all existing user sessions are invalidated (users will need to log in again; no data is lost). Store `.env` separately from the database: in a secrets manager, a secure document store, or a separate backup location. Do not keep it only on the Docker host.

**Caddy's CA volume** (`caddy_data`): holds the internal CA that issued your TLS certificate. This volume survives `docker compose down` automatically. If the volume is lost, Caddy generates a new CA on next start, but all workstations that trusted the old CA root will need to trust the new one. See [Appendix A](#appendix-a-trusting-caddys-root-ca). Back it up before host maintenance:

```bash
docker run --rm \
  -v skerry_caddy_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/caddy_data_backup.tar.gz /data
```

The volume is named after the install folder. `docker volume ls | grep caddy_data` shows the exact name.

### 9.2 Manual Database Backup

From the application: **Admin → Settings → Database → Download .db file**

The file downloads as `risk_register_YYYYMMDD_HHMMSS.db`. Move it off the host.

From the host, use SQLite's backup function through the running container. It takes a consistent copy even while the app is writing:

```bash
mkdir -p ./data/backups
docker compose exec -T web python3 -c "import sqlite3,sys; s=sqlite3.connect('/app/data/risk_register.db'); d=sqlite3.connect(sys.argv[1]); s.backup(d); d.close()" /app/data/backups/risk_register_$(date +%Y%m%d_%H%M%S).db
```

The copy lands in `./data/backups/` on the host. Move it off the host.

Do not back up with a plain `cp` while the stack is running. The database runs in SQLite's default rollback-journal mode, not WAL, so a copy taken mid-write can be inconsistent. A nightly Spotlight sync writes for minutes at a time, and the daily snapshot writes shortly after midnight UTC. A `cp` is safe only with the stack stopped.

### 9.3 Automated Host-Level Backup

Create the backup directory and a cron job:

```bash
mkdir -p /opt/skerry/data/backups

crontab -e
# Add (one line):
0 2 * * * cd /opt/skerry && docker compose exec -T web python3 -c "import sqlite3,sys; s=sqlite3.connect('/app/data/risk_register.db'); d=sqlite3.connect(sys.argv[1]); s.backup(d); d.close()" /app/data/backups/risk_register_$(date +\%Y\%m\%d).db
```

Avoid 05:30, when the nightly Spotlight sync runs by default; the backup still works, but it waits on the sync's writes.

Rotate old backups to prevent disk fill, and copy them off the host on your own schedule:

```bash
# Keep 30 days
0 3 * * * find /opt/skerry/data/backups -name "*.db" -mtime +30 -delete
```

### 9.4 Import-Generated Backups

Every import operation (Admin → Settings → Database → Import & Replace) auto-creates a backup of the replaced database at `./data/risk_register.db.backup_YYYYMMDD_HHMMSS`. These accumulate. Prune them periodically:

```bash
find ./data -name "*.backup_*" -mtime +30 -delete
```

---

## 10. Routine Maintenance

### 10.1 Updating the Application

Use the upgrade script. It backs up the database, `.env`, and Caddy's CA, pulls the new code, rebuilds on fresh base images, restarts, checks the new version, and rolls the images back if the check fails:

```bash
scripts/upgrade.sh --check     # what is running, what is waiting
scripts/upgrade.sh
```

[`UPGRADE.md`](UPGRADE.md) covers what each step does, rolling back, and what to do if it stops. Running it with no new release still matters: it is how Alpine, Python, and Caddy security fixes reach a running install.

To do it by hand instead:

```bash
# Back up the database before any update (stack stopped, so cp is safe)
docker compose down
mkdir -p ./backups
cp ./data/risk_register.db ./backups/risk_register_pre_update_$(date +%Y%m%d).db

# Pull new code (or re-extract the zip), then rebuild on fresh base images
git pull
docker compose build --pull
docker compose pull caddy
docker compose up -d
```

`--pull` matters. Without it, Docker reuses the Python and Alpine base it cached on the first build, and the Caddy image is never refreshed. `./backups` is excluded from git and from the image build.

The database schema is managed by SQLAlchemy's `db.create_all()` on startup. It creates tables that do not exist yet. It does not add columns to a table that already exists, and it never drops anything. A release that only adds tables upgrades on its own; a release that changes an existing table needs a migration step, and its release notes will say so. Restoring from the backup above is the rollback path.

The container starts as root only long enough to give `./data` to the app user (uid 10001), then runs Gunicorn as that user. No manual ownership change is needed on upgrade; see `docker-entrypoint.sh`.

After the rebuild, sign in and check the version under the logo in the sidebar. It should match the newest entry in `CHANGELOG.md`; if it shows the old number, the rebuild did not take. Each `CHANGELOG.md` entry ends with any upgrade steps that release needs.

**Version numbers.** Three parts: the first moves for a change in how the app is used or deployed that people need to be told about, the second for a new feature or report, the third for a small revision on top of that (1.7, then 1.7.1, 1.7.2). A new second number drops the third.

**Releasing a new version.** Change `__version__` in `app/version.py`, add an entry at the top of `CHANGELOG.md`, and update `PackageVersion` in `SBOM.md` and the Version lines in `USER_GUIDE.md` and this guide. The test suite fails until all five agree.

### 10.2 Checking Container Status

```bash
docker compose ps
docker compose logs web --tail 50
docker compose logs caddy --tail 20
```

### 10.3 Restarting After a Configuration Change

To pick up any `.env` change:

```bash
docker compose down && docker compose up -d
```

There is no zero-downtime restart mechanism. This is an internal tool, and a few seconds of restart is acceptable.

### 10.4 Viewing Logs

Application logs (risk operations, auth events, scheduler):

```bash
docker compose logs web -f
```

Caddy TLS and proxy logs:

```bash
docker compose logs caddy -f
```

### 10.5 Rotating the Client Secret (SSO)

When your Azure AD client secret approaches its expiration date:

1. In Azure Portal → App registrations → [your app] → Certificates & secrets, create a new client secret
2. Copy the new value
3. Update `OIDC_CLIENT_SECRET` in `.env`
4. Restart: `docker compose down && docker compose up -d`
5. Delete the old secret in Azure Portal after confirming SSO still works

Do not let the secret expire without a replacement in place. Expired secrets result in all SSO logins failing.

### 10.6 Disk Usage

Check available space on the host:

```bash
df -h /opt/skerry
du -sh /opt/skerry/data/
du -sh /opt/skerry/data/backups/
docker system df
```

The register itself stays small: several hundred risks with full audit history is a few megabytes. The Spotlight queue is what grows. Each finding keeps the full record CrowdStrike returned, so a large tenant can add hundreds of megabytes, and every backup is that size too. Narrowing `SPOTLIGHT_FQL_FILTER` and `SPOTLIGHT_SEVERITIES` is the lever; see `SPOTLIGHT_INGEST.md`. Watch the size after the first full sync and set backup retention to match.

---

## 11. Troubleshooting

### 11.1 Container Will Not Start

Check the logs immediately after the failed start:

```bash
docker compose logs web --tail 30
docker compose logs caddy --tail 20
```

Common causes: missing `.env` (copy from `.env.example`), `SECRET_KEY` empty or left at a placeholder (the log says `SECRET_KEY is unset or still a placeholder`), invalid environment variable (a non-integer where an integer is expected), or a port conflict (something else already using 8443).

Check for port conflicts:

```bash
ss -tlnp | grep -E ':8443|:443|:80 '
```

### 11.2 Browser Shows a Certificate Warning

This is expected on first access. Caddy's internal CA is not yet trusted by the OS or browser. Click **Advanced → Proceed** to continue. To eliminate the warning permanently, follow [Appendix A](#appendix-a-trusting-caddys-root-ca).

If the warning returns after it was previously dismissed, the `caddy_data` volume was likely lost, and Caddy issued a new CA. Re-export and re-install the root certificate.

### 11.3 Browser Cannot Connect (ERR_CONNECTION_REFUSED / ERR_SSL_PROTOCOL_ERROR)

The URL you are typing must match `SERVER_NAME` in `.env`, and include `:8443` with the shipped port mapping. A wrong hostname gets no certificate from Caddy; a missing port reaches nothing at all.

Check what `SERVER_NAME` is set to:

```bash
grep SERVER_NAME .env
```

Common mismatch patterns:

| What you type | SERVER_NAME in .env | Result |
|---|---|---|
| `https://localhost:8443` | `skerry.example.com` | TLS error |
| `https://skerry.example.com:8443` | `localhost` | TLS error |
| `https://localhost` | `localhost` | Connection refused (no port) |
| `https://localhost:8443` | `localhost` | Works |

Fix: update `SERVER_NAME` (and `BASE_URL`) in `.env` to match the URL you are using, then restart:

```bash
docker compose down && docker compose up -d
```

### 11.4 Browser Shows 502 Bad Gateway

Caddy is running but cannot reach the `web` container. The `web` container may still be starting, or it may have crashed.

```bash
docker compose ps
docker compose logs web --tail 30
```

If the `web` container shows as exited, check for Python import errors or a misconfigured `DATABASE_URL`.

Also confirm the `PORT` variable in `.env` is consistent: the `web` container must be listening on the same port Caddy is proxying to. If you changed `PORT`, make sure the stack was restarted.

### 11.5 Cannot Log In

Confirm the `web` container is healthy:

```bash
curl -sk https://<SERVER_NAME>:8443/health
```

If that returns `{"status": "ok"}` but login fails, check that the username is lowercase and matches exactly what was set in `ADMIN_USERNAME` (or the username set in User Management).

If the admin bootstrap account was never created (database was replaced or the account was deactivated), create a new admin manually. Use a password of 12 characters or more, then change it in User Management:

```bash
docker compose exec web python3 -c "
from app import create_app
from app.models import db, User
app = create_app()
with app.app_context():
    u = User(username='admin', email='admin@local', name='Admin', role='admin', is_active=True)
    u.set_password('NewPassword123!')
    db.session.add(u)
    db.session.commit()
    print('Admin created.')
"
```

### 11.6 SSO Login Fails

Check logs:

```bash
docker compose logs web | grep -i "oidc\|oauth\|sso\|error" | tail -30
```

Common causes and their fixes:

| Symptom | Likely Cause | Fix |
|---|---|---|
| Redirect URI mismatch error from Azure | URI in app registration does not match exactly | Confirm `https://<SERVER_NAME>:8443/auth/oidc/callback` in Azure matches your `SERVER_NAME` and port |
| "Not authorized to access this application" | User not in any mapped group | Add user to the correct Azure AD group |
| Turned away with "contact an administrator" | A local account already uses that email | Link the accounts by hand; see [Section 4.6](#46-sso-provisioned-users) |
| Groups claim missing from token | User is in >150 groups | Create a dedicated smaller group for role mapping |
| Invalid client error | Client secret expired or wrong | Rotate secret per Section 10.5 |
| Discovery URL failure | Wrong tenant ID | Verify tenant ID in Azure Portal → Entra ID → Overview |

### 11.7 Email Notifications Not Sending

Check scheduler output in logs after 7:00 AM:

```bash
docker compose logs web | grep -i "email\|smtp\|notif\|scheduler"
```

If the scheduler started but emails are not arriving, confirm SMTP credentials are correct. Test manually from the host:

```bash
python3 -c "
import smtplib
s = smtplib.SMTP('smtp.example.com', 587)
s.starttls()
s.login('user@example.com', 'password')
print('SMTP OK')
s.quit()
"
```

If emails are sending but specific risks are not generating notifications: the risk's Owner field does not match any active user's Full Name or email. Look for `Cannot resolve notification recipient` in the log; it names the value that failed. Case does not matter; spelling and middle initials do.

---

## 12. Migration to a New Host

This procedure moves the platform to a new host with no data loss and minimal downtime. The downtime window is the time between telling users not to enter new data and confirming the new instance is live, typically under 30 minutes.

### 12.1 Prerequisites

Before starting:

- The new host has Docker and Docker Compose installed
- You can clone the repository (or have the release zip) and have a copy of your current `.env`
- The old instance is still accessible

### 12.2 Step 1: Export the Database

Log in to the old instance as admin. Navigate to **Admin → Settings → Database → Download .db file**.

Save the file locally. This is your data.

### 12.3 Step 2: Set Up the New Instance

On the new host:

```bash
git clone <repository-url> skerry
cd skerry
cp /path/to/your/.env .env
```

If the new host uses a different hostname, open `.env` and update two values:

```env
SERVER_NAME=new-hostname
BASE_URL=https://new-hostname:8443
```

If SSO is on, add the new redirect URI to the Entra app registration as well ([Section 8.2](#82-register-the-application-in-azure-portal)).

That is the only edit needed. The `Caddyfile` and `docker-compose.yml` pick up `SERVER_NAME` from `.env` automatically; no changes to those files.

The `SECRET_KEY` should stay the same as the old instance. It keeps session signing consistent. If you change it, all users will be logged out on next access, which is inconvenient but not harmful.

Start the new instance:

```bash
docker compose up --build -d
```

Verify it is healthy:

```bash
curl -sk https://localhost:8443/health
# {"status": "ok"}
```

(Use `localhost` here only because you're running the `curl` command directly on the server. Users will connect to `SERVER_NAME`.)

### 12.4 Step 3: Import the Database

Log in to the new instance using the bootstrap admin credentials from `.env`. The register will be empty at this point, only seed data. If the old `.env` enables the Spotlight sync, set `SPOTLIGHT_SYNC_ENABLED=false` on the new host until cut over, so two instances do not pull from the same tenant.

Navigate to **Admin → Settings → Database → Import & Replace**.

Click **Choose File**, select the `.db` file exported in Step 12.2, and click **Import & Replace**. The platform will validate the file, back up the current (empty) database, and replace it. No restart is required.

### 12.5 Step 4: Verify Before Cut Over

Before redirecting users to the new host, confirm:

- Login works using credentials from the imported database (not the bootstrap admin)
- Register shows existing risks with correct counts
- User Management shows all expected accounts
- Settings → Lookup Lists show your customized values
- A report loads without errors
- An Excel export downloads correctly
- The One-Page Briefing opens, and the dashboard trend shows the imported snapshot history
- If you use Spotlight, Admin → Spotlight Sync → Test connection succeeds
- Check the audit log on at least one risk to confirm history carried over

### 12.6 Step 5: Cut Over

Update DNS or distribute the new hostname to users. If workstations trusted the old Caddy CA, they will need to trust the new one. The new host generates a different CA on first start. Follow [Appendix A](#appendix-a-trusting-caddys-root-ca) with the new root certificate.

Leave the old instance running until users confirm the new one is working. Then shut it down:

```bash
# On the old host
docker compose down
```

---

## Appendix A: Trusting Caddy's Root CA

Caddy creates an internal certificate authority on first start and uses it to issue the TLS certificate for your `SERVER_NAME`. The CA root is not trusted by operating systems or browsers by default, hence the browser warning.

Installing the CA root into the OS trust store is a one-time step per workstation and eliminates the warning permanently for the life of that CA (which lives in the `caddy_data` volume).

### Export the Root Certificate

On the server:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

This creates `caddy-root.crt` in the current directory. Transfer it to each workstation.

### Windows

1. Double-click `caddy-root.crt`
2. Click **Install Certificate**
3. Select **Local Machine** → Next
4. Select **Place all certificates in the following store → Browse → Trusted Root Certification Authorities**
5. Next → Finish

Restart Chrome or Edge. The warning will not reappear.

For domain-joined machines, the certificate can be distributed via Group Policy (Computer Configuration → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities). This eliminates the need to touch each workstation individually.

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain caddy-root.crt
```

Restart the browser.

### Linux (Chrome / Edge)

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "CT,," -n "Caddy Local CA" -i caddy-root.crt
```

### Firefox (Any OS)

Firefox uses its own certificate store regardless of OS.

Navigate to **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**, select `caddy-root.crt`, and check **Trust this CA to identify websites**.

---

## Appendix B: Environment Variable Reference

All variables are read from `.env` at startup. Restart the stack after any change (`docker compose down && docker compose up -d`). The Spotlight variables are explained in full in `SPOTLIGHT_INGEST.md`.

| Variable | Default | Notes |
|---|---|---|
| `SERVER_NAME` | `skerry.example.com` | Hostname Caddy listens on and issues a TLS cert for. Must match what users type in the browser. Change to `localhost` for local dev/testing. See [Section 2.3](#23-configure-hostname-and-port). |
| `BASE_URL` | `https://localhost` | Public URL used in email notification links. Must match `SERVER_NAME`, with the port if it is not 443 (`https://skerry.example.com:8443` with the shipped mapping). See [Section 2.3](#23-configure-hostname-and-port). |
| `PORT` | `5000` | Internal port Gunicorn binds inside the container. Caddy proxies to this port. Change only if 5000 conflicts with another process on your host. See [Section 2.3](#23-configure-hostname-and-port). |
| `SECRET_KEY` | _(none)_ | Flask session signing key. **Required:** the app refuses to start when it is empty or a known placeholder. Generate with `openssl rand -hex 32`. If changed, all active sessions are invalidated. |
| `DATABASE_URL` | `sqlite:////app/data/risk_register.db` | SQLite path inside the container. Do not change unless remapping the volume. |
| `RISK_ID_PREFIX` | `SKR` | Prefix for auto-generated Risk IDs (e.g., `SKR-001`). Set before first run. Changing after risks exist does not renumber existing records. |
| `RAG_RED_THRESHOLD` | `15` | Residual score at or above this value is RED. |
| `RAG_AMBER_THRESHOLD` | `9` | Residual score at or above this value is AMBER (and below RED threshold). |
| `RISK_APPETITE_THRESHOLD` | `8` | Residual score above this value is flagged as exceeding risk appetite. |
| `SMTP_HOST` | _(blank)_ | SMTP server hostname. Leave blank to disable all email notifications. |
| `SMTP_PORT` | `587` | SMTP port. Use 465 with `SMTP_USE_TLS=false` for implicit TLS. |
| `SMTP_USER` | _(blank)_ | SMTP authentication username. |
| `SMTP_PASSWORD` | _(blank)_ | SMTP authentication password. |
| `SMTP_FROM` | `skerry@localhost` | From address on outbound notifications. |
| `SMTP_USE_TLS` | `true` | `true` = STARTTLS on the configured port. `false` = implicit TLS (SMTP_SSL). |
| `OIDC_CLIENT_ID` | _(blank)_ | Azure AD Application (client) ID. Leave blank to disable SSO entirely. |
| `OIDC_CLIENT_SECRET` | _(blank)_ | Azure AD client secret value. Rotate before expiration. |
| `OIDC_DISCOVERY_URL` | _(blank)_ | OpenID Connect discovery endpoint. For Azure AD: `https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration` |
| `OIDC_ADMIN_GROUP` | _(blank)_ | Azure AD group Object ID → admin role. If any group variable is set, users not in a listed group are denied access. |
| `OIDC_OPERATOR_GROUP` | _(blank)_ | Azure AD group Object ID → operator role. |
| `OIDC_VIEWER_GROUP` | _(blank)_ | Azure AD group Object ID → viewer role. |
| `ADMIN_USERNAME` | `admin` | Bootstrap admin login username. Used only on first start to create the account. Ignored on subsequent starts. |
| `ADMIN_EMAIL` | `admin@example.com` | Bootstrap admin email address. Do not change it after first start: a new value creates a second admin account. |
| `ADMIN_NAME` | `Administrator` | Bootstrap admin display name. |
| `ADMIN_PASSWORD` | _(blank)_ | Bootstrap admin password, 12 characters or more. If blank, a random one is generated and printed once to the startup log. |
| `GUNICORN_TIMEOUT` | `300` | Seconds one web request may run before Gunicorn restarts the worker. The Spotlight sync is not bound by it. Takes effect on `docker compose up -d`; no rebuild. |
| `SESSION_COOKIE_SECURE` | `true` | Send the session cookie over HTTPS only. Set `false` only for plain-HTTP local development. |
| `SESSION_LIFETIME_HOURS` | `12` | How long a signed-in session lasts. |
| `REMEMBER_COOKIE_DAYS` | `7` | How long "remember me" lasts. |
| `LOGIN_RATE_LIMIT` | `10 per 15 minutes` | Failed-login throttle per client. |
| `RATELIMIT_STORAGE_URI` | `memory://` | Where the throttle counts live. Memory is right for one worker; counts reset on restart. |
| `FALCON_CLIENT_ID` | _(blank)_ | CrowdStrike API client ID. One scope: Spotlight vulnerabilities, Read. |
| `FALCON_CLIENT_SECRET` | _(blank)_ | CrowdStrike API client secret. |
| `FALCON_CLOUD_REGION` | `us-1` | `us-1`, `us-2`, `eu-1`, `us-gov-1`, or `us-gov-2`. The wrong region returns 401 with a valid key. |
| `FALCON_BASE_URL` | _(blank)_ | Sets the API URL directly; overrides the region. |
| `FALCON_HTTP_TIMEOUT` | `60` | Seconds per CrowdStrike API call. |
| `SPOTLIGHT_FQL_FILTER` | `status:'open',status:'reopen'` | The FQL filter the sync sends. Required by the API; narrow it for a large tenant. |
| `SPOTLIGHT_SEVERITIES` | `CRITICAL,HIGH` | Severities kept in the queue, enforced in Skerry on every record. |
| `SPOTLIGHT_PAGE_SIZE` | `400` | Records per API page. |
| `SPOTLIGHT_SYNC_ENABLED` | `false` | Turns on the nightly sync. Manual syncs work either way. |
| `SPOTLIGHT_SYNC_HOUR` | `5` | Hour of the nightly sync, container time. |
| `SPOTLIGHT_SYNC_MINUTE` | `30` | Minute of the nightly sync. |
