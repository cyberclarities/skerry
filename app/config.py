import os
from datetime import timedelta


def _flag(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


class Config:
    # SECRET_KEY intentionally has no fallback. A silent dev default that
    # survives into production is a forged session waiting to happen, so
    # create_app() refuses to start when this is empty or left at a placeholder.
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:////app/data/risk_register.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True

    # ── Session and cookie hardening ─────────────────────────────────────────
    # Secure-by-default. For plain-HTTP local development set
    # SESSION_COOKIE_SECURE=false in your .env, and set it back for anything
    # anyone else can reach.
    SESSION_COOKIE_SECURE = _flag("SESSION_COOKIE_SECURE", "true")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_DURATION = timedelta(
        days=int(os.environ.get("REMEMBER_COOKIE_DAYS", 7))
    )
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.environ.get("SESSION_LIFETIME_HOURS", 12))
    )

    # ── Login throttling ─────────────────────────────────────────────────────
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per 15 minutes")
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # Risk scoring thresholds
    RAG_RED_THRESHOLD = int(os.environ.get("RAG_RED_THRESHOLD", 15))
    RAG_AMBER_THRESHOLD = int(os.environ.get("RAG_AMBER_THRESHOLD", 9))
    RISK_APPETITE_THRESHOLD = int(os.environ.get("RISK_APPETITE_THRESHOLD", 8))
    RISK_ID_PREFIX = os.environ.get("RISK_ID_PREFIX", "SKR")

    # -- CrowdStrike Falcon Spotlight ingest ---------------------------------
    # The API client should carry ONE scope: Spotlight vulnerabilities: READ.
    # Nothing in this integration writes back to CrowdStrike, so a key with
    # more than read on one service is more key than the job needs.
    FALCON_CLIENT_ID = os.environ.get("FALCON_CLIENT_ID", "")
    FALCON_CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET", "")
    # us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2. The wrong region returns 401
    # with a perfectly valid key, so this is explicit rather than guessed.
    FALCON_CLOUD_REGION = os.environ.get("FALCON_CLOUD_REGION", "us-1")
    FALCON_BASE_URL = os.environ.get("FALCON_BASE_URL", "")  # overrides region
    FALCON_HTTP_TIMEOUT = int(os.environ.get("FALCON_HTTP_TIMEOUT", 60))

    # The Spotlight API requires an FQL filter -- there is no "everything"
    # query. Default pulls currently-open findings that are not suppressed.
    # Widen or narrow this per tenant; a 40,000-host estate should probably
    # add cve.severity or host_info.asset_criticality to keep the queue
    # something a person can actually work.
    SPOTLIGHT_FQL_FILTER = os.environ.get(
        "SPOTLIGHT_FQL_FILTER",
        "status:'open',status:'reopen'",
    )
    SPOTLIGHT_PAGE_SIZE = int(os.environ.get("SPOTLIGHT_PAGE_SIZE", 400))
    SPOTLIGHT_SYNC_ENABLED = _flag("SPOTLIGHT_SYNC_ENABLED", "false")

    # Severities the ingest keeps (CVE severity as Spotlight reports it).
    # Enforced in Skerry on every record, whatever SPOTLIGHT_FQL_FILTER says,
    # so the queue holds only what someone should act on.
    SPOTLIGHT_SEVERITIES = tuple(
        s.strip().upper()
        for s in os.environ.get("SPOTLIGHT_SEVERITIES", "CRITICAL,HIGH").split(",")
        if s.strip()
    )
    SPOTLIGHT_SYNC_HOUR = int(os.environ.get("SPOTLIGHT_SYNC_HOUR", 5))
    SPOTLIGHT_SYNC_MINUTE = int(os.environ.get("SPOTLIGHT_SYNC_MINUTE", 30))

    # SMTP
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "skerry@localhost")
    SMTP_USE_TLS = _flag("SMTP_USE_TLS", "true")

    # OIDC (optional)
    OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
    OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")

    # Azure AD group Object IDs → role mapping (optional).
    OIDC_ADMIN_GROUP = os.environ.get("OIDC_ADMIN_GROUP", "")
    OIDC_OPERATOR_GROUP = os.environ.get("OIDC_OPERATOR_GROUP", "")
    OIDC_VIEWER_GROUP = os.environ.get("OIDC_VIEWER_GROUP", "")

    # Base URL — used in email notification links (set to your public hostname)
    BASE_URL = os.environ.get("BASE_URL", "https://localhost")

    # Bootstrap admin
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    ADMIN_NAME = os.environ.get("ADMIN_NAME", "Administrator")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


# Values we refuse to boot with — placeholders that mean "nobody set this yet."
PLACEHOLDER_SECRETS = {
    "",
    "change-me-to-a-long-random-string",
    "dev-secret-change-me",
    "changeme",
    "secret",
}
