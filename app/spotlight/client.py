"""Falcon API client for Spotlight vulnerabilities.

Deliberately small. This wraps two calls -- get a token, page through
/spotlight/combined/vulnerabilities/v1 -- rather than pulling in the full
FalconPy SDK, because `requests` is already a dependency and the surface we
need is two endpoints wide.

Credentials come from config (environment), never from the database, and the
secret is never logged. The API client should be scoped to **Spotlight
vulnerabilities: READ** only; nothing here writes back to CrowdStrike, and a
key with more scope than that is a key that can do more damage than this
integration needs.
"""

import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)

# Falcon cloud regions. The wrong base URL returns 401 with a valid key,
# which is a confusing failure -- so the region is an explicit setting, not
# a guess.
CLOUD_REGIONS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

# Facets are what turn a bare vulnerability record into something useful.
# Without `cve` there is no severity or ExPRT rating; without `host_info`
# there is no hostname, only an agent ID.
DEFAULT_FACETS = ("cve", "host_info", "remediation")

MAX_LIMIT = 400  # combined endpoint allows 5000; 400 keeps responses sane


class SpotlightError(RuntimeError):
    """Any failure talking to Falcon. Carries enough to act on."""


class FalconSpotlightClient:
    def __init__(self, client_id, client_secret, region="us-1", base_url=None,
                 timeout=60, verify=True):
        if not client_id or not client_secret:
            raise SpotlightError(
                "Falcon API credentials are not configured. Set "
                "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET."
            )
        self.client_id = client_id
        self.client_secret = client_secret
        if base_url:
            _check_base_url(base_url)
        self.base_url = (base_url or CLOUD_REGIONS.get(region) or "").rstrip("/")
        if not self.base_url:
            raise SpotlightError(
                f"Unknown Falcon region '{region}'. Valid values: "
                f"{', '.join(sorted(CLOUD_REGIONS))} -- or set FALCON_BASE_URL."
            )
        self.timeout = timeout
        self.verify = verify
        self._token = None
        self._token_expires_at = 0.0
        self._session = requests.Session()

    # -- auth ---------------------------------------------------------------
    def _authenticate(self):
        """OAuth2 client-credentials. Tokens last 30 minutes; we refresh at 25."""
        resp = self._session.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.timeout,
            verify=self.verify,
        )
        if resp.status_code == 403:
            raise SpotlightError(
                "Falcon rejected the credentials (403). Check the client ID and "
                "secret, and that the key is issued in the same cloud region."
            )
        if resp.status_code != 201:
            raise SpotlightError(
                f"Falcon token request failed: HTTP {resp.status_code} "
                f"{_safe_error(resp)}"
            )
        body = resp.json()
        self._token = body.get("access_token")
        if not self._token:
            raise SpotlightError("Falcon returned no access_token.")
        expires_in = int(body.get("expires_in", 1800))
        self._token_expires_at = time.time() + max(60, expires_in - 300)
        log.info("Falcon token acquired, valid ~%ss", expires_in)

    def _headers(self):
        if not self._token or time.time() >= self._token_expires_at:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    # -- fetch --------------------------------------------------------------
    def iter_vulnerabilities(self, fql_filter, limit=MAX_LIMIT, facets=DEFAULT_FACETS,
                             max_pages=500):
        """Yield (page_number, [resources]) from the combined endpoint.

        A generator rather than a list: a large tenant returns tens of
        thousands of findings, and holding all of them in memory to then
        write them one at a time buys nothing.

        `fql_filter` is required by the API -- there is no "everything"
        query. See config.SPOTLIGHT_FQL_FILTER for the default.
        """
        if not fql_filter:
            raise SpotlightError(
                "An FQL filter is required by the Spotlight API. "
                "The default is set in SPOTLIGHT_FQL_FILTER."
            )

        after = None
        page = 0
        url = f"{self.base_url}/spotlight/combined/vulnerabilities/v1"

        while page < max_pages:
            params = [("filter", fql_filter), ("limit", min(limit, MAX_LIMIT))]
            for facet in facets:
                params.append(("facet", facet))
            if after:
                params.append(("after", after))

            resp = self._request_with_retry(url, params)
            body = resp.json()

            errors = body.get("errors") or []
            if errors:
                raise SpotlightError(f"Falcon returned errors: {errors}")

            resources = body.get("resources") or []
            page += 1
            yield page, resources

            pagination = (body.get("meta") or {}).get("pagination") or {}
            after = pagination.get("after")
            # No token, or a short page, means we are done. Both checks --
            # the API has returned an empty token on the last full page.
            if not after or not resources:
                return

        log.warning("Stopped at max_pages=%s; results may be incomplete.", max_pages)

    def _request_with_retry(self, url, params, attempts=4):
        """GET with backoff on 429 and 5xx.

        Falcon publishes the wait on 429 via X-RateLimit-RetryAfter (an epoch
        second). Honour it rather than guessing -- guessing is how an
        integration gets a key throttled for everyone else using it.
        """
        last_error = None
        for attempt in range(1, attempts + 1):
            try:
                resp = self._session.get(
                    url, params=params, headers=self._headers(),
                    timeout=self.timeout, verify=self.verify,
                )
            except requests.RequestException as exc:
                last_error = f"network error: {exc}"
                time.sleep(min(2 ** attempt, 30))
                continue

            if resp.status_code == 200:
                return resp

            if resp.status_code == 401:
                # Token expired mid-run. Re-auth once, then let it fail loudly.
                self._token = None
                last_error = "401 unauthorized"
                if attempt < attempts:
                    continue

            if resp.status_code == 429:
                retry_at = resp.headers.get("X-RateLimit-RetryAfter")
                wait = 5
                if retry_at:
                    try:
                        wait = max(1, int(retry_at) - int(time.time()))
                    except ValueError:
                        pass
                wait = min(wait, 120)
                log.warning("Falcon rate limit hit; waiting %ss", wait)
                time.sleep(wait)
                last_error = "429 rate limited"
                continue

            if 500 <= resp.status_code < 600:
                last_error = f"HTTP {resp.status_code} {_safe_error(resp)}"
                time.sleep(min(2 ** attempt, 30))
                continue

            # 4xx that is not 401/429 will not fix itself on a retry.
            raise SpotlightError(
                f"Spotlight query failed: HTTP {resp.status_code} {_safe_error(resp)}"
            )

        raise SpotlightError(f"Spotlight query failed after {attempts} attempts: {last_error}")

    def test_connection(self):
        """Cheap credential check for the Settings page.

        Pulls exactly one record. Returns (ok, message) -- never raises, so
        the settings view can show the failure instead of a 500.
        """
        try:
            self._authenticate()
            for _page, resources in self.iter_vulnerabilities(
                "status:'open'", limit=1, max_pages=1
            ):
                return True, (
                    f"Connected to {self.base_url}. "
                    f"Query returned {len(resources)} record(s)."
                )
            return True, f"Connected to {self.base_url}. Query returned no records."
        except SpotlightError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001 -- surface, don't swallow
            return False, f"Unexpected error: {exc}"


ALLOWED_HOST_SUFFIXES = (".crowdstrike.com", ".crowdstrike.mil")


def _check_base_url(url):
    """FALCON_BASE_URL receives the client secret. Refuse anything that is
    not HTTPS to a CrowdStrike API host, so a typo cannot send it elsewhere."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(ALLOWED_HOST_SUFFIXES):
        raise SpotlightError(
            f"FALCON_BASE_URL must be an https:// URL on a CrowdStrike API host "
            f"(*.crowdstrike.com or *.crowdstrike.mil); got '{url}'."
        )


def _safe_error(resp):
    """Pull the message out of a Falcon error body without echoing secrets."""
    try:
        body = resp.json()
    except ValueError:
        return (resp.text or "")[:200]
    errors = body.get("errors") or []
    if errors:
        return "; ".join(str(e.get("message", e))[:200] for e in errors[:3])
    return str(body)[:200]


def parse_ts(value):
    """Falcon timestamps are RFC3339 with a Z. Return naive UTC, or None.

    Naive-UTC because the rest of the app stores naive datetimes; mixing
    aware and naive values is where comparison bugs come from.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
