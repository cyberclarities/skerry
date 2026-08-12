"""Shared extension instances.

These live outside app/__init__.py so blueprints can import them without
tripping a circular import back through the application factory.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Throttles brute-force login attempts. Storage is in-process memory by
# default, which is correct for the shipped single-worker Gunicorn setup.
# If you scale to multiple workers or hosts, point RATELIMIT_STORAGE_URI at
# a shared backend (redis://...) or the counters drift per worker.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    headers_enabled=True,
)
