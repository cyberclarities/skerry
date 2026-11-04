"""The version shown in the app, and the docs that must agree with it."""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_security_fixes import _login, _make_app  # noqa: E402

from app.version import __version__  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    return open(os.path.join(ROOT, name), encoding="utf-8").read()


def test_version_is_shown_under_the_logo():
    c = _make_app().test_client()
    _login(c)
    html = c.get("/dashboard").get_data(as_text=True)
    brand = html[html.index('class="brand"'):html.index("<nav>")]
    assert f'id="app-version">Version {__version__}</div>' in brand


def test_version_is_not_shown_to_anyone_signed_out():
    """A version number tells an outsider which build to look up."""
    c = _make_app().test_client()
    assert f"Version {__version__}" not in c.get("/login").get_data(as_text=True)
    assert __version__ not in str(c.get("/health").get_json())


def test_docs_agree_with_the_version():
    """Bumping app/version.py alone fails here until the docs follow."""
    newest = re.search(r"^## (\S+) \(", _read("CHANGELOG.md"), re.M).group(1)
    assert newest == __version__, "add a CHANGELOG.md entry for this version"
    assert f"| **PackageVersion** | {__version__} |" in _read("SBOM.md")
    assert f"**Version:** {__version__}" in _read("USER_GUIDE.md")
