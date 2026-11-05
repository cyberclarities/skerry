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


def test_version_has_two_or_three_parts():
    """1.7 for a feature release, 1.7.1 and on for revisions to it."""
    assert re.fullmatch(r"\d+\.\d+(\.[1-9]\d*)?", __version__), __version__


def test_reports_is_one_collapsible_group_with_the_excel_export():
    c = _make_app().test_client()
    _login(c)
    html = c.get("/dashboard").get_data(as_text=True)
    group = html[html.index('id="nav-reports"'):html.index("</details>")]
    assert 'data-keep-open="no"' in group
    for link in ("/reports/briefing", "/reports/overdue", "/reports/reviews", "Excel Export"):
        assert link in group, link
    assert '<div class="nav-section">Export</div>' not in html
    on_report = c.get("/reports/overdue").get_data(as_text=True)
    assert 'id="nav-reports" data-keep-open="yes"' in on_report


def test_admin_is_a_collapsible_group_for_admins_only():
    from test_security_fixes import OPERATOR_PW, _make_operator
    app = _make_app()
    c = app.test_client()
    _login(c)
    html = c.get("/dashboard").get_data(as_text=True)
    start = html.index('id="nav-admin"')
    group = html[start:html.index("</details>", start)]
    assert 'data-keep-open="no"' in group
    for link in ("User Management", "Settings", "Spotlight Sync"):
        assert link in group, link
    for page in ("/users/", "/settings/", "/ingest/runs"):
        resp = c.get(page, follow_redirects=True)
        assert 'id="nav-admin" data-keep-open="yes"' in resp.get_data(as_text=True), page

    _make_operator(app)
    op = app.test_client()
    _login(op, "op", OPERATOR_PW)
    assert 'id="nav-admin"' not in op.get("/dashboard").get_data(as_text=True)
