"""The application version, shown under the logo in the sidebar.

To release a new version:
  1. Change __version__ below.
  2. Add an entry at the top of CHANGELOG.md for it.
  3. Update PackageVersion in SBOM.md and the Version lines in USER_GUIDE.md
     and ADMIN_GUIDE.md.

tests/test_version.py fails until all five agree, so a bump cannot leave
the docs behind.

Numbering: the first number moves for a change in how the app is used or
deployed that people need to be told about; the second for a new feature or
report; the third, starting at .1, for a small revision on top of that
(1.7, then 1.7.1, 1.7.2). A new second number drops the third: 1.7.3 is
followed by 1.8, not 1.8.0.
"""

__version__ = "1.8"
