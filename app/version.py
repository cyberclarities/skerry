"""The application version, shown under the logo in the sidebar.

To release a new version:
  1. Change __version__ below.
  2. Add an entry at the top of CHANGELOG.md for it.
  3. Update PackageVersion in SBOM.md and the Version line in USER_GUIDE.md.

tests/test_version.py fails until all four agree, so a bump cannot leave
the docs behind.

Numbering: the first number moves for a change in how the app is used or
deployed that people need to be told about; the second for everything else.
"""

__version__ = "1.4"
