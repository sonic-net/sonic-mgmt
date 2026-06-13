"""Shared constants for the CMIS test package.

Kept in a standalone module (rather than in a test module) so that
``conftest.py`` and ``test_cdb_background_mode.py`` can both import them
without ``conftest`` importing from a test module -- an anti-pattern that
couples conftest import to test-module collection.
"""

# Stem for the /tmp counter/PGID file names written on the DUT by the CDB
# background-mode stress test's ``_RemoteBgReader``.  The test appends
# per-run suffixes; the session-scoped cleanup fixture in this package's
# conftest.py globs ``<prefix>_*`` to sweep anything a SIGKILL'd run leaks.
BG_READER_TMP_PREFIX = "/tmp/test_cmis_bg"
