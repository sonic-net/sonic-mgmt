"""CMIS test-category conftest.

Houses fixtures that only apply to the CMIS-specific tests under
``tests/transceiver/eeprom/cmis/``.

Currently provides a single defensive cleanup fixture for the CDB
background-mode stress test.  That test launches a long-lived bash loop on
the DUT (under ``setsid``) that writes counter and PGID files to ``/tmp``;
when pytest exits normally those files are removed by
``_RemoteBgReader.join()``, but when pytest is SIGKILL'd (CI timeout,
operator ^C^C, OOM) the loop's EXIT trap may not run and the temp files
leak.  This fixture sweeps any leftovers before the session starts and
again on teardown so a subsequent run cannot pick up stale counters.
"""
import logging

import pytest

# Pull the prefix from the test module so the cleanup pattern is guaranteed
# to track any future rename of the temp-file stem.
from tests.transceiver.eeprom.cmis.test_cdb_background_mode import (
    BG_READER_TMP_PREFIX,
)

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="session")
def _cleanup_stale_cdb_bg_tmpfiles(duthost):
    """Remove any ``/tmp/test_cmis_bg_*`` files on the DUT before and after the
    session, so a previously-aborted pytest run can't contaminate this one.

    Idempotent and cheap (``rm -f`` of a glob with no matches is a no-op).
    """
    cleanup_cmd = f"rm -f {BG_READER_TMP_PREFIX}_*"
    logger.debug("Pre-session cleanup of stale CDB bg-reader temp files: %s", cleanup_cmd)
    duthost.shell(cleanup_cmd, module_ignore_errors=True)
    yield
    logger.debug("Post-session cleanup of CDB bg-reader temp files: %s", cleanup_cmd)
    duthost.shell(cleanup_cmd, module_ignore_errors=True)
