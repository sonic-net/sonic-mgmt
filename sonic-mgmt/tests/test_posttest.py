import pytest
import logging
import os.path

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.posttest,
    pytest.mark.topology('util'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]


def test_collect_techsupport(duthost):
    """
    A util for collecting techsupport after tests.

    Since nightly test on Jenkins will do a cleanup at the beginning of tests,
    we need a method to save history logs and dumps. This util does the job.
    """
    logger.info("Collecting techsupport since yesterday")
    # Because Jenkins is configured to save artifacts from tests/logs,
    # and this util is mainly designed for running on Jenkins,
    # save path is fixed to logs for now.
    TECHSUPPORT_SAVE_PATH = 'logs/'
    out = duthost.command("generate_dump -s yesterday", module_ignore_errors=True)
    if out['rc'] == 0:
        tar_file = out['stdout_lines'][-1]
        duthost.fetch(src=tar_file, dest=TECHSUPPORT_SAVE_PATH, flat=True)

    assert True
