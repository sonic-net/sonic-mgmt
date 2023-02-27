import pytest
import os
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]
SYSTEM_STABILIZE_MAX_TIME = 300
logger = logging.getLogger(__name__)


def upload_metadata_scripts(duthost):
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"\
            .format(metadata_scripts_path))

    path_exists = duthost.stat(path="/tmp/anpscripts/")
    if not path_exists["stat"]["exists"]:
        duthost.command("mkdir /tmp/anpscripts")
        duthost.copy(src=metadata_scripts_path + "/", dest="/tmp/anpscripts/")


def test_mirror_session_script(duthost, request):
    metadata_process = request.config.getoption('metadata_process')
    if not metadata_process:
        # this test case is only for sonic-metadata script test
        return

    # upload scripts
    upload_metadata_scripts(duthost)

    duthost.command("chmod +x /tmp/anpscripts/mirror_session.py")

    # create empty entry json file.
    logger.info("create empty entry json file")
    out = duthost.command("bash -c 'echo {}>/tmp/test_session.json'")
    pytest_assert(out['rc'] == 0, out['stderr'])

    # create test entry
    logger.info("create new test mirror session")
    out = duthost.command("python /tmp/anpscripts/mirror_session.py create /tmp/test_session")
    pytest_assert(out['rc'] == 0, out['stderr'])

    # delete test entry
    logger.info("delete test mirror session")
    out = duthost.command("python /tmp/anpscripts/mirror_session.py delete /tmp/test_session")
    pytest_assert(out['rc'] == 0, out['stderr'])
