import pytest
import logging
from tests.common.utilities import wait_until
from tests.common import config_reload


pytestmark = [
    pytest.mark.topology('any'),
]

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        LAG tests are triggering following syncd complaints but the don't cause
        harm to DUT.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    # when loganalyzer is disabled, the object could be None
    if loganalyzer:
        ignoreRegex = [
            ".*",
        ]
        loganalyzer.ignore_regex.extend(ignoreRegex)
        expectRegex = [
            ".*teamd#teammgrd: :- cleanTeamProcesses.*",
            ".*teamd#teamsyncd: :- cleanTeamSync.*"
        ]
        loganalyzer.expect_regex.extend(expectRegex)


def check_kernel_po_interface_cleaned(duthost):
    res = duthost.shell("ip link show | grep -c PortChannel",  module_ignore_errors=True)["stdout_lines"][0].decode("utf-8")
    return res == '0'


def test_po_cleanup(duthost):
    """
    test port channel are cleaned up correctly and teammgrd and teamsyncd process
    handle  SIGTERM gracefully
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    if len(mg_facts['minigraph_portchannels'].keys()) == 0:
        pytest.skip("Skip test due to there is no portchannel exists in current topology.")

    try:
        logging.info("Disable Teamd Feature")
        duthost.shell("sudo config feature state teamd disabled")
        # Check if Linux Kernel Portchannel Interface teamdev are clean up
        if not wait_until(10, 1, check_kernel_po_interface_cleaned, duthost):
            fail_msg = "PortChannel interface still exists in kernel"
            pytest.fail(fail_msg)
    finally:
        # Do config reload to restor everything back
        logging.info("Reloading config..")
        config_reload(duthost)
