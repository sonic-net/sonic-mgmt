import logging
import pytest
from postupgrade_helper import run_postupgrade_actions, run_bgp_neighbor

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    ignoreRegex = [
        # The postupgrade script will forcibly stop auditd, which will consequently terminate audisp-tacplus.
        ".*plugin /sbin/audisp-tacplus terminated unexpectedly*",
        # The postupgrade script will restart the network service, which may temporarily disrupt the TACACS connection.
        ".*tac_connect_single: connection failed with*",
        ".*nss_tacplus: failed to connect TACACS+ server*",
    ]
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


def test_postupgrade_actions(duthosts, localhost, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    run_postupgrade_actions(duthost, localhost, tbinfo, True, False)


def test_bgp_neighbors(duthosts, localhost, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    run_bgp_neighbor(duthost, localhost, tbinfo, True)
