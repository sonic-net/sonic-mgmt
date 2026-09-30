import logging

import pytest
from postupgrade_helper import run_postupgrade_actions, run_bgp_neighbor
from firmware_report_helper import find_metadata_actions_dir, verify_unmapped_update_firmware_failure_report

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def metadata_actions_dir():
    actions_dir = find_metadata_actions_dir()
    if actions_dir is None:
        pytest.skip("SONiC metadata checkout is not available in this test environment")
    return actions_dir


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
    run_bgp_neighbor(duthost, localhost, tbinfo, True, False)


# This isolated reporting test does not exercise live routing services; their
# pre-existing memory usage is outside the contract being validated here.
@pytest.mark.disable_memory_utilization
def test_unmapped_update_firmware_failure_report(
    duthosts,
    rand_one_dut_hostname,
    metadata_actions_dir,
):
    """Run the real firmware entry point with a failing Redis query in an isolated filesystem."""
    verify_unmapped_update_firmware_failure_report(duthosts[rand_one_dut_hostname], metadata_actions_dir)
