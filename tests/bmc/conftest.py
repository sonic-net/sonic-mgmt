import pytest

from tests.common.platform.bmc_utils import get_switch_host_or_skip_test


@pytest.fixture(scope="module")
def bmc_duthost(duthosts, rand_one_dut_hostname):
    """Get the BMC DUT host and assert it is actually a BMC."""
    duthost = duthosts[rand_one_dut_hostname]
    assert duthost.is_bmc(), "This test requires a BMC DUT"
    return duthost


@pytest.fixture(scope="module")
def bmc_host_side(bmc_duthost):
    """Get the host (CPU) side SonicHost associated with this BMC.

    Skips the test cleanly if the paired Switch-Host is not reachable from
    the test runner (e.g. not in inventory, no SSH path).
    """
    return get_switch_host_or_skip_test(bmc_duthost)
