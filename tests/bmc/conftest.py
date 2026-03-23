import pytest

from tests.common.helpers.assertions import pytest_assert


@pytest.fixture(scope="module")
def bmc_duthost(duthosts, rand_one_dut_hostname):
    """Get the BMC DUT host and assert it is actually a BMC."""
    duthost = duthosts[rand_one_dut_hostname]
    pytest_assert(duthost.is_bmc(), "This test requires a BMC DUT")
    return duthost


@pytest.fixture(scope="module")
def bmc_host_side(bmc_duthost):
    """Get the host (CPU) side SonicHost associated with this BMC."""
    return bmc_duthost.get_bmc_host()
