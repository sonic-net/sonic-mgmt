import pytest


@pytest.fixture(scope="module")
def bmc_duthost(duthosts, rand_one_dut_hostname):
    """Get the BMC DUT host and assert it is actually a BMC."""
    duthost = duthosts[rand_one_dut_hostname]
    assert duthost.is_bmc(), "This test requires a BMC DUT"
    return duthost


@pytest.fixture(scope="module")
def bmc_host_side(bmc_duthost):
    """Get the host (CPU) side SonicHost associated with this BMC."""
    return bmc_duthost.get_bmc_host()
