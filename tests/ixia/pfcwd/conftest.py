import pytest

@pytest.fixture(scope="module", autouse=True)
def start_pfcwd_default_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that PFC watchdog is enabled with default setting after tests

    Args:
       duthosts (pytest fixture) : list of DUTs
       rand_one_dut_hostname (pytest fixture): DUT hostname
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sudo pfcwd start_default')
