import pytest

from tests.common.utilities import skip_release

def pytest_configure(config):
    """ JsonPatch ordering will discard incorrect ordering and continue
        on next ordering. But LogAnalyzer will analyze failure on discarded
        ordering log, we will disable it for GCU and use our own ways of
        verification.
    """
    if not config.option.disable_loganalyzer:
        config.option.disable_loganalyzer = True

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106"])

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    """
    Config facts for selected DUT
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
