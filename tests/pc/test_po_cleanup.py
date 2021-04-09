import pytest
import logging
from tests.common.utilities import wait_until
from tests.common import config_reload


pytestmark = [
    pytest.mark.topology('any'),
]

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
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
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)
        expectRegex = [
            ".*teammgrd: :- cleanTeamProcesses.*",
            ".*teamsyncd: :- cleanTeamSync.*"
        ]
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].expect_regex.extend(expectRegex)

def check_kernel_po_interface_cleaned(duthost, asic_index):
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    res = duthost.shell(duthost.get_linux_ip_cmd_for_namespace("ip link show | grep -c PortChannel", namespace),module_ignore_errors=True)["stdout_lines"][0].decode("utf-8")
    return res == '0'

@pytest.fixture(scope="module", autouse=True)
def check_topo_and_restore(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    if len(mg_facts['minigraph_portchannels'].keys()) == 0 and not duthost.is_multi_asic:
        pytest.skip("Skip test due to there is no portchannel exists in current topology.")
    yield 
    # Do config reload to restore everything back
    logging.info("Reloading config..")
    config_reload(duthost)

def test_po_cleanup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index, tbinfo):
    """
    test port channel are cleaned up correctly and teammgrd and teamsyncd process
    handle  SIGTERM gracefully
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Disable swss/teamd Feature")
    duthost.asic_instance(enum_asic_index).stop_service("swss")
    # Check if Linux Kernel Portchannel Interface teamdev are clean up
    if not wait_until(10, 1, check_kernel_po_interface_cleaned, duthost, enum_asic_index):
        fail_msg = "PortChannel interface still exists in kernel"
        pytest.fail(fail_msg)
