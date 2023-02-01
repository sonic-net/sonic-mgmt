import pytest
import logging
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

pytestmark = [
    pytest.mark.topology('any'),
]

LOG_EXPECT_PO_CLEANUP_RE = "cleanTeamProcesses: Sent SIGTERM to port channel.*{}.*"

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

def test_po_cleanup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_asic_index, tbinfo):
    """
    test port channel are cleaned up correctly and teammgrd and teamsyncd process
    handle  SIGTERM gracefully
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Disable swss/teamd Feature in all asics")
    # Following will call "sudo systemctl stop swss@0", same for swss@1 ..
    duthost.stop_service("swss")
    # Check if Linux Kernel Portchannel Interface teamdev are clean up
    for asic_id in duthost.get_asic_ids():
        if not wait_until(10, 1, 0, check_kernel_po_interface_cleaned, duthost, asic_id):        
            fail_msg = "PortChannel interface still exists in kernel"
            pytest.fail(fail_msg)
    # Restore config services
    config_reload(duthost)
    
def test_po_cleanup_after_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    test port channel are cleaned up correctly after config reload, with system under stress.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    host_facts = duthost.setup()['ansible_facts']

    # Get the cpu information.
    if host_facts.has_key("ansible_processor_vcpus"):
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logging.info("found {} cpu on the dut".format(host_vcpus))

    # Get portchannel facts and interfaces.
    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
    port_channel_intfs = lag_facts['names'].keys()

    # Add start marker to the DUT syslog
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='port_channel_cleanup')
    loganalyzer.expect_regex = []
    for pc in port_channel_intfs:
        loganalyzer.expect_regex.append(LOG_EXPECT_PO_CLEANUP_RE.format(pc))

    try:
        # Make CPU high
        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        with loganalyzer:
            logging.info("Reloading config..")
            config_reload(duthost)

        duthost.shell("killall yes")
    except:
        duthost.shell("killall yes")
        raise
