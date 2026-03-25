import re
import pytest
import logging

from tests.common.fixtures.duthost_utils import stop_route_checker_on_duthost
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.utilities import wait_until
from tests.common import config_reload

pytestmark = [
    pytest.mark.disable_route_check,
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


@pytest.fixture(autouse=True)
def disable_route_check_for_duthost(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    allowed_topologies = {"t2", "ut2", "lt2"}
    topo_name = tbinfo['topo']['name']
    if topo_name in allowed_topologies:
        logging.info("Stopping route check monitor before test case")
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for duthost in duthosts.frontend_nodes:
                executor.submit(stop_route_checker_on_duthost, duthost, wait_for_status=True)
    else:
        logging.info("Topology {} is not allowed for disable_route_check_for_duthost fixture".format(topo_name))

    yield


def check_kernel_po_interface_cleaned(duthost, asic_index):
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    res = duthost.shell(duthost.get_linux_ip_cmd_for_namespace("ip link show | grep -c PortChannel", namespace),
                        module_ignore_errors=True)["stdout_lines"][0]
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
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


def test_po_cleanup_after_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    test port channel are cleaned up correctly after config reload, with system under stress.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    host_facts = duthost.setup()['ansible_facts']

    # Get the cpu information.
    if "ansible_processor_vcpus" in host_facts:
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logging.info("found {} cpu on the dut".format(host_vcpus))

    # Get portchannel facts and interfaces.
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    port_channel_intfs = list(lag_facts['names'].keys())

    # Record current syslog size so we only search new entries later.
    # We avoid the LogAnalyzer context manager here because its start/end
    # markers are sent through the syslog UDP socket (/dev/log).  Under
    # heavy CPU load combined with the syslog storm from restarting all
    # containers, the host rsyslogd UDP receive buffer overflows and
    # silently drops marker messages, causing a spurious RuntimeError.
    # Grepping the syslog directly is immune to this.
    start_line = int(duthost.shell("wc -l /var/log/syslog")['stdout'].split()[0])

    try:
        # Make CPU high
        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        logging.info("Reloading config..")
        config_reload(duthost, wait=240, safe_reload=True, wait_for_bgp=True)
    finally:
        duthost.shell("killall yes", module_ignore_errors=True)

    # Verify that port channel cleanup logs appeared during the reload.
    syslog_tail = duthost.shell(
        "tail -n +{} /var/log/syslog".format(start_line),
        module_ignore_errors=True)['stdout']
    for pc in port_channel_intfs:
        pattern = LOG_EXPECT_PO_CLEANUP_RE.format(pc)
        assert re.search(pattern, syslog_tail), \
            "Missing port channel cleanup log for {}".format(pc)
