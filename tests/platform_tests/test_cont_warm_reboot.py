"""
Test for continuously warm rebooting the DUT
In between warm reboots, verify:
Reboot cause (should match the trigger cause)
Status of services (Services syncd and swss should be active/running)
Status of interfaces and LAGs (all interface and LAGs should comply with current topology)
Status of transceivers (ports in lab_connection_graph should be present)
Status of BGP neighbors (should be established)
"""
import os
import sys
import pytest

from check_critical_services import check_critical_services
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait
from tests.common.utilities import wait_until
from tests.common.reboot import check_reboot_cause, reboot_ctrl_dict, logging, reboot, REBOOT_TYPE_WARM
from tests.common.platform.interface_utils import check_interface_information
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.plugins.sanity_check import checks

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0-soak')
]

MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120


def reboot_and_check(localhost, dut, interfaces, reboot_type=REBOOT_TYPE_WARM, reboot_kwargs=None):
    """
    Perform the specified type of reboot and check platform status.
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
    @param reboot_kwargs: The argument used by reboot_helper
    """
    logging.info("Run %s reboot on DUT" % reboot_type)

    reboot(dut, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=reboot_kwargs)

    # Perform health-check
    check_services(dut)
    check_reboot_type(dut, reboot_type)
    check_interfaces_and_transceivers(dut, interfaces)
    check_neighbors(dut)


def check_services(dut):
    """
    Perform a health check of services
    @param dut: The AnsibleHost object of DUT.
    """
    logging.info("Wait until all critical services are fully started")
    check_critical_services(dut)


def check_reboot_type(dut, reboot_type=None):
    """
    Perform a match of reboot-cause and reboot-trigger
    @param dut: The AnsibleHost object of DUT.
    """
    if reboot_type is not None:
        logging.info("Check reboot cause")
        pytest_assert(wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, check_reboot_cause, dut, reboot_type), \
            "got reboot-cause failed after rebooted by %s" % reboot_type)

        if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
            logging.info("Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
            return


def check_interfaces_and_transceivers(dut, interfaces):
    """
    Perform a check of transceivers, LAGs and interfaces status
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Wait %d seconds for all the transceivers to be detected" % MAX_WAIT_TIME_FOR_INTERFACES)
    pytest_assert(wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, check_interface_information, dut, interfaces), \
        "Not all transceivers are detected or interfaces are up in %d seconds" % MAX_WAIT_TIME_FOR_INTERFACES)

    logging.info("Check transceiver status")
    check_transceiver_basic(dut, interfaces)

    logging.info("Check LAGs and interfaces status")
    checks.check_interfaces(dut)


def check_neighbors(dut):
    """
    Perform a BGP neighborship check.
    @param dut: The AnsibleHost object of DUT.
    """
    logging.info("Check BGP neighbors status. Expected state - established")
    bgp_facts = dut.bgp_facts()['ansible_facts']
    mg_facts  = dut.minigraph_facts(host=dut.hostname)['ansible_facts']

    for value in bgp_facts['bgp_neighbors'].values():
        # Verify bgp sessions are established
        pytest_assert(value['state'] == 'established', "BGP session not established")
        # Verify locat ASNs in bgp sessions
        pytest_assert(value['local AS'] == mg_facts['minigraph_bgp_asn'], \
          "Local ASNs not found in BGP session")

    for v in mg_facts['minigraph_bgp']:
        # Compare the bgp neighbors name with minigraph bgp neigbhors name
        pytest_assert(v['name'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['description'], \
          "BGP neighbor's name does not match minigraph")
        # Compare the bgp neighbors ASN with minigraph
        pytest_assert(v['asn'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS'], \
          "BGP neighbor's ASN does not match minigraph")


def test_cont_warm_reboot(duthost, localhost, conn_graph_facts, continuous_reboot_count, continuous_reboot_delay):
    """
    @summary: This test case is to perform continuous warm reboot in a row
    """
    asic_type = duthost.facts["asic_type"]
    if asic_type in ["mellanox"]:
        issu_capability = duthost.command("show platform mlnx issu")["stdout"]
        if "disabled" in issu_capability:
            pytest.skip("ISSU is not supported on this DUT, skip this test case")

    for _ in range(continuous_reboot_count):
        reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_WARM)
        wait(continuous_reboot_delay, msg="Wait {}s before next warm-reboot".format(continuous_reboot_delay))
