import logging
import random
import pytest
import re

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts, conn_graph_facts, get_graph_facts  # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps  # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory  # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses  # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file  # noqa F401
from tests.common.dualtor.dual_tor_utils import dualtor_ports, is_tunnel_qos_remap_enabled  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.qos.qos_sai_base import QosSaiBase
from tests.common import config_reload
from tests.qos.conftest import combine_qos_parameter # noqa F401
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(duthosts, loganalyzer):
    """ignore the syslog ERR syncd0#syncd: [03:00.0] brcm_sai_set_switch_
       attribute:1920 updating switch mac addr failed with error -2"""
    ignore_regex = [
        ".*ERR syncd[0-9]*#syncd.*brcm_sai_set_switch_attribute.*updating switch mac addr failed with error.*",
        # The following error log is related to the bug of https://github.com/sonic-net/sonic-buildimage/issues/13265
        ".*ERR lldp#lldpmgrd.*Command failed.*lldpcli.*configure.*ports.*unable to connect to socket.*",
        ".*ERR lldp#lldpmgrd.*Command failed.*lldpcli.*configure.*ports.*lldp.*unknown command from argument"
        ".*configure.*command was failed.*times, disabling retry.*"
        # Error related to syncd socket-timeout intermittenly
        ".*ERR syncd[0-9]*#dsserve: _ds2tty broken pipe.*"
    ]

    if loganalyzer:
        for a_dut in duthosts:
            hwsku = a_dut.facts["hwsku"]
            if "7050" in hwsku and "QX" in hwsku.upper():
                logger.info("ignore memory threshold check for 7050qx")
                # ERR memory_threshold_check: Free memory 381608 is less then free memory threshold 400382.4
                ignore_regex.append(".*ERR memory_threshold_check: Free memory .* is less then free memory threshold.*")
            loganalyzer[a_dut.hostname].ignore_regex.extend(ignore_regex)


@pytest.fixture(scope="module", autouse="True")
def files_generation(combine_qos_parameter):  # noqa F811
    logger.debug("For creation of qos.yml file")


class TestVoqCounter(QosSaiBase):
    """TestVoqCounter derives from QosSaiBase and contains collection of QoS SAI test cases.
    Note:
        This test implicitly verifies that queue counters --voq (i.e. Credit-WD-Del/pkts)
        are working as expected.
    """

    def test_voq_queue_counter(self, duthosts,
                               ptfhost, dutTestParams, dutConfig, get_src_dst_asic_and_duts):
        """
        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
            dutTestParams (Fixture, dict): DUT host test params
            dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                and test port.
        The Counter are reset on read issue is open
        """
        testParams = dict()
        testParams.update(dutTestParams["basicParams"])
        testParams.update({
            "dst_port_id": dutConfig["testPorts"]["dst_port_id"],
            "dst_port_ip": dutConfig["testPorts"]["dst_port_ip"],
            "src_port_id": dutConfig["testPorts"]["src_port_id"],
            "src_port_ip": dutConfig["testPorts"]["src_port_ip"],
        })
        dest_ip = dutConfig['testPorts']['dst_port_ip']
        mg_facts = dutConfig['dstDutInstance'].get_extended_minigraph_facts(ptfhost.tbinfo)
        name = next((item['name'] for item in mg_facts['minigraph_bgp'] if item['addr'] == dest_ip), None)
        interface = [key for key, value in mg_facts['minigraph_neighbors'].items() if value['name'] == name]
        inter_str = '|'.join(interface)
        asichost = dutConfig['srcDutInstance'].asics[testParams['src_asic_index']]
        filter_str = dutConfig['dstDutInstance'].hostname + "|asic" + str(testParams['dst_asic_index'])
        cmd = "show queue counters --voq --nonzero| grep -i '{}'|grep -E '{}' |awk '{{print $7}}'".format(filter_str,
                                                                                                          inter_str)
        asic_cmd = "{} {}".format(asichost.ns_arg, cmd)
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.VOQ_drop_Countertest", testParams=testParams, async_mode=True
        )

        def queue_counter_assertion():
            out = asichost.shell(asic_cmd)['stdout'].split('\n')
            integers = [int(item.replace(',', '')) for item in out if item.replace(',', '').strip().isdigit()]
            return any(num > 0 for num in integers)

        pytest_assert(wait_until(300, 0, 0, queue_counter_assertion), "Credit-WD-Del/pkts is not incresing")


def test_voq_drop_counter(duthosts, tbinfo, ptfadapter,
                          nbrhosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asichost = duthost.asic_instance(enum_rand_one_asic_index)
    bcm_changes = False
    # Ensure the device is a Broadcom device
    pytest_require((duthost.facts.get('platform_asic') == "broadcom-dnx"),
                   "The Test Case is only supported on Broadcom-dnx ASIC")
    # If the DUT is a supervisor node
    if duthost.is_supervisor_node():
        # Retrieve active ASIC list from the chassis state database
        out = duthost.command("sonic-db-cli CHASSIS_STATE_DB keys \"CHASSIS_FABRIC_ASIC_TABLE|asic*\"")['stdout']
        active_asic_list = [int(n) for n in re.findall(r'asic(\d+)', out)]
        if enum_rand_one_asic_index not in active_asic_list:
            # If the randomly selected ASIC index is not active, update it
            logging.info("Selected Enum Index in not Active on Supervisor. Updating asic ")
            enum_rand_one_asic_index = random.choice(active_asic_list)
            asichost = duthost.asic_instance(enum_rand_one_asic_index)
        # Broadcom command sequence for Broadcom chips to induce CRC Error on CPM
        cmd_bcmcmd = [line.strip() for line in open('voq/files/CRC_ERROR_SUP', 'r')]
    else:
        pytest.skip("Skipping the Test Case Because of Open Issue ")
        # Boadcom command sequence for Broadcom  chips to induce CRC Error on LC
        cmd_bcmcmd = [line.strip() for line in open('voq/files/CRC_Error_LC', 'r')]
    drop_cmd = "show dropcounters counts "
    out = duthost.show_and_parse("{} {}".format(asichost.ns_arg, drop_cmd))[0]['pkt_integrity_err']
    pre_count = int(out if out.strip().isdigit() else pytest.fail("PKT_INTEGRITY_ERR Count Error"))
    try:
        bcm_changes = True
        for cmd in cmd_bcmcmd:
            cmd = "bcmcmd {} ".format("-n " + str(enum_rand_one_asic_index)) + cmd
            res = duthost.shell(cmd, module_ignore_errors=True)
            if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                pytest.fail("BCMCMD Failed")

        def drop_counter_assertion():
            out = duthost.show_and_parse("{} {}".format(asichost.ns_arg, drop_cmd))[0]['pkt_integrity_err']
            post_count = int(out if out.strip().isdigit() else pytest.fail("PKT_INTEGRITY_ERR Count Error"))
            return post_count > pre_count

        pytest_assert(wait_until(120, 5, 0, drop_counter_assertion), "PKT_INTEGRITY_ERR Count is not increasing")
    finally:
        if bcm_changes:
            logging.info("Reloading config")
            config_reload(duthost, safe_reload=True, wait_for_bgp=True)
