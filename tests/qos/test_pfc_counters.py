from tests.common.fixtures.conn_graph_facts import conn_graph_facts, enum_fanout_graph_facts     # noqa: F401
from .qos_fixtures import leaf_fanouts      # noqa: F401
from .qos_helpers import eos_to_linux_intf, nxos_to_linux_intf, sonic_to_linux_intf
import os
import time
import pytest
import logging

"""
This module implements test cases for PFC counters of SONiC.
The PFC Rx counter should be increased when the switch receives a priority-based flow control (PFC) pause/unpause frame.
The PFC Rx counter should NOT be updated when the switch receives a global flow control pause/unpause frame.

In each test case, we send a specific number of pause/unpause frames to a given priority queue of a given port at the
device under test (DUT). Then we check the SONiC PFC Rx counters.
"""

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

PFC_GEN_FILE_RELATIVE_PATH = r'../../ansible/roles/test/files/helpers/pfc_gen.py'
""" Expected PFC generator path at the leaf fanout switch """
PFC_GEN_FILE_DEST = r'~/pfc_gen.py'
PFC_GEN_FILE_ABSOLUTE_PATH = r'/root/pfc_gen_cpu.py'

""" Number of generated packets for each test case """
PKT_COUNT = 10
""" Number of switch priorities """
PRIO_COUNT = 8


@pytest.fixture(scope='module', autouse=True)
def enable_flex_port_counter(rand_selected_dut):
    get_cmd = 'sonic-db-cli CONFIG_DB hget "FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS"'
    status = rand_selected_dut.shell(get_cmd)['stdout']
    if status == 'enable':
        yield
        return
    set_cmd = 'sonic-db-cli CONFIG_DB hset "FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS" "{}"'
    logger.info("Enable flex counter for port")
    rand_selected_dut.shell(set_cmd.format('enable'))
    yield
    logger.info("Disable flex counter for port")
    rand_selected_dut.shell(set_cmd.format('disable'))


def setup_testbed(fanouthosts, duthost, leaf_fanouts):           # noqa: F811
    """
    @Summary: Set up the duthost, including clearing counters,
              and copying the PFC generator to the leaf fanout switches.
    @param duthost: dut host information
    @param leaf_fanouts: Leaf fanout switches
    """
    """ Clear PFC counters """
    duthost.sonic_pfc_counters(method="clear")

    """ Copy the PFC generator to all the leaf fanout switches """
    for peer_device in leaf_fanouts:
        if peer_device not in fanouthosts:
            continue

        peerdev_ans = fanouthosts[peer_device]
        file_src = os.path.join(os.path.dirname(
            __file__), PFC_GEN_FILE_RELATIVE_PATH)
        peerdev_ans.host.copy(src=file_src, dest=PFC_GEN_FILE_DEST, force=True)


def run_test(fanouthosts, duthost, conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts,       # noqa: F811
             is_pfc=True, pause_time=65535, check_continuous_pfc=False):
    """
    @Summary: Run test for Ethernet flow control (FC) or priority-based flow control (PFC)
    @param duthost: The object for interacting with DUT through ansible
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param is_pfc: If this test is for PFC?
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(fanouthosts, duthost, leaf_fanouts)
    asic = duthost.asic_instance()
    asic_type = duthost.facts["asic_type"]
    conn_facts = conn_graph_facts['device_conn'].get(duthost.hostname, {})
    onyx_pfc_container_name = 'storm'
    int_status = asic.show_interface(command="status")[
        'ansible_facts']['int_status']
    """ We only test active physical interfaces """
    active_phy_intfs = [intf for intf in int_status if
                        intf.startswith('Ethernet') and
                        int_status[intf]['admin_state'] == 'up' and
                        int_status[intf]['oper_state'] == 'up']
    only_lossless_rx_counters = "Cisco-8122" in asic.sonichost.facts["hwsku"]
    no_xon_counters = "Cisco-8122" in asic.sonichost.facts["hwsku"]
    if only_lossless_rx_counters and asic_type != 'vs':
        config_facts = asic.config_facts(host=asic.hostname, source='persistent')['ansible_facts']
    if not check_continuous_pfc:
        if asic_type != 'vs':
            """ Generate PFC or FC packets for active physical interfaces """
            for intf in active_phy_intfs:
                peer_device = conn_facts[intf]['peerdevice']
                peer_port = conn_facts[intf]['peerport']

                if peer_device not in fanouthosts:
                    continue

                peerdev_ans = fanouthosts[peer_device]
                fanout_os = peerdev_ans.get_fanout_os()
                fanout_hwsku = enum_fanout_graph_facts[peerdev_ans.hostname]["device_info"]["HwSku"]
                if fanout_os == "nxos":
                    peer_port_name = nxos_to_linux_intf(peer_port)
                elif fanout_os == "sonic":
                    peer_port_name = sonic_to_linux_intf(peer_port)
                else:
                    peer_port_name = eos_to_linux_intf(
                        peer_port, hwsku=fanout_hwsku)

                if is_pfc:
                    for priority in range(PRIO_COUNT):
                        if fanout_hwsku == "MLNX-OS":
                            cmd = 'docker exec %s "python %s -i %s -p %d -t %d -n %d"' % (
                                onyx_pfc_container_name, PFC_GEN_FILE_ABSOLUTE_PATH,
                                peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                            peerdev_ans.host.config(cmd)
                        else:
                            cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (
                                PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                            peerdev_ans.host.command(cmd)
                else:
                    if fanout_hwsku == "MLNX-OS":
                        cmd = 'docker exec %s "python %s -i %s -g -t %d -n %d"' % (
                            onyx_pfc_container_name, PFC_GEN_FILE_ABSOLUTE_PATH, peer_port_name, pause_time, PKT_COUNT)
                        peerdev_ans.host.config(cmd)
                    else:
                        cmd = "sudo python %s -i %s -g -t %d -n %d" % (
                            PFC_GEN_FILE_DEST, peer_port_name, pause_time, PKT_COUNT)
                        peerdev_ans.host.command(cmd)

        """ SONiC takes some time to update counters in database """
        time.sleep(5)

        """ Check results """
        counter_facts = duthost.sonic_pfc_counters(method="get")[
            'ansible_facts']
        if only_lossless_rx_counters and asic_type != 'vs':
            pfc_enabled_prios = [int(prio) for prio in config_facts["PORT_QOS_MAP"][intf]['pfc_enable'].split(',')]
        failures = []
        for intf in active_phy_intfs:
            if is_pfc and (not no_xon_counters or pause_time != 0):
                if only_lossless_rx_counters:
                    expected_prios = [str(PKT_COUNT if prio in pfc_enabled_prios else 0) for prio in range(PRIO_COUNT)]
                else:
                    expected_prios = [str(PKT_COUNT)] * PRIO_COUNT
            else:
                # Expect 0 counters when "no_xon_counters and pause_time == 0", i.e. when
                # device does not support XON counters and the frame is XON.
                expected_prios = ['0'] * PRIO_COUNT
            logger.info("Verifying PFC RX count matches {}".format(expected_prios))
            if counter_facts[intf]['Rx'] != expected_prios:
                failures.append((counter_facts[intf]['Rx'], expected_prios))
        if asic_type != 'vs':
            for failure in failures:
                logger.error("Got {}, expected {}".format(*failure))
            assert len(failures) == 0, (
                "PFC RX counter increment not matching expected for above logged cases. "
                "Number of failures: {}"
            ).format(len(failures))

    else:
        for intf in active_phy_intfs:
            """only check priority 3 and 4: lossless priorities"""
            for priority in range(3, 5):
                """ Clear PFC counters """
                duthost.sonic_pfc_counters(method="clear")

                if asic_type != 'vs':
                    peer_device = conn_facts[intf]['peerdevice']
                    peer_port = conn_facts[intf]['peerport']

                    if peer_device not in fanouthosts:
                        continue

                    peerdev_ans = fanouthosts[peer_device]
                    fanout_os = peerdev_ans.get_fanout_os()
                    fanout_hwsku = enum_fanout_graph_facts[peerdev_ans.hostname]["device_info"]["HwSku"]
                    if fanout_os == "nxos":
                        peer_port_name = nxos_to_linux_intf(peer_port)
                    elif fanout_os == "sonic":
                        peer_port_name = sonic_to_linux_intf(peer_port)
                    else:
                        peer_port_name = eos_to_linux_intf(
                            peer_port, hwsku=fanout_hwsku)

                    if fanout_hwsku == "MLNX-OS":
                        cmd = 'docker exec %s "python %s -i %s -p %d -t %d -n %d"' % (
                            onyx_pfc_container_name, PFC_GEN_FILE_ABSOLUTE_PATH,
                            peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                        peerdev_ans.host.config(cmd)
                    else:
                        cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (
                            PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                        peerdev_ans.host.command(cmd)

                time.sleep(5)

                pfc_rx = duthost.sonic_pfc_counters(
                    method="get")['ansible_facts']
                if asic_type != 'vs':
                    """check pfc Rx frame count on particular priority are increased"""
                    assert pfc_rx[intf]['Rx'][priority] == str(PKT_COUNT), (
                        "PFC RX counter value mismatch for interface {} and priority {}. "
                        "Expected value: {}, but got {}."
                    ).format(intf, priority, PKT_COUNT, pfc_rx[intf]['Rx'][priority])

                    """check LHS priorities are 0 count"""
                    for i in range(priority):
                        assert pfc_rx[intf]['Rx'][i] == '0', (
                            "PFC RX counter value is not zero for interface {} and priority {}. "
                            "Expected value: 0, but got {}."
                        ).format(intf, i, pfc_rx[intf]['Rx'][i])

                    """check RHS priorities are 0 count"""
                    for i in range(priority+1, PRIO_COUNT):
                        assert pfc_rx[intf]['Rx'][i] == '0', (
                            "PFC RX counter value is not zero for interface {} and priority {}. "
                            "Expected value: 0, but got {}."
                        ).format(intf, i, pfc_rx[intf]['Rx'][i])


def test_pfc_pause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                   conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):          # noqa: F811
    """ @Summary: Run PFC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts)


def test_pfc_unpause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                     conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):        # noqa: F811
    """ @Summary: Run PFC unpause frame (pause time quanta = 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, pause_time=0)


def test_fc_pause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                  conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):           # noqa: F811
    """ @Summary: Run FC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, is_pfc=False)


def test_fc_unpause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                    conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):         # noqa: F811
    """ @Summary: Run FC pause frame (pause time quanta = 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, is_pfc=False, pause_time=0)


def test_continous_pfc(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                       conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):     # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, check_continuous_pfc=True)
