from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from qos_fixtures import leaf_fanouts
from qos_helpers import eos_to_linux_intf
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
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

PFC_GEN_FILE_RELATIVE_PATH = r'../../ansible/roles/test/files/helpers/pfc_gen.py'
""" Expected PFC generator path at the leaf fanout switch """
PFC_GEN_FILE_DEST = r'~/pfc_gen.py'
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


def setup_testbed(fanouthosts, duthost, leaf_fanouts):
    """
    @Summary: Set up the duthost, including clearing counters, and copying the PFC generator to the leaf fanout switches.
    @param duthost: dut host information
    @param leaf_fanouts: Leaf fanout switches
    """
    """ Clear PFC counters """
    duthost.sonic_pfc_counters(method = "clear")

    """ Copy the PFC generator to all the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = fanouthosts[peer_device]
        file_src = os.path.join(os.path.dirname(__file__), PFC_GEN_FILE_RELATIVE_PATH)
        peerdev_ans.host.copy(src = file_src, dest = PFC_GEN_FILE_DEST, force = True)

def run_test(fanouthosts, duthost, conn_graph_facts, leaf_fanouts, is_pfc=True, pause_time=65535):
    """
    @Summary: Run test for Ethernet flow control (FC) or priority-based flow control (PFC)
    @param duthost: The object for interacting with DUT through ansible
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param is_pfc: If this test is for PFC?
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(fanouthosts, duthost, leaf_fanouts)
    conn_facts = conn_graph_facts['device_conn'][duthost.hostname]

    int_status = duthost.show_interface(command = "status")['ansible_facts']['int_status']

    """ We only test active physical interfaces """
    active_phy_intfs = [intf for intf in int_status if \
        intf.startswith('Ethernet') and \
        int_status[intf]['admin_state'] == 'up' and \
        int_status[intf]['oper_state'] == 'up']

    """ Generate PFC or FC packets for active physical interfaces """
    for intf in active_phy_intfs:
        peer_device = conn_facts[intf]['peerdevice']
        peer_port = conn_facts[intf]['peerport']
        peer_port_name = eos_to_linux_intf(peer_port)

        peerdev_ans = fanouthosts[peer_device]
        if is_pfc:
            for priority in range(PRIO_COUNT):
                cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                peerdev_ans.host.command(cmd)
        else:
            cmd = "sudo python %s -i %s -g -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, pause_time, PKT_COUNT)
            peerdev_ans.host.command(cmd)

    """ SONiC takes some time to update counters in database """
    time.sleep(5)

    """ Check results """
    counter_facts = duthost.sonic_pfc_counters(method = "get")['ansible_facts']

    for intf in active_phy_intfs:
        if is_pfc:
            assert counter_facts[intf]['Rx'] == [str(PKT_COUNT)] * PRIO_COUNT
        else:
            assert counter_facts[intf]['Rx'] == ['0'] * PRIO_COUNT

def test_pfc_pause(fanouthosts, duthosts, rand_one_dut_hostname, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run PFC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[rand_one_dut_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts, leaf_fanouts)

def test_pfc_unpause(fanouthosts, duthosts, rand_one_dut_hostname, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run PFC unpause frame (pause time quanta = 0) tests """
    duthost = duthosts[rand_one_dut_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts, leaf_fanouts, pause_time=0)

def test_fc_pause(fanouthosts, duthosts, rand_one_dut_hostname, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run FC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[rand_one_dut_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts, leaf_fanouts, is_pfc=False)

def test_fc_unpause(fanouthosts, duthosts, rand_one_dut_hostname, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run FC pause frame (pause time quanta = 0) tests """
    duthost = duthosts[rand_one_dut_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts, leaf_fanouts, is_pfc=False, pause_time=0)
