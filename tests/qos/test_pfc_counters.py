from ansible_host import AnsibleHost
from qos_fixtures import conn_graph_facts, leaf_fanouts
from qos_helpers import eos_to_linux_intf
import os
import time

"""
This module implements test cases for PFC counters of SONiC.
The PFC Rx counter should be increased when the switch receives a priority-based flow control (PFC) pause/unpause frame.
The PFC Rx counter should NOT be updated when the switch receives a global flow control pause/unpause frame.

In each test case, we send a specific number of pause/unpause frames to a given priority queue of a given port at the
device under test (DUT). Then we check the SONiC PFC Rx counters. 
"""

PFC_GEN_FILE_RELATIVE_PATH = r'../../ansible/roles/test/files/helpers/pfc_gen.py'
""" Expected PFC generator path at the leaf fanout switch """
PFC_GEN_FILE_DEST = r'~/pfc_gen.py'
""" Number of generated packets for each test case """
PKT_COUNT = 10
""" Number of switch priorities """ 
PRIO_COUNT = 8

def setup_testbed(ansible_adhoc, testbed, leaf_fanouts):
    """
    @Summary: Set up the testbed, including clearing counters, and copying the PFC generator to the leaf fanout switches.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param leaf_fanouts: Leaf fanout switches
    """
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    """ Clear PFC counters """
    dut_ans.sonic_pfc_counters(method = "clear")

    """ Copy the PFC generator to all the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        file_src = os.path.join(os.path.dirname(__file__), PFC_GEN_FILE_RELATIVE_PATH)
        peerdev_ans.copy(src = file_src, dest = PFC_GEN_FILE_DEST, force = True)

def run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, is_pfc=True, pause_time=65535):
    """
    @Summary: Run test for Ethernet flow control (FC) or priority-based flow control (PFC)
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology connectivity information
    @param leaf_fanouts: Leaf fanout switches
    @param is_pfc: If this test is for PFC?
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(ansible_adhoc, testbed, leaf_fanouts)
    conn_facts = conn_graph_facts['device_conn']
    
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    int_status = dut_ans.show_interface(command = "status")['ansible_facts']['int_status']
    
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

        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        if is_pfc:
            for priority in range(PRIO_COUNT):
                cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
                peerdev_ans.command(cmd)
        else:
            cmd = "sudo python %s -i %s -g -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, pause_time, PKT_COUNT)
            peerdev_ans.command(cmd)
            
    """ SONiC takes some time to update counters in database """
    time.sleep(5)

    """ Check results """
    counter_facts = dut_ans.sonic_pfc_counters(method = "get")['ansible_facts']

    for intf in active_phy_intfs:    
        if is_pfc:
            assert counter_facts[intf]['Rx'] == [str(PKT_COUNT)] * PRIO_COUNT
        else:
            assert counter_facts[intf]['Rx'] == ['0'] * PRIO_COUNT

def test_pfc_pause(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run PFC pause frame (pause time quanta > 0) tests """
    run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts)

def test_pfc_unpause(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run PFC unpause frame (pause time quanta = 0) tests """
    run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, pause_time=0)        

def test_fc_pause(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run FC pause frame (pause time quanta > 0) tests """
    run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, is_pfc=False)

def test_fc_unpause(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts):
    """ @Summary: Run FC pause frame (pause time quanta = 0) tests """ 
    run_test(ansible_adhoc, testbed, conn_graph_facts, leaf_fanouts, is_pfc=False, pause_time=0)