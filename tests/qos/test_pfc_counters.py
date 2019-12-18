from ansible_host import AnsibleHost
from qos_fixtures import conn_graph_facts
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

def setup_testbed(ansible_adhoc, testbed, conn_graph_facts):
    """
    @Summary: Set up the testbed, including clearing counters, and copying the PFC generator to the leaf fanout switches.
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology connectivity information
    """
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    """ Clear PFC counters """
    dut_ans.sonic_pfc_counters(method = "clear")

    conn_facts = conn_graph_facts['device_conn']	
    """ Get all the leaf fanout switches """
    leaf_fanouts = []
    """ For each interface of DUT"""
    for intf in conn_facts:
        peer_device = conn_facts[intf]['peerdevice']
        if peer_device not in leaf_fanouts:
            leaf_fanouts.append(peer_device)
	
    """ Copy the PFC generator to all the leaf fanout switches """
    for peer_device in leaf_fanouts:
        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        file_src = os.path.join(os.path.dirname(__file__), PFC_GEN_FILE_RELATIVE_PATH)
        peerdev_ans.copy(src = file_src, dest = PFC_GEN_FILE_DEST, force = True)

def run_pfc(ansible_adhoc, testbed, conn_graph_facts, pause_time):
    """
    @Summary: Run the priority-based flow control (PFC) test case
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology connectivity information
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(ansible_adhoc, testbed, conn_graph_facts)
    conn_facts = conn_graph_facts['device_conn']
     
    """ Generate PFC packets for all the priority queues of all the interfaces """
    for intf in conn_facts:
        peer_device = conn_facts[intf]['peerdevice']
        peer_port = conn_facts[intf]['peerport']
        peer_port_name = eos_to_linux_intf(peer_port)

        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        for priority in range(PRIO_COUNT):
            cmd = "sudo python %s -i %s -p %d -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, 2 ** priority, pause_time, PKT_COUNT)
            peerdev_ans.command(cmd)
	
    """ SONiC takes some time to update counters in database """
    time.sleep(5)

    """ Check results """
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    counter_facts = dut_ans.sonic_pfc_counters(method = "get")['ansible_facts']

    for intf in conn_facts:
        assert intf in counter_facts
        assert 'Rx' in counter_facts[intf]
        assert counter_facts[intf]['Rx'] == [str(PKT_COUNT)] * PRIO_COUNT

def run_fc(ansible_adhoc, testbed, conn_graph_facts, pause_time):
    """
    @Summary: Run the flow control (FC) test case
    @param ansible_adhoc: Fixture provided by the pytest-ansible package. Source of the various device objects. It is
    mandatory argument for the class constructors.
    @param testbed: Testbed information
    @param conn_graph_facts: Testbed topology connectivity information
    @param pause_time: Pause time quanta (0-65535) in the frame. 0 means unpause.
    """
    setup_testbed(ansible_adhoc, testbed, conn_graph_facts)
    conn_facts = conn_graph_facts['device_conn']

    """ Generate flow control packets for all the interfaces """
    for intf in conn_facts:
        peer_device = conn_facts[intf]['peerdevice']
        peer_port = conn_facts[intf]['peerport']
        peer_port_name = eos_to_linux_intf(peer_port)

        peerdev_ans = AnsibleHost(ansible_adhoc, peer_device)
        cmd = "sudo python %s -i %s -g -t %d -n %d" % (PFC_GEN_FILE_DEST, peer_port_name, pause_time, PKT_COUNT)
        peerdev_ans.command(cmd)
	
    """ SONiC takes some time to update counters in database """
    time.sleep(5)

    """ Check resuls. SONiC should not update PFC counters when receiving global pause/unpause frames """
    dut_hostname = testbed['dut']
    dut_ans = AnsibleHost(ansible_adhoc, dut_hostname)
    counter_facts = dut_ans.sonic_pfc_counters(method = "get")['ansible_facts']
    
    for intf in conn_facts:
        assert intf in counter_facts
        assert 'Rx' in counter_facts[intf]
        assert counter_facts[intf]['Rx'] == ['0'] * PRIO_COUNT

def eos_to_linux_intf(eos_intf_name):
    """
    @Summary: Map EOS's interface name to Linux's interface name
    @param eos_intf_name: Interface name in EOS
    @return: Return the interface name in Linux 
    """
    return eos_intf_name.replace('Ethernet', 'et').replace('/', '_')

def test_pfc_pause(ansible_adhoc, testbed, conn_graph_facts):
    """ @Summary: Run PFC pause frame (pause time quanta > 0) tests """
    run_pfc(ansible_adhoc, testbed, conn_graph_facts, 65535)
			
def test_pfc_unpause(ansible_adhoc, testbed, conn_graph_facts):
    """ @Summary: Run PFC unpause frame (pause time quanta = 0) tests """
    run_pfc(ansible_adhoc, testbed, conn_graph_facts, 0)        

def test_fc_pause(ansible_adhoc, testbed, conn_graph_facts):
    """ @Summary: Run FC pause frame (pause time quanta > 0) tests """
    run_fc(ansible_adhoc, testbed, conn_graph_facts, 65535)

def test_fc_unpause(ansible_adhoc, testbed, conn_graph_facts):
    """ @Summary: Run FC pause frame (pause time quanta = 0) tests """ 
    run_fc(ansible_adhoc, testbed, conn_graph_facts, 0) 	
