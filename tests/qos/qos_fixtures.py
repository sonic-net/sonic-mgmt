import pytest
import os
from ansible_host import AnsibleHost

@pytest.fixture(scope = "module")
def lossless_prio_dscp_map(testbed_devices):
    dut = testbed_devices["dut"]
    config_facts = dut.config_facts(host=dut.hostname, source="persistent")['ansible_facts']
    
    if "PORT_QOS_MAP" not in config_facts.keys():
        return None 
    
    port_qos_map = config_facts["PORT_QOS_MAP"]
    lossless_priorities = list()
    intf = port_qos_map.keys()[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return None 
        
    lossless_priorities = [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]
    dscp_to_tc_map = config_facts["DSCP_TO_TC_MAP"]
    
    result = dict()
    for prio in lossless_priorities:
        result[prio] = list()

    profile = dscp_to_tc_map.keys()[0]
         
    for dscp in dscp_to_tc_map[profile]:
        tc = dscp_to_tc_map[profile][dscp]
        
        if int(tc) in lossless_priorities:
            result[int(tc)].append(int(dscp))
    
    return result 

@pytest.fixture(scope = "module")
def conn_graph_facts(testbed_devices):
    """
    @summary: Fixture for getting testbed topology connectivity information.
    @param testbed_devices: Devices in the testbed
    @return: Return the topology connectivity information
    """
    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_file = os.path.join(base_path, "../../ansible/files/lab_connection_graph.xml")
    result = localhost.conn_graph_facts(host=dut.hostname, filename=lab_conn_graph_file)['ansible_facts']
	
    return result

@pytest.fixture(scope = "module")
def leaf_fanouts(conn_graph_facts):
    """
    @summary: Fixture for getting the list of leaf fanout switches
    @param conn_graph_facts: Topology connectivity information
    @return: Return the list of leaf fanout switches
    """
    leaf_fanouts = []
    conn_facts = conn_graph_facts['device_conn']
    
    """ for each interface of DUT """
    for intf in conn_facts:
        peer_device = conn_facts[intf]['peerdevice']
        if peer_device not in leaf_fanouts:
            leaf_fanouts.append(peer_device)

    return leaf_fanouts