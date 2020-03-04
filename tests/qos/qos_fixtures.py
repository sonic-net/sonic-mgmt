import pytest
import os

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
