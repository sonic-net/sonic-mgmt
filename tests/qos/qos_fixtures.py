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



