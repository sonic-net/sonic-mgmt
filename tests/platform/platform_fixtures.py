import pytest
import os

@pytest.fixture(scope="module")
def conn_graph_facts(testbed_devices):
    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_file = os.path.join(base_path, "../../ansible/files/lab_connection_graph.xml")
    conn_graph_facts = localhost.conn_graph_facts(host=dut.hostname, filename=lab_conn_graph_file)['ansible_facts']
    return conn_graph_facts
