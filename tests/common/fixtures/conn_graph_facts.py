import pytest
import os
import json

from ansible_host import AnsibleHost

@pytest.fixture(scope="module")
def conn_graph_facts(testbed_devices, ansible_adhoc):
    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    base_path = os.path.dirname(os.path.realpath(__file__))
    # default lab graph file
    lab_conn_graph_file = os.path.join(base_path, "../../../ansible/files/lab_connection_graph.xml")
    # json file contains mapping from inventory file name to its corresponding graph file
    inv_mapping_file = os.path.join(base_path, "../../../ansible/group_vars/all/inv_mapping.json")
    if os.path.exists(inv_mapping_file):
        with open(inv_mapping_file) as fd:
            inv_map = json.load(fd)
        ans_host = AnsibleHost(ansible_adhoc, dut.hostname)
        inv_file = ans_host.host.options['inventory'].split('/')[-1]
        if inv_file in inv_map:
            lab_conn_graph_file = os.path.join(base_path, "../../../ansible/files/{}".format(inv_map[inv_file]))

    conn_graph_facts = localhost.conn_graph_facts(host=dut.hostname, filename=lab_conn_graph_file)['ansible_facts']
    return conn_graph_facts
