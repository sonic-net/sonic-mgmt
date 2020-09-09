import pytest
import os
import six
import yaml


@pytest.fixture(scope="module")
def conn_graph_facts(duthost, localhost):
    return get_graph_facts(duthost, localhost, duthost.hostname)


@pytest.fixture(scope="module")
def conn_graph_facts_multi_duts(duthost, duthosts, localhost):
    return get_graph_facts(duthost, localhost,
                           [dh.hostname for dh in duthosts])

  
@pytest.fixture(scope="module")
def fanout_graph_facts(localhost, duthost, conn_graph_facts):
    facts = dict()
    for intf in conn_graph_facts["device_conn"]:
        fanout = conn_graph_facts["device_conn"][intf]["peerdevice"]
        if fanout not in facts:
            facts[fanout] = get_graph_facts(duthost, localhost, fanout)
    return facts


def get_graph_facts(duthost, localhost, hostnames):
    """
    duthost - pytest fixture
    hostnames - can be either a single DUT or a list of multiple DUTs
    """
    conn_graph_facts = dict()
    base_path = os.path.dirname(os.path.realpath(__file__))
    # yaml file contains mapping from inventory file name to its corresponding graph file
    inv_mapping_file = os.path.join(base_path, "../../../ansible/group_vars/all/inv_mapping.yml")
    if os.path.exists(inv_mapping_file):
        with open(inv_mapping_file) as fd:
            inv_map = yaml.load(fd, Loader=yaml.FullLoader)
        inv_opt = duthost.host.options['inventory']
        inv_files = []
        if isinstance(inv_opt, str):
            inv_files = [duthost.host.options['inventory']]  # Make it iterable for later use
        elif isinstance(inv_opt, list) or isinstance(inv_opt, tuple):
            inv_files = duthost.host.options['inventory']

        for inv_file in inv_files:
            inv_file = os.path.basename(inv_file)

            # Loop through the list of inventory files supplied in --inventory argument.
            # For the first inventory file that has a mapping in inv_mapping.yml, return
            # its conn_graph_facts.
            if inv_map and inv_file in inv_map:
                lab_conn_graph_file = os.path.join(base_path, "../../../ansible/files/{}".format(inv_map[inv_file]))
                kargs = {"filename": lab_conn_graph_file}
                if isinstance(hostnames, six.string_types):
                    kargs["host"] = hostnames
                elif isinstance(hostnames, (list, tuple)):
                    kargs["hosts"] = hostnames
                conn_graph_facts = localhost.conn_graph_facts(
                    **kargs)["ansible_facts"]
                return conn_graph_facts
    return conn_graph_facts
