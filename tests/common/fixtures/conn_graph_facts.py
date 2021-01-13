import pytest
import os
import six
import yaml


@pytest.fixture(scope="module")
def conn_graph_facts(duthosts, localhost):
    return get_graph_facts(duthosts[0], localhost,
                           [dh.hostname for dh in duthosts])


@pytest.fixture(scope="module")
def fanout_graph_facts(localhost, duthosts, rand_one_dut_hostname, conn_graph_facts):
    duthost = duthosts[rand_one_dut_hostname]
    facts = dict()
    dev_conn = conn_graph_facts.get('device_conn', {})
    for _, val in dev_conn[duthost.hostname].items():
        fanout = val["peerdevice"]
        if fanout not in facts:
            facts[fanout] = {k: v[fanout] for k, v in get_graph_facts(duthost, localhost, fanout).items()}
    return facts


def get_graph_facts(duthost, localhost, hostnames):
    """
    duthost - pytest fixture
    hostnames - can be either a single DUT or a list of multiple DUTs
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_path = os.path.join(base_path, "../../../ansible/files/")

    # BEGINING OF DEPRECATE WARNING:
    #
    # conn_graph_facts is able to look up the right graph according to
    # the hostname(s) passed in from all graph file lists. Therefore the
    # inv_mapping.yml solution is become redandunt. Please move on to
    # populate ansible/files/graph_files.yml with all graph files.
    # The next chunk of code will be deprecated in the future.

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
                lab_conn_graph_file = os.path.join(lab_conn_graph_path, inv_map[inv_file])
                kargs = {"filename": lab_conn_graph_file}
                if isinstance(hostnames, six.string_types):
                    kargs["host"] = hostnames
                elif isinstance(hostnames, (list, tuple)):
                    kargs["hosts"] = hostnames
                conn_graph_facts = localhost.conn_graph_facts(
                    **kargs)["ansible_facts"]
                return conn_graph_facts
    # END OF DEPRECATE WARNING: deprecate ends here.

    kargs = {"filepath": lab_conn_graph_path}
    if isinstance(hostnames, six.string_types):
        kargs["host"] = hostnames
    elif isinstance(hostnames, (list, tuple)):
        kargs["hosts"] = hostnames
    conn_graph_facts = localhost.conn_graph_facts(
        **kargs)["ansible_facts"]
    return conn_graph_facts
