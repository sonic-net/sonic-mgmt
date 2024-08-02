import pytest
import os
import six
import yaml
import copy


@pytest.fixture(scope="module")
def conn_graph_facts(duthosts, localhost):
    return get_graph_facts(duthosts[0], localhost,
                           [dh.hostname for dh in duthosts])


@pytest.fixture(scope="module")
def fanout_graph_facts(localhost, duthosts, rand_one_tgen_dut_hostname, conn_graph_facts):
    duthost = duthosts[rand_one_tgen_dut_hostname]
    facts = dict()
    dev_conn = conn_graph_facts.get('device_conn', {})
    if not dev_conn:
        return facts
    for _, val in list(dev_conn[duthost.hostname].items()):
        fanout = val["peerdevice"]
        if fanout not in facts:
            facts[fanout] = {k: v[fanout] for k, v in list(get_graph_facts(duthost, localhost, fanout).items())}
    return facts


@pytest.fixture(scope="module")
def enum_fanout_graph_facts(localhost, duthosts, enum_rand_one_per_hwsku_frontend_hostname, conn_graph_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    facts = dict()
    dev_conn = conn_graph_facts.get('device_conn', {})
    if not dev_conn:
        return facts
    for _, val in list(dev_conn[duthost.hostname].items()):
        fanout = val["peerdevice"]
        if fanout not in facts:
            facts[fanout] = {k: v[fanout] for k, v in list(get_graph_facts(duthost, localhost, fanout).items())}
    return facts


def get_graph_facts(duthost, localhost, hostnames):
    """
    duthost - pytest fixture
    hostnames - can be either a single DUT or a list of multiple DUTs
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_path = os.path.join(base_path, "../../../ansible/files/")

    inv_files = duthost.host.options["inventory_manager"]._sources
    graph_groups_file = os.path.join(lab_conn_graph_path, "graph_groups.yml")
    group = None
    if os.path.isfile(graph_groups_file):
        graph_groups = yaml.safe_load(open(graph_groups_file))
        for inv_file in inv_files:
            inv_name = os.path.basename(inv_file)
            if inv_name in graph_groups:
                group = inv_name

    kargs = {"filepath": lab_conn_graph_path}
    if group:
        kargs["group"] = group
    if isinstance(hostnames, six.string_types):
        kargs["host"] = hostnames
    elif isinstance(hostnames, (list, tuple)):
        kargs["hosts"] = hostnames
    conn_graph_facts = localhost.conn_graph_facts(
        **kargs)["ansible_facts"]
    return key_convert2str(conn_graph_facts)


def key_convert2str(conn_graph_facts):
    """
        In Python2, some key type are unicode, but In Python3, are AnsibleUnsafeText. Convert them to str.
        Currently, convert the key in conn_graph_facts['device_conn'].
    """
    # If Python2, do not change
    if six.PY2:
        return conn_graph_facts

    # Else, convert
    result = copy.deepcopy(conn_graph_facts)
    result['device_conn'] = {}
    for key, value in list(conn_graph_facts['device_conn'].items()):
        result['device_conn'][str(key)] = value

    return result
