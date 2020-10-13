import pytest
from tests.common.fixtures.conn_graph_facts import conn_graph_facts


@pytest.fixture(scope = "module")
def lossless_prio_dscp_map(duthost):
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

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
