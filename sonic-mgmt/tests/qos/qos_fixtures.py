import pytest
from tests.common.fixtures.conn_graph_facts import conn_graph_facts


@pytest.fixture(scope = "module")
def lossless_prio_dscp_map(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    if "PORT_QOS_MAP" not in config_facts.keys():
        return None

    port_qos_map = config_facts["PORT_QOS_MAP"]
    lossless_priorities = list()
    intf = port_qos_map.keys()[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return None

    lossless_priorities = [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]
    if "DSCP_TO_TC_MAP" in config_facts:
        prio_to_tc_map = config_facts["DSCP_TO_TC_MAP"]
    elif "DOT1P_TO_TC_MAP" in config_facts:
        prio_to_tc_map = config_facts["DOT1P_TO_TC_MAP"]

    result = dict()
    for prio in lossless_priorities:
        result[prio] = list()

    profile = prio_to_tc_map.keys()[0]

    for prio in prio_to_tc_map[profile]:
        tc = prio_to_tc_map[profile][prio]

        if int(tc) in lossless_priorities:
            result[int(tc)].append(int(prio))

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
    for _, value in conn_facts.items():
        for _, val in value.items():
            peer_device = val['peerdevice']
            if peer_device not in leaf_fanouts:
                leaf_fanouts.append(peer_device)

    return leaf_fanouts
