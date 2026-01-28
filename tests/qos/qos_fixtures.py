import pytest
from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa: F401
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def lossless_prio_dscp_map(duthosts, rand_one_dut_hostname):
    """Return a mapping of each lossless priority to the DSCP/DOT1P values
    that forward to it.

    Selection strategy:
    - T0 topologies: derive lossless priorities from a VLAN member port
    - Non-T0 topologies: fall back to any port in PORT_QOS_MAP with pfc_enable
    """

    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="persistent")['ansible_facts']

    if "PORT_QOS_MAP" not in config_facts:
        return None

    port_qos_map = config_facts["PORT_QOS_MAP"]

    # Step 1: pick an interface to derive lossless priorities from.
    intf = None

    # T0-topo: use a VLAN member port (server-facing) when VLAN_MEMBER is present.
    vlan_members = config_facts.get("VLAN_MEMBER", {})
    if vlan_members:
        # Pick the first VLAN, then the first member that has pfc_enable.
        vlan = sorted(vlan_members.keys())[0]
        for cand_intf in sorted(vlan_members[vlan].keys()):
            if cand_intf in port_qos_map and "pfc_enable" in port_qos_map[cand_intf]:
                intf = cand_intf
                break

    # other topologies: no VLAN_MEMBER present; fall back to any port with pfc_enable.
    if intf is None:
        for cand_intf in sorted(port_qos_map.keys()):
            qos_cfg = port_qos_map[cand_intf]
            if "pfc_enable" in qos_cfg:
                intf = cand_intf
                break

    if intf is None or "pfc_enable" not in port_qos_map[intf]:
        return None

    lossless_priorities = [
        int(x) for x in port_qos_map[intf]["pfc_enable"].split(',')
    ]

    # Step 2: figure out which QoS map to use (DSCP or DOT1P).
    prio_to_tc_map = None
    profile_key = None
    if "DSCP_TO_TC_MAP" in config_facts:
        prio_to_tc_map = config_facts["DSCP_TO_TC_MAP"]
        profile_key = "dscp_to_tc_map"
    elif "DOT1P_TO_TC_MAP" in config_facts:
        prio_to_tc_map = config_facts["DOT1P_TO_TC_MAP"]
        profile_key = "dot1p_to_tc_map"

    if prio_to_tc_map is None or profile_key not in port_qos_map[intf]:
        return None

    # Retrieve the profile name (e.g., AZURE) for this port and walk its map.
    profile = port_qos_map[intf][profile_key]

    result = {prio: [] for prio in lossless_priorities}

    for prio, tc in prio_to_tc_map[profile].items():
        if int(tc) in lossless_priorities:
            result[int(tc)].append(int(prio))

    # Deduplicate and sort DSCP lists for determinism
    for prio in list(result.keys()):
        result[prio] = sorted(set(result[prio]))

    logger.info("lossless_prio_dscp_map: %s", result)
    return result


@pytest.fixture(scope="module")
def leaf_fanouts(conn_graph_facts):         # noqa: F811
    """
    @summary: Fixture for getting the list of leaf fanout switches
    @param conn_graph_facts: Topology connectivity information
    @return: Return the list of leaf fanout switches
    """
    leaf_fanouts = []
    conn_facts = conn_graph_facts['device_conn']

    """ for each interface of DUT """
    for _, value in list(conn_facts.items()):
        for _, val in list(value.items()):
            peer_device = val['peerdevice']
            if peer_device not in leaf_fanouts:
                leaf_fanouts.append(peer_device)

    return leaf_fanouts
