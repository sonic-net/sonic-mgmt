import pytest
"""
RDMA test cases may require variety of traffic related fixtures. This file
is repository of all different kinds of traffic related fixtures. This
file currently holds the following fixture(s):
    1. lossless_prio_dscp_map
"""
@pytest.fixture(scope = "module")
def lossless_prio_dscp_map(duthost):
    """
    This fixture reads the QOS parameters from SONiC DUT, and creates
    lossless priority Vs. DSCP priority port map (dictionary key = lossless 
    priority).

    Args:
       duthost (pytest fixture) : duthost
       
    Returns:
        Lossless priority vs. DSCP map (dictionary, key = lossless priority).
        Example: {3: [3], 4: [4]} 
    """
    config_facts = duthost.config_facts(host=duthost.hostname, 
                                        source="persistent")['ansible_facts']

    if "PORT_QOS_MAP" not in config_facts.keys():
        return None

    # Read the port QOS map. If pfc_enable flag is false then return None.
    port_qos_map = config_facts["PORT_QOS_MAP"]
    intf = port_qos_map.keys()[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return None

    # lossless_priorities == list of priorities values for which frame loss
    # should not happen 
    lossless_priorities = \
        [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]

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
