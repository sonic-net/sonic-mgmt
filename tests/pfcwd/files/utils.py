import pytest

def lossless_prio_dscp_map(duthost, dut_intf_map=None):
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

    lossless_priorities = \
        list(set([int(x) for x in port_qos_map[intf]['pfc_enable'].split(',') for intf in port_qos_map]))
    
    dscp_to_tc_map = config_facts["DSCP_TO_TC_MAP"]

    result = dict()
    for prio in lossless_priorities:
        result[prio] = list()

    profile = dscp_to_tc_map.keys()[0]

    for dscp in dscp_to_tc_map[profile]:
        tc = dscp_to_tc_map[profile][dscp]

        if int(tc) in lossless_priorities:
            result[int(tc)].append(int(dscp))
    
    lossless_priorities_interface = \
        {intf : [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')] for intf in port_qos_map}
    
    if dut_intf_map:
        return (result, lossless_priorities_interface)
    
    return result

