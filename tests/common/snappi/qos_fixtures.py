import pytest

"""
RDMA test cases may require variety of fixtures. This
file currently holds the following fixture(s):
    1. prio_dscp_map
    2. all_prio_list
    3. lossless_prio_list
    4. lossy_prio_list
"""


@pytest.fixture(scope="module")
def prio_dscp_map(duthosts, rand_one_dut_hostname):
    """
    This fixture reads the QOS parameters from SONiC DUT, and creates
    priority Vs. DSCP priority port map

    Args:
       duthosts (pytest fixture) : list of DUTs
       rand_one_dut_hostname (pytest fixture): DUT hostname

    Returns:
        Priority vs. DSCP map (dictionary, key = priority).
        Example: {0: [0], 1: [1], 2: [2], 3: [3], 4: [4] ....}
    """
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']

    if "DSCP_TO_TC_MAP" not in config_facts.keys():
        return None

    dscp_to_tc_map_lists = config_facts["DSCP_TO_TC_MAP"]
    if len(dscp_to_tc_map_lists) != 1:
        return None

    profile = dscp_to_tc_map_lists.keys()[0]
    dscp_to_tc_map = dscp_to_tc_map_lists[profile]

    result = {}
    for dscp in dscp_to_tc_map:
        tc = int(dscp_to_tc_map[dscp])
        result.setdefault(tc, []).append(int(dscp))

    return result


@pytest.fixture(scope="module")
def all_prio_list(prio_dscp_map):
    """
    This fixture returns the list of all the priorities

    Args:
        prio_dscp_map (pytest fixture) : Priority vs. DSCP map

    Returns:
        All the priorities (list)
    """
    return list(prio_dscp_map.keys())


@pytest.fixture(scope="module")
def lossless_prio_list(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the list of lossless priorities

    Args:
       duthosts (pytest fixture) : list of DUTs
       rand_one_dut_hostname (pytest fixture): DUT hostname

    Returns:
        Lossless priorities (list)
    """
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']

    if "PORT_QOS_MAP" not in config_facts.keys():
        return None

    port_qos_map = config_facts["PORT_QOS_MAP"]
    if len(port_qos_map.keys()) == 0:
        return None

    """ Here we assume all the ports have the same lossless priorities """
    intf = port_qos_map.keys()[0]
    if 'pfc_enable' not in port_qos_map[intf]:
        return None

    result = [int(x) for x in port_qos_map[intf]['pfc_enable'].split(',')]
    return result


@pytest.fixture(scope="module")
def lossy_prio_list(all_prio_list, lossless_prio_list):
    """
    This fixture returns the list of lossu priorities

    Args:
        all_prio_list (pytest fixture) : all the priorities
        lossless_prio_list (pytest fixture): lossless priorities

    Returns:
        Lossy priorities (list)
    """
    result = [x for x in all_prio_list if x not in lossless_prio_list]
    return result
