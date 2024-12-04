import pytest
import time
import json
from tests.common.snappi_tests.common_helpers import \
        stop_pfcwd, disable_packet_aging, enable_packet_aging
from tests.common.utilities import get_running_config

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
    config_facts = duthost.config_facts(host=duthost.hostname, asic_index=0,
                                        source="running")['ansible_facts']

    if "DSCP_TO_TC_MAP" not in list(config_facts.keys()):
        return None

    dscp_to_tc_map_lists = config_facts["DSCP_TO_TC_MAP"]
    if len(dscp_to_tc_map_lists) != 1:
        return None

    profile = list(dscp_to_tc_map_lists.keys())[0]
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
    config_facts = duthost.config_facts(host=duthost.hostname, asic_index=0,
                                        source="running")['ansible_facts']

    if "PORT_QOS_MAP" not in list(config_facts.keys()):
        return None

    port_qos_map = config_facts["PORT_QOS_MAP"]
    if len(list(port_qos_map.keys())) == 0:
        return None

    """ Here we assume all the ports have the same lossless priorities """
    intf = list(port_qos_map.keys())[0]
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


# Introducing these functions, since the existing pfcwd-start function
# uses start-default. The start-default starts pfcwd only if the config
# is enabled by default. Since we need a definite way to start pfcwd,
# the following functions are introduced.
def get_pfcwd_config(duthost):
    config = get_running_config(duthost)
    if "PFC_WD" in config.keys():
        return config['PFC_WD']
    else:
        all_configs = []
        output = duthost.shell("ip netns | awk '{print $1}'")['stdout']
        all_asic_list = output.split("\n")
        all_asic_list.append(None)
        for space in all_asic_list:
            config = get_running_config(duthost, space)
            if "PFC_WD" in config.keys():
                all_configs.append(config['PFC_WD'])
            else:
                all_configs.append({})
        return all_configs


def reapply_pfcwd(duthost, pfcwd_config):
    timestamp = time.time()
    file_prefix = f"{timestamp}_pfcwd"
    if type(pfcwd_config) is dict:
        duthost.copy(content=json.dumps({"PFC_WD": pfcwd_config}, indent=4), dest=file_prefix)
        duthost.shell(f"config load {file_prefix} -y")
    elif type(pfcwd_config) is list:
        output = duthost.shell("ip netns | awk '{print $1}'")['stdout']
        all_asic_list = output.split("\n")
        all_asic_list.append(None)

        all_files = []
        for index, config in enumerate(pfcwd_config):
            filename = "{}_{}.json".format(file_prefix, all_asic_list[index])
            duthost.copy(content=json.dumps({"PFC_WD": config}, indent=4), dest=filename)
            all_files.append(filename)
        duthost.shell("config load {} -y".format(",".join(all_files)))
    else:
        raise RuntimeError(f"Script problem: Got an unsupported type of pfcwd_config:{pfcwd_config}")


@pytest.fixture(autouse=False)
def disable_pfcwd(duthosts):
    pfcwd_value = {}
    for duthost in duthosts:
        pfcwd_value[duthost.hostname] = get_pfcwd_config(duthost)
        stop_pfcwd(duthost)
        disable_packet_aging(duthost)
    yield
    for duthost in duthosts:
        reapply_pfcwd(duthost, pfcwd_value[duthost.hostname])
        enable_packet_aging(duthost)
