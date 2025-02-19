import logging
import pytest
import random
import json
import re
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.utilities import wait_until
from route_checker import assert_only_loopback_routes_announced_to_neighs, parse_routes_on_neighbors
from route_checker import verify_current_routes_announced_to_neighs, check_and_log_routes_diff
import ipaddress

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

def verify_prefix_list_in_db(host, prefix_type, prefix, cmd="sudo prefix_list status", add=True):
    """
    Verify if the prefix list is in the CONFIG_DB for asic_index
    PREFIX_LIST status shows
    BGP0: Current prefix lists:
    {('PREFIX_TYPE', 'PREFIX1'): {}}
    {('PREFIX_TYPE', 'PREFIX2'): {}}
    BGP1: Current prefix lists:
    {('PREFIX_TYPE', 'PREFIX1'): {}}
    {('PREFIX_TYPE', 'PREFIX2'): {}}

    Parameters:
    host (SonicHost): The SonicHost object
    prefix_type (str): The prefix type
    prefix (str): The prefix
    outputs (str): The output of the command
    add (bool): True if the prefix was added, False if the prefix was removed
    """
    outputs = host.shell(cmd)['stdout']
    # string matching to see if prefix type and prefix are in the output 
    expected = len(host.get_frontend_asic_ids()) if add else 0
    # check if we have n_asic entry matches of (PREFIX_TYPE, PREFIX) in the output
    result_str = f"('{prefix_type}', '{prefix}')"
    count = outputs.count(result_str)
    if count != expected:
        logger.error(f"Expected {expected} occurences of {result_str} in the output, but found {count} occurences")
        return False
    return True

def add_prefix(host, prefix_type, prefix, with_config_reload=False):
    """
    Add a prefix to the prefix list

    Parameters:
    host (SonicHost): The SonicHost object
    prefix_type (str): The prefix type
    prefix (str): The prefix
    asic_index (int): The asic index
    """
    # add the prefix to the prefix list
    cmd= f"sudo prefix-list add {prefix_type} {prefix}"
    host.shell(cmd)
    if with_config_reload:
        host.shell("sudo config save -y")
        config_reload(host, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
    if not verify_prefix_list_in_db(host, prefix_type, prefix):
        logger.error(f"Failed to add prefix {prefix} to the prefix list")
        return False
    return True

def remove_prefix(host, prefix_type, prefix, with_config_reload=False):
    """
    Remove a prefix from the prefix list

    Parameters:
    host (SonicHost): The SonicHost object
    prefix_type (str): The prefix type
    prefix (str): The prefix
    asic_index (int): The asic index
    """
    # remove the prefix from the prefix list
    cmd= f"sudo prefix-list remove {prefix_type} {prefix}"
    outputs = host.shell(cmd)
    if with_config_reload:
        host.shell("sudo config save -y")
        config_reload(host, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
    if not verify_prefix_list_in_db(host, prefix_type, prefix, outputs, add=False):
        logger.error(f"Failed to remove prefix {prefix} from the prefix list")
        return False
    return True

def verify_prefix_in_table(host, prefix, present=True, table="bgp"):
    """
    Verify if the prefix is in the specified table

    Parameters:
    host (SonicHost): The SonicHost object
    prefix (str): The prefix
    present (bool): True if the prefix should be present, False if it should not be present
    table (str): The table to check, either "bgp" or "route"
    """
    if table not in ["bgp", "route"]:
        raise ValueError("Invalid table specified. Must be 'bgp' or 'route'.")

    ipv = "ip" if ipaddress.ip_network(prefix).version==4 else "ipv6"

    for asic_index in host.get_frontend_asic_ids():
        if table == "bgp":
            cmd = f"vtysh -n {asic_index} -c 'show bgp {ipv} {prefix}'"
        else:
            cmd = f"vtysh -n {asic_index} -c 'show {ipv} route {prefix}'"

        outputs = host.shell(cmd)['stdout']
        if present:
            if f"Network not in table" in outputs:
                logger.error(f"Expected prefix {prefix} to be in the {table} table, but it was not found")
                return False
        else:
            if f"Network not in table" not in outputs:
                logger.error(f"Expected prefix {prefix} to not be in the {table} table, but found it")
                return False
        
    return True

def neighbor_ip(duthost):
    """
    returns a dictionary of the form {
        "namespace": {
            "peer_group": {
                "ip_version": [ip1, ip2, ...]
            }
        }
    }
    """
    bgp_neighbors = duthost.get_bgp_neighbors_per_asic()
    transformed = {}
    for namespace, neighbors in bgp_neighbors.items():
        transformed[namespace] = {}
        for ip, details in neighbors.items():
            peer_group = details["peer group"]
            ip_version = details["ip_version"]
            if peer_group not in transformed[namespace]:
                transformed[namespace][peer_group] = {}
            if ip_version not in transformed[namespace][peer_group]:
                transformed[namespace][peer_group][ip_version] = []
            transformed[namespace][peer_group][ip_version].append(ip)
    return transformed

def verify_prefix_announce_to_neighbor(duthost, prefix, neigh_ip_dic, neighbor_peer_group, present=True):
    """	
    Verify if the prefix is announced to the specified neighbor
    Parameters:
    duthost (SonicHost): The SonicHost object
    prefix (str): The prefix
    neigh_ips (str): The neighbor IP address dictionary {4: [ip1, ip2, ...], 6: [ip1, ip2, ...]}
    present (bool): True if the prefix should be announced, False if it should not be announced
    """
    prefix_version = ipaddress.ip_network(prefix).version
    ipv = "ip" if prefix_version==4 else "ipv6"
    error_msg_present = f"Expected prefix {prefix} to be announced to neighbor {random_neigh_ip}, but it was not found"
    error_msg_not_present = f"Expected prefix {prefix} to not be announced to neighbor {random_neigh_ip}, but it was found"

    for asic_index in duthost.get_frontend_asic_ids():
        asic_namespace = f"/asic{asic_index}"
        random_neigh_ip = random.choice(neigh_ip_dic[asic_namespace][neighbor_peer_group][prefix_version])
        cmd = f"vtysh -n {asic_index} -c 'show bgp {ipv} {prefix} json'"
        outputs = duthost.shell(cmd, verbose=False)['stdout']
        # remove all control characters from the output
        outputs = re.sub(r'[\x00-\x1F]+', '', outputs)
        try:
            outputs =  json.loads(outputs)
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON output for command: {cmd}")
            return False
        # check if the prefix is in the announced prefixes for the neighbor
        if not outputs and present:
            logger.error(error_msg_present)
            return False
        if not outputs and not present:
            return True

        # check if atleast 1 path has neighbor ip in advertisedTo
        found = False
        for path in outputs['paths']:
            if random_neigh_ip in path['advertisedTo'].keys():
                found = True
                break
        if found ^ present:
            logger.error(error_msg_present if present else error_msg_not_present)
            return False   
    return True


@pytest.fixture(scope="module")
def rand_one_uplink_duthost(duthosts, tbinfo):
    """
    Pick one uplink linecard duthost randomly
    """
    if tbinfo['topo']['type'] != 't2':
        return []
    uplink_dut_list = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        # First get all T3 neighbors, which are of type RegionalHub, AZNGHub
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        device_neighbor_metadata = config_facts['DEVICE_NEIGHBOR_METADATA']
        for k, v in device_neighbor_metadata.items():
            # if this duthost has peer of type RH/AZNG, then it is uplink LC
            if v['type'] == "RegionalHub":
                uplink_dut_list.append(duthost)
                break

    if len(uplink_dut_list) > 0 :
        return random.choice(uplink_dut_list)
    pytest.skip("No uplink linecard found")


def add_radian_prefix(rand_one_uplink_duthost,  prefix_type, prefix, with_config_reload=False):
    """
    Testing cli command to add a prefix along with its configs
    1. Add prefix using the cli command
    2. Verify the prefix is in the CONFIG_DB
    3. Verify the prefix is in the BGP table
    4. Verify the prefix is not in the Route table
    5. Verify the prefix is announced to the neighbor RH
    6. Verify the prefix is not announced to AH
    7. Verify the prefix is not announced to downlink LCs
    """
    # remove the prefix from the prefix list
    prefix_version = ipaddress.ip_network(prefix).version
    RH_PEER_GROUP = f"RH_V{prefix_version}"
    AH_PEER_GROUP = f"AH_V{prefix_version}"
    VOQ_PEER_GROUP = f"VOQ_CHASSIS_V{prefix_version}_PEER"

    duthost = rand_one_uplink_duthost
    neighbor_ip_dic = neighbor_ip(duthost)
    # 1, 2. Add prefix using the cli command and verify the prefix is in the CONFIG_DB
    pytest_assert(add_prefix(duthost, prefix_type, prefix, with_config_reload=with_config_reload), f"Failed to add prefix {prefix} to the prefix list")
    # 3. Verify the prefix is in the BGP table
    pytest_assert(verify_prefix_in_table(duthost, prefix, present=True, table="bgp"), f"Failed to verify prefix {prefix} in the BGP table")
    # 4. Verify the prefix is not in the Routing table
    pytest_assert(verify_prefix_in_table(duthost, prefix, present=False, table="route"), f"Failed to verify prefix {prefix} not in the Routing table")
    # 5. verify the prefix is announced to the neighbor RH
    pytest_assert(verify_prefix_announce_to_neighbor(duthost, prefix, neighbor_ip_dic, RH_PEER_GROUP, present=True), f"Failed to verify prefix {prefix} announced to neighbor RH")
    # 6. verify the prefix is not announced to the neighbor AH
    pytest_assert(verify_prefix_announce_to_neighbor(duthost, prefix, neighbor_ip_dic, AH_PEER_GROUP, present=False), f"Failed to verify prefix {prefix} not announced to neighbor AH")
    # 7. verify the prefix is not announced to the downlink LCs
    pytest_assert(verify_prefix_announce_to_neighbor(duthost, prefix, neighbor_ip_dic, VOQ_PEER_GROUP, present=False), f"Failed to verify prefix {prefix} not announced to downlink LCs")




    

def remove_radian_prefix(rand_one_uplink_duthost, prefix_type, prefix, with_config_reload=False):
    """
    Testing cli command to remove a prefix along with its configs
    1. Remove prefix using the cli command
    2. Verify the prefix is not in the CONFIG_DB
    3. Verify the prefix is not in the BGP table
    4. Verify the prefix is not in the Route table
    """
    
    duthost = rand_one_uplink_duthost
    # remove the prefix from the prefix list
    prefix_version = ipaddress.ip_network(prefix).version
    RH_PEER_GROUP = f"RH_V{prefix_version}"
    AH_PEER_GROUP = f"AH_V{prefix_version}"
    VOQ_PEER_GROUP = f"VOQ_CHASSIS_V{prefix_version}_PEER"
    # 1. Remove prefix using the cli command
    pytest_assert(remove_prefix(duthost, prefix_type, prefix, with_config_reload=with_config_reload), f"Failed to remove prefix {prefix} from the prefix list")
    # 2. Verify the prefix is not in the CONFIG_DB
    pytest_assert(verify_prefix_list_in_db(duthost, prefix_type, prefix, cmd="sudo prefix_list status", add=False), f"Failed to verify prefix {prefix} not in the CONFIG_DB")
    # 3. Verify the prefix is not in the BGP table
    pytest_assert(verify_prefix_in_table(duthost, prefix, present=False, table="bgp"), f"Failed to verify prefix {prefix} not in the BGP table")
    # 4. Verify the prefix is not in the Routing table
    pytest_assert(verify_prefix_in_table(duthost, prefix, present=False, table="route"), f"Failed to verify prefix {prefix} not in the Routing table")

# test cases

def test_radian_prefix_list(rand_one_uplink_duthosts):
    """
    Test the prefix list feature
    """
    prefix_type = "ANCHOR_PREFIX"
    prefix = "FC00::/48"
    add_radian_prefix(rand_one_uplink_duthost)
    remove_radian_prefix(rand_one_uplink_duthost, prefix_type, prefix)

def test_radian_prefix_list_with_config_reload(rand_one_uplink_duthost):
    """
    Test the prefix list feature with config reload
    """
    prefix_type = "ANCHOR_PREFIX"
    prefix = "FC00::/48"
    add_radian_prefix(rand_one_uplink_duthost, prefix_type, prefix, with_config_reload=True)
    remove_radian_prefix(rand_one_uplink_duthost, prefix_type, prefix, with_config_reload=True)

