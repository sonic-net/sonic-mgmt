import pytest
import random
import logging
import json
import time
import yaml
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.parallel import parallel_run

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)
PREFIX_TYPE = "ANCHOR_PREFIX"
ANCHOR_PREFIXES = {
    "ipv6": ["50c0::/48", "60c0::/48"],
    "ipv4": ["205.168.0.0/24", "205.169.0.0/24"]
}
ROUTES_TO_ADVERTISE = {
    "ipv6": [
        "50c0:0:0:1::/64",
        "50c0:0:0:2::/64",
        "60c0:0:0:1::/64",
        "60c0:0:0:2::/64",
    ],
    "ipv4": [
        "205.168.0.64/26",
        "205.168.0.128/26",
        "205.169.0.64/26",
        "205.169.0.128/26",
    ]
}
CONSTANTS_FILE = "/etc/sonic/constants.yml"


def op_anchor_prefix_with_cmd(duthost, prefix_type, prefix, action, ignore_error=False):
    # Add or remove prefix list
    pytest_assert(action in ["add", "remove"], "Invalid action specified. Must be 'add' or 'remove'.")
    cmd = "sudo prefix_list {} {} {}".format(action, prefix_type, prefix)
    duthost.shell(cmd, module_ignore_errors=ignore_error)
    return True


def verify_prefix_list_in_db(duthost, prefix_type, prefix):
    cmd = "prefix_list status"
    outputs = duthost.shell(cmd)['stdout']
    # string matching to see if prefix type and prefix are in the output
    expected = len(duthost.get_frontend_asic_ids())
    # check if we have n_asic entry matches of (PREFIX_TYPE, PREFIX) in the output
    result_str = "('{}', '{}')".format(prefix_type, prefix)
    count = outputs.count(result_str)
    if count != expected:
        logger.warning("Expected {} occurences of {} in the output, but found {} occurences"
                       .format(expected, result_str, count))
        return False
    return True


def verify_prefix_in_bgp_table(duthost, ip_version, prefix):
    # Check whether prefix in BGP table
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = f"-n {asic_index}" if duthost.is_multi_asic else ""
        cmd = f"vtysh {asic_ns} -c 'show bgp {ip_version} {prefix}'"
        outputs = duthost.shell(cmd)["stdout"]
        if "Network not in table" in outputs:
            logger.info("Expected prefix {} to be in the BGP table, but it was not found".format(prefix))
            return False
    return True


def verify_prefix_in_fib_table(duthost, prefix):
    # Check whether prefix in FIB table
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = f"-n asic{asic_index}" if duthost.is_multi_asic else ""
        cmd = f"sonic-db-cli {asic_ns} APPL_DB hgetall \"ROUTE_TABLE:{prefix}\""
        output = duthost.shell(cmd)["stdout"].strip().replace("'", "\"")
        route_info = json.loads(output) if output else {}
        if route_info == {} or ("blackhole" in route_info and route_info["blackhole"] == "true"):
            logger.info("Expected prefix {} to be in the FIB table, but it was not found".format(prefix))
            return False

    return True


def verify_prefix_in_table(duthost, prefix, ip_version, table="bgp"):
    pytest_assert(table in ["bgp", "fib"], "Invalid table specified. Must be 'bgp' or 'fib'.")
    if table == "bgp":
        return verify_prefix_in_bgp_table(duthost, ip_version, prefix)
    else:
        return verify_prefix_in_fib_table(duthost, prefix)


def check_sonic_route_receive(present, output_json, expected_community, unexpected_community):
    result = False
    if present:
        if "paths" in output_json:
            for path in output_json["paths"]:
                if not ("community" in path and "list" in path["community"]):
                    # If community doesn't exist in route and there is not expected community, we can treat it as True
                    if len(expected_community) == 0:
                        result = True
                        break
                    else:
                        continue
                # If community exists in route, then we need to check whether it match expected / unexpected community
                if (
                    all(item in path["community"]["list"] for item in expected_community) and
                    all(item not in path["community"]["list"] for item in unexpected_community)
                ):
                    result = True
                    break
    else:
        if output_json == {}:
            result = True
    return result


def check_eos_route_receive(present, output_json, expected_community, unexpected_community, hostname, prefix):
    result = False
    if present:
        try:
            paths = output_json["vrfs"]["default"]["bgpRouteEntries"][prefix]["bgpRoutePaths"]
            for path in paths:
                if len(expected_community) == 0 and "communityList" not in path["routeDetail"]:
                    # If community doesn't exist in route and there is not expected community, we can treat it as True
                    result = True
                # If community exists in route, then we need to check whether it match expected / unexpected community
                if (
                    all(item in path["routeDetail"]["communityList"] for item in expected_community) and
                    all(item not in path["routeDetail"]["communityList"] for item in unexpected_community)
                ):
                    result = True
        except KeyError:
            logger.warning("Cannot find route path info from EOS neighbor {}".format(hostname))
    else:
        if (
            "vrfs" not in output_json or
            "default" not in output_json["vrfs"] or
            "bgpRouteEntries" not in output_json["vrfs"]["default"] or
            prefix not in output_json["vrfs"]["default"]["bgpRouteEntries"]
        ):
            result = True
    return result


def check_route_receive(prefix, expected_community, unexpected_community, neighbor_type, present=True, node=None,
                        results=None):
    result = False
    output_json = node["host"].get_route(prefix)
    logger.info("Neighbor {} route info: {}".format(node["host"].hostname, output_json))
    hostname = node["host"].hostname
    if neighbor_type == "sonic":
        result = check_sonic_route_receive(present, output_json, expected_community, unexpected_community)
    elif neighbor_type == "eos":
        result = check_eos_route_receive(present, output_json, expected_community, unexpected_community, hostname,
                                         prefix)
    results[node["host"].hostname] = result


def verify_prefix_received_in_neighbor(neighbor_list, prefix, expected_community, unexpected_community, present,
                                       neighbor_type):
    result = parallel_run(check_route_receive,
                          (prefix, expected_community, unexpected_community, neighbor_type, present), {},
                          neighbor_list, timeout=60)
    logger.info("Prefix received result: {}".format(result))
    return all(item is True for item in result.values())


@pytest.fixture(scope="module")
def rand_one_uplink_duthost(duthosts):
    """
    Pick one uplink linecard duthost randomly
    """
    uplink_dut_list = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        device_metadata = config_facts["DEVICE_METADATA"]
        if ("localhost" in device_metadata and "type" in device_metadata["localhost"] and
            device_metadata["localhost"]["type"] == "SpineRouter" and
                "subtype" in device_metadata["localhost"] and device_metadata["localhost"]["subtype"] == "UpstreamLC"):
            uplink_dut_list.append(duthost)
    if len(uplink_dut_list) == 0:
        pytest.skip("No upstream linecard found")

    yield random.choice(uplink_dut_list)


@pytest.fixture(params=["ipv4", "ipv6"])
def ip_version(request):
    return request.param


def announce_routes(localhost, tbinfo, ptfhost, routes, neighbor_names, ip_version, action="announce"):
    nh = tbinfo["topo"]["properties"]["configuration_properties"]["common"]["nh{}".format(ip_version)]
    topo_name = tbinfo["topo"]["name"]
    ptf_ip = ptfhost.mgmt_ip
    peers_routes = {}
    for nbr_name in neighbor_names:
        peers_routes[nbr_name] = [(route, nh, None) for route in routes]
    localhost.announce_routes(topo_name=topo_name, adhoc=True, ptf_ip=ptf_ip, action=action,
                              peers_routes_to_change=peers_routes, path="../ansible")


def construct_neighbor_routes(ah_nbrs, rh_nbrs, community, duthost, anchor_prefixes, anchor_contributing_routes):
    # Construct the object to indicates prefixes should be announced to which neighbor with what communities
    # Return sample:
    # {
    #     "prefix":
    #      [
    #         {
    #             "expected_community": [...],
    #             "unexpected_community": [...],
    #             "neighbors": [...],
    #             "type": "anchor"
    #         },
    #         {
    #             "expected_community": [...],
    #             "unexpected_community": [...],
    #             "neighbors": [...],
    #             "type": "anchor"
    #         },
    #     ]
    # }
    announced_result = {}
    not_announced_result = {}
    # Anchor and contributing routes should be announced to rh and ah neighbor
    for prefix in anchor_prefixes:
        announced_result.setdefault(prefix, [])
        announced_result[prefix].append({
            "expected_community": [community["anchor_community"]],
            "unexpected_community": [community["local_anchor_community"], community["anchor_contributing_community"]],
            "neighbors": rh_nbrs + ah_nbrs,
            "type": "anchor"
        })
    for prefix in anchor_contributing_routes:
        announced_result.setdefault(prefix, [])
        announced_result[prefix].append({
            "expected_community": [community["anchor_contributing_community"]],
            "unexpected_community": [community["local_anchor_community"], community["anchor_community"]],
            "neighbors": rh_nbrs + ah_nbrs,
            "type": "contributing"
        })

    return announced_result, not_announced_result


@pytest.fixture(scope="function")
def common_setup_and_teardown(localhost, nbrhosts, tbinfo, ptfhost, rand_one_uplink_duthost, ip_version):
    duthost = rand_one_uplink_duthost
    anchor_prefixes = ANCHOR_PREFIXES[ip_version]
    anchor_contributing_routes = ROUTES_TO_ADVERTISE[ip_version]
    # Fetch anchor communities
    pytest_require(duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
                   "constants.yml doesn't exist, skip test")
    constants = yaml.safe_load(duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
    try:
        community = {
            "anchor_community": constants["constants"]["bgp"]["anchor_route_community"],
            "local_anchor_community": constants["constants"]["bgp"]["local_anchor_route_community"],
            "anchor_contributing_community": constants["constants"]["bgp"]["anchor_contributing_route_community"]
        }
    except KeyError:
        pytest.skip("No anchor route community defined in constants.yml, skip test")

    downstream_nbr_names = [nbr_name for nbr_name in nbrhosts.keys() if nbr_name.endswith("T1")]
    # Fetch ah and rh neighbor
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    neighbor_metadata = config_facts["DEVICE_NEIGHBOR_METADATA"]
    rh_neighbor_name = [key for key, value in neighbor_metadata.items() if value["type"] == "RegionalHub"]
    ah_neighbor_name = [key for key, value in neighbor_metadata.items() if value["type"] == "AZNGHub"]
    rh_neighbors = [nbr_host for nbr_name, nbr_host in nbrhosts.items() if nbr_name in rh_neighbor_name]
    ah_neighbors = [nbr_host for nbr_name, nbr_host in nbrhosts.items() if nbr_name in ah_neighbor_name]

    announced_neighbors, not_announced_neighbors = construct_neighbor_routes(ah_neighbors, rh_neighbors, community,
                                                                             duthost, anchor_prefixes,
                                                                             anchor_contributing_routes)

    yield (anchor_prefixes, anchor_contributing_routes, announced_neighbors, not_announced_neighbors,
           downstream_nbr_names, ip_version, rand_one_uplink_duthost)

    announce_routes(localhost, tbinfo, ptfhost, ROUTES_TO_ADVERTISE[ip_version], downstream_nbr_names, ip_version,
                    "withdraw")
    duthost.shell("sudo TSB", module_ignore_errors=True)
    for prefix in ANCHOR_PREFIXES[ip_version]:
        op_anchor_prefix_with_cmd(duthost, PREFIX_TYPE, prefix, "remove", ignore_error=True)


def verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type):
    # Wait for changes be applied
    time.sleep(10)
    result = {"prefix_in_db": set(), "prefix_in_bgp_table": set(), "prefix_in_fib_table": set(),
              "prefix_announcing": set()}
    for prefix, values in announced_neighbors.items():
        if values[0]["type"] == "anchor":
            # Check whether prefix existing in DUT's CONFIG_DB
            if verify_prefix_list_in_db(duthost, PREFIX_TYPE, prefix):
                result["prefix_in_db"].add(prefix)
            # Check whether prefix existing in DUT's BGP table
            if verify_prefix_in_table(duthost, prefix, ip_version, "bgp"):
                result["prefix_in_bgp_table"].add(prefix)
            # Check whether prefix existing in DUT's FIB table
            if verify_prefix_in_table(duthost, prefix, ip_version, "fib"):
                result["prefix_in_fib_table"].add(prefix)

        # Check whether routes are received on expected neighbors, because a route maybe be advertised to different
        # neighbors with different communities, hence we need to loop the values
        expected_received = True
        for item in values:
            expected_received &= verify_prefix_received_in_neighbor(item["neighbors"], prefix,
                                                                    item["expected_community"],
                                                                    item["unexpected_community"], present=True,
                                                                    neighbor_type=neighbor_type)
        # Check whether routes are NOT received on unexpected neighbors, only one scenario of a single route,
        # hence we only use not_announced_neighbors[prefix][0]
        expected_no_received = True
        if expected_received and prefix in not_announced_neighbors:
            expected_no_received = verify_prefix_received_in_neighbor(not_announced_neighbors[prefix][0]["neighbors"],
                                                                      prefix, [], [], present=False,
                                                                      neighbor_type=neighbor_type)
        if expected_no_received and expected_received:
            result["prefix_announcing"].add(prefix)
    # Check whether routes are NOT received on unexpected neighbors, only one scenario of a single route,
    # hence we only use not_announced_neighbors[prefix][0]
    for prefix in not_announced_neighbors.keys():
        if prefix in announced_neighbors:
            continue
        if verify_prefix_received_in_neighbor(not_announced_neighbors[prefix][0]["neighbors"], prefix, [], [],
                                              present=False, neighbor_type=neighbor_type):
            result["prefix_announcing"].add(prefix)

    logger.info("Verify result: {}".format(result))
    return result


def test_prefix_list_tsa(common_setup_and_teardown, localhost, tbinfo, ptfhost, request):
    (anchor_prefixes, anchor_contributing_routes, announced_neighbors, not_announced_neighbors,
     downstream_nbr_names, ip_version, duthost) = common_setup_and_teardown
    neighbor_type = request.config.getoption("neighbor_type")
    announce_routes(localhost, tbinfo, ptfhost, anchor_contributing_routes, downstream_nbr_names, ip_version)
    for prefix in anchor_prefixes:
        op_anchor_prefix_with_cmd(duthost, PREFIX_TYPE, prefix, "add")
    result = verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type)
    # After adding Anchor prefix, we need below verification:
    # 1) Anchor prefixes are existing in DB
    # 2) Anchor prefixes are existing in BGP table in DUT
    # 3) Anchor prefixes are NOT existing in FIB table in DUT
    # 4) Anchor prefixes and contributing routes are announcing to the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(anchor_prefixes),
                  "Prefix in db is unexpected before TSA: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(anchor_prefixes),
                  "Prefix in bgp table is unexpected before TSA: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected before TSA: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == len(anchor_prefixes) + len(anchor_contributing_routes),
                  "Prefix announcing is unexpected before TSA: {}".format(result["prefix_announcing"]))
    duthost.shell("sudo TSA")
    result = verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type)
    # After TSA, only 4) prefix announcing changed: Anchor prefixes and contributing routes are NOT announcing to
    # the neighbors
    pytest_assert(len(result["prefix_in_db"]) == len(anchor_prefixes),
                  "Prefix in db is unexpected after TSA: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(anchor_prefixes),
                  "Prefix in bgp table is unexpected after TSA: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected after TSA: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == 0,
                  "Prefix announcing is unexpected after TSA: {}".format(result["prefix_announcing"]))
    duthost.shell("sudo TSB")
    result = verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type)
    # After TSB, only 4) prefix announcing changed: Anchor prefixes and contributing routes are announcing to
    # the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(anchor_prefixes),
                  "Prefix in db is unexpected after TSB: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(anchor_prefixes),
                  "Prefix in bgp table is unexpected after TSB: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected after TSB: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == len(anchor_prefixes) + len(anchor_contributing_routes),
                  "Prefix announcing is unexpected after TSB: {}".format(result["prefix_announcing"]))


def test_prefix_list_specific_routes(common_setup_and_teardown, localhost, tbinfo, ptfhost,
                                     request):
    (anchor_prefixes, anchor_contributing_routes, announced_neighbors, not_announced_neighbors,
     downstream_nbr_names, ip_version, duthost) = common_setup_and_teardown
    neighbor_type = request.config.getoption("neighbor_type")
    for prefix in anchor_prefixes:
        op_anchor_prefix_with_cmd(duthost, PREFIX_TYPE, prefix, "add")
    result = verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type)
    # After adding Anchor prefix but not advertising specific routes from neighbor, we need below verification:
    # 1) Anchor prefixes are existing in DB
    # 2) Anchor prefixes are NOT existing in BGP table in DUT
    # 3) Anchor prefixes are NOT existing in FIB table in DUT
    # 4) Anchor prefixes and contributing routes are NOT announcing to the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(anchor_prefixes),
                  "Prefix in db is unexpected before adding specific routes: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == 0,
                  "Prefix in bgp table is unexpected before adding specific routes: {}"
                  .format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected before adding specific routes: {}"
                  .format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == 0,
                  "Prefix announcing is unexpected before adding specific routes: {}"
                  .format(result["prefix_announcing"]))
    announce_routes(localhost, tbinfo, ptfhost, anchor_contributing_routes, downstream_nbr_names, ip_version)
    result = verify(duthost, announced_neighbors, not_announced_neighbors, ip_version, neighbor_type)
    # After announce specific routes, 2) and 4) changed
    # 2) Anchor prefixes are existing in BGP table in DUT
    # 4) Anchor prefixes and contributing routes are NOT announcing to the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(anchor_prefixes),
                  "Prefix in db is unexpected after adding specific routes: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(anchor_prefixes),
                  "Prefix in bgp table is unexpected after adding specific routes: {}"
                  .format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected after adding specific routes: {}"
                  .format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == len(anchor_prefixes) + len(anchor_contributing_routes),
                  "Prefix announcing is unexpected after adding specific routes: {}"
                  .format(result["prefix_announcing"]))
