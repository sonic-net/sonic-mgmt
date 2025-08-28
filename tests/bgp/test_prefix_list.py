import pytest
import random
import logging
import json
import ipaddress
import yaml
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)
PREFIX_TYPE = "ANCHOR_PREFIX"
ANCHOR_PREFIXES = ["50c0::/48", "60c0::/48"]
ROUTES_TO_ADVERTISE = [
    "50c0:0:0:1::/64",
    "50c0:0:0:2::/64",
    "50c0:0:0:3::/64",
    "50c0:0:0:4::/64",
    "60c0:0:0:1::/64",
    "60c0:0:0:2::/64",
    "60c0:0:0:3::/64",
    "60c0:0:0:4::/64"
]
CONSTANTS_FILE = "/etc/sonic/constants.yml"


def op_anchor_prefix_with_cmd(duthost, prefix_type, prefix, action, ignore_error=False):
    # Add or remove prefix list
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
        logger.error("Expected {} occurences of {} in the output, but found {} occurences".format(expected, result_str,
                                                                                                  count))
        return False
    return True


def verify_prefix_in_bgp_table(duthost, ip_version, prefix):
    # Check whether prefix in BGP table
    for asic_index in duthost.get_frontend_asic_ids():
        cmd = "vtysh -n {} -c 'show bgp {} {}'".format(asic_index, ip_version, prefix)
        outputs = duthost.shell(cmd)["stdout"]
        if "Network not in table" in outputs:
            logger.info("Expected prefix {} to be in the BGP table, but it was not found".format(prefix))
            return False
    return True


def verify_prefix_in_fib_table(duthost, prefix):
    # Check whether prefix in FIB table
    for asic_index in duthost.get_frontend_asic_ids():
        cmd = "sonic-db-cli -n asic{} APPL_DB hgetall \"ROUTE_TABLE:{}\"".format(asic_index, prefix)
        output = duthost.shell(cmd)["stdout"].strip().replace("'", "\"")
        route_info = json.loads(output) if output else {}
        if "blackhole" in route_info and route_info["blackhole"] == "true":
            logger.info("Expected prefix {} to be in the FIB table, but it was not found".format(prefix))
            return False

    return True


def verify_prefix_in_table(duthost, prefix, table="bgp"):
    pytest_assert(table in ["bgp", "fib"], "Invalid table specified. Must be 'bgp' or 'fib'.")
    ip_version = "ip" if ipaddress.ip_network(prefix).version == 4 else "ipv6"

    if table == "bgp":
        return verify_prefix_in_bgp_table(duthost, ip_version, prefix)
    else:
        return verify_prefix_in_fib_table(duthost, prefix)


def verify_prefix_received_sonic(nbr_host, prefix, expected_community, unexpected_community):
    cmd = "show ipv6 bgp net {} json".format(prefix)
    output = nbr_host["host"].shell(cmd, module_ignore_errors=True)['stdout'].strip()
    result = False
    try:
        output_json = json.loads(output)
    except Exception as e:
        logger.error("Failed to parse JSON output from neighbor: {}".format(e))
        return False

    if "paths" in output_json:
        for path in output_json["paths"]:
            if not ("community" in path and "list" in path["community"]):
                continue
            if (
                all(item in path["community"]["list"] for item in expected_community) and
                all(item not in path["community"]["list"] for item in unexpected_community)
            ):
                result = True
                break
    return result


def verify_prefix_received(neighbor_type, nbr_host, prefix, expected_community, unexpected_community):
    if neighbor_type == "sonic":
        return verify_prefix_received_sonic(nbr_host, prefix, expected_community, unexpected_community)


def verify_prefix_announce_to_neighbor(neighbor_list, prefix, neighbor_type, expected_community, unexpected_community):
    for nbr_host in neighbor_list:
        if not verify_prefix_received(neighbor_type, nbr_host, prefix, expected_community, unexpected_community):
            logger.warning("Expected prefix {} to be received by neighbor {}, but it was not found"
                           .format(prefix, nbr_host))
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
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        device_metadata = config_facts["DEVICE_METADATA"]
        if ("localhost" in device_metadata and "type" in device_metadata["localhost"] and
            device_metadata["localhost"]["type"] == "SpineRouter" and
                "subtype" in device_metadata["localhost"] and device_metadata["localhost"]["subtype"] == "UpstreamLC"):
            uplink_dut_list.append(duthost)

    if len(uplink_dut_list) == 0:
        pytest.skip("No upstream linecard found")

    yield random.choice(uplink_dut_list)


@pytest.fixture(scope="function")
def common_setup_and_teardown(localhost, nbrhosts, tbinfo, ptfhost, rand_one_uplink_duthost):
    # Fetch anchor communities
    pytest_require(rand_one_uplink_duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
                   "constants.yml doesn't exist, skip test")
    constants = yaml.safe_load(rand_one_uplink_duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
    try:
        community = {
            "anchor_community": constants["constants"]["bgp"]["anchor_route_community"],
            "local_anchor_community": constants["constants"]["bgp"]["local_anchor_route_community"],
            "anchor_contributing_community": constants["constants"]["bgp"]["anchor_contributing_route_community"]
        }
    except KeyError:
        pytest.skip("No anchor route community defined in constants.yml, skip test")

    # Announce routes from ptf to the upstream neighbors and fetch upstream neighbor hosts
    nhipv6 = tbinfo["topo"]["properties"]["configuration_properties"]["common"]["nhipv6"]
    topo_name = tbinfo["topo"]["name"]
    ptf_ip = ptfhost.mgmt_ip
    upstream_nbrs = {nbr_name: nbr_host for nbr_name, nbr_host in nbrhosts.items() if nbr_name.endswith("T3")}
    downstream_nbr_names = [nbr_name for nbr_name in nbrhosts.keys() if nbr_name.endswith("T1")]
    peers_routes = {}
    for nbr_name in downstream_nbr_names:
        peers_routes[nbr_name] = [(route, nhipv6, None) for route in ROUTES_TO_ADVERTISE]
    localhost.announce_routes(topo_name=topo_name, adhoc=True, ptf_ip=ptf_ip, action="announce",
                              peers_routes_to_change=peers_routes, path="../ansible")

    yield upstream_nbrs, community
    localhost.announce_routes(topo_name=topo_name, adhoc=True, ptf_ip=ptf_ip, action="withdraw",
                              peers_routes_to_change=peers_routes, path="../ansible")
    rand_one_uplink_duthost.shell("sudo TSB", module_ignore_errors=True)
    for prefix in ANCHOR_PREFIXES:
        op_anchor_prefix_with_cmd(rand_one_uplink_duthost, PREFIX_TYPE, prefix, "remove", ignore_error=True)


def verify(neighbor_list, neighbor_type, community, rand_one_uplink_duthost):
    result = {"prefix_in_db": set(), "prefix_in_bgp_table": set(), "prefix_in_fib_table": set(),
              "prefix_announcing": set()}
    for prefix in ANCHOR_PREFIXES:
        if verify_prefix_list_in_db(rand_one_uplink_duthost, PREFIX_TYPE, prefix):
            result["prefix_in_db"].add(prefix)
        if verify_prefix_in_table(rand_one_uplink_duthost, prefix, "bgp"):
            result["prefix_in_bgp_table"].add(prefix)
        if verify_prefix_in_table(rand_one_uplink_duthost, prefix, "fib"):
            result["prefix_in_fib_table"].add(prefix)
        if verify_prefix_announce_to_neighbor(neighbor_list, prefix, neighbor_type,
                                              [community["anchor_community"]],
                                              [community["anchor_contributing_community"],
                                               community["local_anchor_community"]]):
            result["prefix_announcing"].add(prefix)
    for prefix in ROUTES_TO_ADVERTISE:
        if verify_prefix_announce_to_neighbor(neighbor_list, prefix, neighbor_type,
                                              [community["anchor_contributing_community"]],
                                              [community["anchor_community"],
                                               community["local_anchor_community"]]):
            result["prefix_announcing"].add(prefix)
    logger.info("Verify result: {}".format(result))
    return result


def test_prefix_list_tsa(rand_one_uplink_duthost, request, common_setup_and_teardown):
    neighbor_type = request.config.getoption("neighbor_type")
    upstream_nbrs, community = common_setup_and_teardown
    upstream_nbr_hosts = [nbrhost for nbrhost in upstream_nbrs.values()]
    for prefix in ANCHOR_PREFIXES:
        op_anchor_prefix_with_cmd(rand_one_uplink_duthost, PREFIX_TYPE, prefix, "add")
    result = verify(upstream_nbr_hosts, neighbor_type, community, rand_one_uplink_duthost)
    # After adding Anchor prefix, we need below verication:
    # 1) Anchor prefixes are existing in DB
    # 2) Anchor prefixes are existing in BGP table in DUT
    # 3) Anchor prefixes are NOT existing in FIB table in DUT
    # 4) Anchor prefixes and contributing routes are announcing to the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(ANCHOR_PREFIXES),
                  "Prefix in db is unexpected: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(ANCHOR_PREFIXES),
                  "Prefix in bgp table is unexpected: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == len(ANCHOR_PREFIXES) + len(ROUTES_TO_ADVERTISE),
                  "Prefix announcing is unexpected: {}".format(result["prefix_announcing"]))
    rand_one_uplink_duthost.shell("sudo TSA")
    result = verify(upstream_nbr_hosts, neighbor_type, community, rand_one_uplink_duthost)
    # After TSA, only 4) prefix announcing changed: Anchor prefixes and contributing routes are NOT announcing to
    # the neighbors
    pytest_assert(len(result["prefix_in_db"]) == len(ANCHOR_PREFIXES),
                  "Prefix in db is unexpected: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(ANCHOR_PREFIXES),
                  "Prefix in bgp table is unexpected: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == 0,
                  "Prefix announcing is unexpected: {}".format(result["prefix_announcing"]))
    rand_one_uplink_duthost.shell("sudo TSB")
    result = verify(upstream_nbr_hosts, neighbor_type, community, rand_one_uplink_duthost)
    # After TSA, only 4) prefix announcing changed: Anchor prefixes and contributing routes are announcing to
    # the neighbors with correct communities
    pytest_assert(len(result["prefix_in_db"]) == len(ANCHOR_PREFIXES),
                  "Prefix in db is unexpected: {}".format(result["prefix_in_db"]))
    pytest_assert(len(result["prefix_in_bgp_table"]) == len(ANCHOR_PREFIXES),
                  "Prefix in bgp table is unexpected: {}".format(result["prefix_in_bgp_table"]))
    pytest_assert(len(result["prefix_in_fib_table"]) == 0,
                  "Prefix in fib table is unexpected: {}".format(result["prefix_in_fib_table"]))
    pytest_assert(len(result["prefix_announcing"]) == len(ANCHOR_PREFIXES) + len(ROUTES_TO_ADVERTISE),
                  "Prefix announcing is unexpected: {}".format(result["prefix_announcing"]))
