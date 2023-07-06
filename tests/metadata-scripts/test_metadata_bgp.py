import pytest
import os
import logging
import ipaddr as ipaddress
import json
import re
import random
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common import config_reload


pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
]
SYSTEM_STABILIZE_MAX_TIME = 300
MAX_CHECK_BGP_NEI = 8
logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def upload_metadata_scripts(duthosts, enum_frontend_dut_hostname):
    duthost = duthosts[enum_frontend_dut_hostname]
    base_path = os.path.dirname(__file__)
    metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
    if os.path.exists(metadata_scripts_path):
        path_exists = duthost.stat(path="/tmp/anpscripts/")
        if not path_exists["stat"]["exists"]:
            duthost.command("mkdir /tmp/anpscripts")
            duthost.copy(src=metadata_scripts_path + "/", dest="/tmp/anpscripts/")
        return True
    return False


@pytest.fixture(scope="module")
def get_lo_intf(duthosts, enum_frontend_dut_hostname):
    duthost = duthosts[enum_frontend_dut_hostname]
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    lo_intf = {}
    for i in range(0, 2):
        addr = mg_facts["minigraph_lo_interfaces"][i]["addr"]
        if ipaddress.IPNetwork(addr).version == 4:
            lo_intf[4] = ipaddress.IPNetwork(addr)
        else:
            # The IPv6 Loopback announced to neighbors is /64
            lo_intf[6] = ipaddress.IPNetwork(addr + "/64")

    return lo_intf


@pytest.fixture(scope="module")
def random_bgp_neighbors(duthosts, enum_frontend_dut_hostname):
    # It would take 20 mins to get all neighbor info for normal T1 topo
    # It is not necessary, just pick up of several to check would be good enough
    duthost = duthosts[enum_frontend_dut_hostname]
    random_nei = []
    bgp_facts = get_bgp_facts(duthost)
    for asic_id, bgp_fact in bgp_facts.items():
        for k, v in bgp_fact.items():
            if "INTERNAL" in v.get("peer group", ""):
                continue
            random_nei.append(k)
    if len(random_nei) / MAX_CHECK_BGP_NEI > 1:
        random_nei = random.sample(random_nei, MAX_CHECK_BGP_NEI)
    return random_nei


def transform_to_json(output):
    # Define regular expression pattern to extract relevant information
    pattern = r"\*>?\s*(?P<network>[^/]+/\d+)\s*(?P<next_hop>\d+\.\d+\.\d+\.\d+)?\s*(?P<metric>.*)"

    # Extract relevant information using regular expression
    matches = re.finditer(pattern, output)

    # Store information in a dictionary
    result = {}
    for match in matches:
        network = match.group("network")
        next_hop = match.group("next_hop")
        metric = match.group("metric")
        result[network] = {"next_hop": next_hop, "metric": metric}

    # Convert dictionary to JSON
    return json.dumps(result)


def _check_bgp_adervertised_routes(duthost, peer_ip, ip_ver, lo_addr, asic_id):
    routes_json = _get_advertised_routes(duthost, peer_ip, ip_ver, asic_id)

    for prefix, v in routes_json.items():
        logger.info(
            "Verifying only loopback routes(ipv{}) are announced to {}".format(
                ip_ver, peer_ip
            )
        )
        if ipaddress.IPNetwork(prefix) != lo_addr:
            logger.warn(
                "route for {} is found on {}, which is not in loopback address".format(
                    prefix, peer_ip
                )
            )
            return False

    return True


def check_bgp_adervertised_routes(duthost, status, lo_addr, check_nei):
    if status == "away":
        bgp_facts = get_bgp_facts(duthost)
        for asic_id, bgp_fact in bgp_facts.items():
            for k, v in bgp_fact.items():
                if "INTERNAL" in v.get("peer group", "") or k not in check_nei:
                    continue
                pytest_assert(
                    _check_bgp_adervertised_routes(
                        duthost, k, v["ip_version"], lo_addr[v["ip_version"]], asic_id
                    ),
                    "BGP routes are not withdrawed",
                )
    return True


def check_bgp_status(duthost, status):
    bgp_facts = get_bgp_facts(duthost)
    for asic_id, bgp_fact in bgp_facts.items():
        for k, v in bgp_fact.items():
            if "INTERNAL" in v.get("peer group", ""):
                continue
            pytest_assert(v["admin"] == status, "BGP status is incorrect")
    return True


def get_neighbor_seq(duthost, log_file):
    duthost.shell('show logging -f | grep "bgp_neighbor" > {}'.format(log_file))


def bgp_ordered_check(duthost, log_file):
    ext_bgp = 0
    bgp_facts = get_bgp_facts(duthost)

    for asic_id, bgp_fact in bgp_facts.items():
        for k, v in bgp_fact.items():
            if "INTERNAL" in v.get("peer group", ""):
                continue
            else:
                ext_bgp = ext_bgp + 1

    matches = []
    with open(log_file) as file:
        # Read the entire file into a string
        text = file.read()

        # Define the regular expression pattern
        pattern = r"bgp_neighbor:.*type:(\S+)\s+"

        # Search for the pattern in the text
        matches = re.findall(pattern, text, re.IGNORECASE)

    pytest_assert(
        len(matches) == ext_bgp,
        "BGP neighbor number mismatch, eBGP: {} != BGP neighbor: {}".format(
            ext_bgp, len(matches)
        ),
    )

    first = matches[0]
    changes = 0
    for match in matches:
        if first != match:
            changes = changes + 1
            first = match

    pytest_assert(changes <= 1, "BGP oper not ordered")
    logger.info("{} bgp neighbors, bgp order changed {}".format(ext_bgp, changes))
    return True


def _get_advertised_routes(duthost, peer_ip, ip_ver, asic_id):
    stdout = duthost.shell(
        "sudo sonic_installer list | grep Current | awk '{print $2}'"
    )["stdout_lines"]
    current_version = ""
    if stdout != []:
        current_version = str(stdout[0]).replace("\n", "")

    routes_json = {}
    if "2018" in current_version:
        if 4 == ip_ver:
            bgp_nbr_cmd = (
                "sudo vtysh -c 'show ip bgp neighbors {} advertised-routes'".format(
                    peer_ip
                )
            )
        else:
            bgp_nbr_cmd = (
                "sudo vtysh -c 'show bgp ipv6 neighbors {} advertised-routes'".format(
                    peer_ip
                )
            )
        res = duthost.command(bgp_nbr_cmd)

        routes_json = transform_to_json(res["stdout"])
    else:
        if asic_id == "":
            asic_info = asic_id
        else:
            asic_info = "-n {}".format(asic_id)
        if 4 == ip_ver:
            bgp_nbr_cmd = "sudo vtysh {} -c 'show ip bgp neighbors {} advertised-routes json'".format(
                asic_info, peer_ip
            )
        else:
            bgp_nbr_cmd = "sudo vtysh {} -c 'show bgp ipv6 neighbors {} advertised-routes json'".format(
                asic_info, peer_ip
            )

        res = duthost.command(bgp_nbr_cmd)
        routes_json.update(json.loads(res["stdout"]).get("advertisedRoutes", {}))

    return routes_json


def get_bgp_facts(duthost):
    front_end_asics = [""]
    bgp_facts = {}
    if duthost.sonichost.is_multi_asic:
        front_end_asics = duthost.get_frontend_asic_ids()
        for asic_id in front_end_asics:
            bgp_facts[asic_id] = duthost.bgp_facts(instance_id=asic_id)[
                "ansible_facts"
            ]["bgp_neighbors"]
    else:
        bgp_facts[""] = duthost.bgp_facts()["ansible_facts"]["bgp_neighbors"]
    return bgp_facts


def get_advertised_routes(duthost, check_nei):
    bgp_routes_nei = {}
    bgp_facts = get_bgp_facts(duthost)
    for asic_id, bgp_fact in bgp_facts.items():
        for k, v in bgp_fact.items():
            if "INTERNAL" in v.get("peer group", "") or k not in check_nei:
                continue
            bgp_routes_nei[k] = _get_advertised_routes(
                duthost, k, v["ip_version"], asic_id
            )
            logger.info(
                "Asic {} {} routes advertised to neighbor {}".format(
                    asic_id, len(bgp_routes_nei[k]), k
                )
            )
    return bgp_routes_nei


def routes_adv_done(duthost, orig_routes, check_nei):
    new_adv_routes = get_advertised_routes(duthost, check_nei)
    # compare keys between orig_routes and new_adv_routes
    # then compare sub keys of orig_routes and new_adv_routes
    if set(orig_routes.keys()) == set(new_adv_routes.keys()):
        for key in orig_routes:
            orig_keys = set(orig_routes[key].keys())
            new_keys = set(new_adv_routes[key].keys())
            if orig_keys != new_keys:
                logger.info("Routes advertised to neighbor changed: {}".format(orig_keys ^ new_keys))
                return False
    else:
        return False
    return True


@pytest.fixture(scope="module")
def setup_teardown(duthosts, enum_frontend_dut_hostname):
    yield
    duthost = duthosts[enum_frontend_dut_hostname]
    logger.info("Reload Config DB")
    config_reload(
        duthost,
        config_source="config_db",
        safe_reload=True,
        check_intf_up_ports=True,
    )


@pytest.mark.parametrize(
    "ts_method", ["bgpshut", "forbidroutemap"], ids=["bgpshut", "forbidroutemap"]
)
def test_bgp_traffic_shift_away(
    duthosts,
    request,
    enum_frontend_dut_hostname,
    ts_method,
    tbinfo,
    setup_teardown,
    upload_metadata_scripts,
    get_lo_intf,
    random_bgp_neighbors,
):
    metadata_process = request.config.getoption("metadata_process")
    if not metadata_process:
        # this test case is only for sonic-metadata script test
        return

    pytest_assert(upload_metadata_scripts, "Failed to upload script files")
    # 1. run script to do the isolation with forbidroutempa and bgpshut
    # 2. check the traffic and bgp routes, if nothing adervertised to all neighbors and bgp status
    # 3. run script to do the unisolation with forbidroutempa and bgpshut
    # 4. check the traffic and bgp routes, if adervertised to all neighbors and bgp status
    try:
        duthost = duthosts[enum_frontend_dut_hostname]
        duthost.command("chmod +x /tmp/anpscripts/bgp_neighbor")
        check_bgp_status(duthost, "up")
        timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

        log_file = "/tmp/bgp_oper.{}.txt".format(timestamp)

        duthost.shell(
            "nohup show logging -f > {} &".format(log_file), executable="/bin/bash"
        )
        logger.info("Restore traffic start")
        duthost.command(
            "python /tmp/anpscripts/bgp_neighbor -m {} shutdown 0.0.0.0".format(
                ts_method
            )
        )
        logger.info("Restore traffic end")
        out = duthost.shell(
            "ps -ef | grep 'show logging -f' | grep -v grep", executable="/bin/bash"
        )
        if len(out["stdout"]) >= 1:
            duthost.command(
                "kill -9 {}".format(out["stdout"].split()[1]), executable="/bin/bash"
            )
        else:
            logger.error(
                "show logging -f ended unexpected, may cause ordered check failure"
            )

        if ts_method == "bgpshut" or "t0" in tbinfo["topo"]["type"]:
            check_bgp_status(duthost, "down")
            logger.info("All BGP neighbors are admin down")
        else:
            pytest_assert(
                check_bgp_adervertised_routes(
                    duthost, "away", get_lo_intf, random_bgp_neighbors
                ),
                "BGP routes are not withdrawed",
            )
            logger.info("All BGP routes are withdrawed")

        duthost.fetch(src=log_file, dest="/tmp/fib")
        if ts_method == "bgpshut" and "t1" in tbinfo["topo"]["type"]:
            pytest_assert(
                bgp_ordered_check(
                    duthost,
                    "/tmp/fib/{}/tmp/bgp_oper.{}.txt".format(
                        duthost.hostname, timestamp
                    ),
                ),
                "BGP is not ordered shutdown",
            )
        duthost.command("rm {}".format(log_file))

    finally:
        duthost.command(
            "python /tmp/anpscripts/bgp_neighbor -m {} startup 0.0.0.0".format(
                ts_method
            )
        )


@pytest.mark.parametrize(
    "ts_method", ["bgpshut", "forbidroutemap"], ids=["bgpshut", "forbidroutemap"]
)
def test_bgp_traffic_shift_restore(
    duthosts,
    request,
    enum_frontend_dut_hostname,
    ts_method,
    tbinfo,
    setup_teardown,
    upload_metadata_scripts,
    random_bgp_neighbors,
):
    metadata_process = request.config.getoption("metadata_process")
    if not metadata_process:
        # this test case is only for sonic-metadata script test
        return

    pytest_assert(upload_metadata_scripts, "Failed to upload script files")

    try:
        duthost = duthosts[enum_frontend_dut_hostname]
        duthost.command("chmod +x /tmp/anpscripts/bgp_neighbor")
        check_bgp_status(duthost, "up")
        timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

        log_file = "/tmp/bgp_oper.{}.txt".format(timestamp)

        orig_adv_routes = get_advertised_routes(duthost, random_bgp_neighbors)
        pytest_assert(len(orig_adv_routes) > 0, "Advertised routes is zero")

        duthost.command("python /tmp/anpscripts/bgp_neighbor shutdown 0.0.0.0")
        check_bgp_status(duthost, "down")

        duthost.shell(
            "nohup show logging -f > {} &".format(log_file), executable="/bin/bash"
        )

        logger.info("Restore traffic start")
        duthost.command(
            "python /tmp/anpscripts/bgp_neighbor -m {} startup 0.0.0.0".format(
                ts_method
            )
        )
        logger.info("Restore traffic end")
        out = duthost.shell(
            "ps -ef | grep 'show logging -f' | grep -v grep",
            executable="/bin/bash",
            module_ignore_errors=True,
        )
        if len(out["stdout"]) >= 1:
            duthost.command(
                "kill -9 {}".format(out["stdout"].split()[1]), executable="/bin/bash"
            )
        else:
            logger.info(
                "show logging -f ended unexpected, may cause ordered check failure"
            )
        check_bgp_status(duthost, "up")
        duthost.fetch(src=log_file, dest="/tmp/fib")
        if "t1" in tbinfo["topo"]["type"]:
            pytest_assert(
                bgp_ordered_check(
                    duthost,
                    "/tmp/fib/{}/tmp/bgp_oper.{}.txt".format(
                        duthost.hostname, timestamp
                    ),
                ),
                "BGP is not ordered startup",
            )

        pytest_assert(
            wait_until(
                90,
                10,
                30,
                routes_adv_done,
                duthost,
                orig_adv_routes,
                random_bgp_neighbors,
            ),
            "BGP routes are not equal with previous",
        )

        logger.info("advertised routes to {} neighbors".format(len(orig_adv_routes)))
        duthost.command("rm {}".format(log_file))

    finally:
        duthost.command(
            "python /tmp/anpscripts/bgp_neighbor -m {} startup 0.0.0.0".format(
                ts_method
            )
        )
