import pytest
import logging
import re
import time

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.helpers.bgp import run_bgp_facts
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv6_only_topology
from ipaddress import ip_interface


pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

CUSTOMIZED_BGP_ROUTER_ID = "8.8.8.8"


def verify_bgp(enum_asic_index, duthost, expected_bgp_router_id, neighbor_type, nbrhosts, tbinfo):
    is_v6_topo = is_ipv6_only_topology(tbinfo)
    cmd = "show ipv6 bgp summary" if is_v6_topo else "show ip bgp summary"
    output = duthost.shell(cmd, module_ignore_errors=True)["stdout"]

    # Verify router id from DUT itself
    pattern = r"BGP router identifier (\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, output)
    pytest_assert(match, (
        "Cannot get actual BGP router id from [{}]. "
    ).format(output))

    pytest_assert(match.group(1) == expected_bgp_router_id, (
        "BGP router id unexpected, expected: {}, actual: {}. "
    ).format(expected_bgp_router_id, match.group(1)))

    # Verify BGP sessions are established
    run_bgp_facts(duthost, enum_asic_index)

    # Verify from peer device side to check
    if neighbor_type not in ["sonic", "eos"]:
        logger.warning("Unsupport neighbor type for neighbor bgp check: {}".format(neighbor_type))
    local_ip_map = {}
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for _, item in cfg_facts.get("BGP_NEIGHBOR", {}).items():
        addr_char = ":" if is_v6_topo else "."
        if addr_char in item["local_addr"]:
            local_ip_map[item["name"]] = item["local_addr"]

    for neighbor_name, nbrhost in nbrhosts.items():
        pytest_assert(neighbor_name in local_ip_map, (
            "Cannot find local ip for {}. "
            "Local IP map: {}"
        ).format(neighbor_name, local_ip_map))

        if neighbor_type == "sonic":
            if is_v6_topo:
                cmd = "show ipv6 bgp neighbors {}".format(local_ip_map[neighbor_name])
            else:
                cmd = "show ip bgp neighbors {}".format(local_ip_map[neighbor_name])
        elif neighbor_type == "eos":
            if is_v6_topo:
                cmd = "/usr/bin/Cli -c \"show ipv6 bgp peers {}\"".format(local_ip_map[neighbor_name])
            else:
                cmd = "/usr/bin/Cli -c \"show ip bgp neighbors {}\"".format(local_ip_map[neighbor_name])
        output = nbrhost["host"].shell(cmd, module_ignore_errors=True)['stdout']
        pattern = r"BGP version 4, remote router ID (\d+\.\d+\.\d+\.\d+)"
        match = re.search(pattern, output)
        pytest_assert(match, (
            "Cannot get remote BGP router id from [{}]. "
        ).format(output))

        pytest_assert(match.group(1) == expected_bgp_router_id, (
            "BGP router id is unexpected, local: {}, fetch from remote: {}. "
        ).format(expected_bgp_router_id, match.group(1)))


@pytest.fixture()
def loopback_ip(duthosts, enum_frontend_dut_hostname):
    duthost = duthosts[enum_frontend_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    loopback_ip = None
    loopback_table = cfg_facts.get("LOOPBACK_INTERFACE", {})
    for key in loopback_table.get("Loopback0", {}).keys():
        if "." in key:
            loopback_ip = key.split("/")[0]
    pytest_require(loopback_ip is not None, "Cannot get IPv4 address of Loopback0")
    yield loopback_ip


@pytest.fixture()
def loopback_ipv6(duthosts, enum_frontend_dut_hostname):
    duthost = duthosts[enum_frontend_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    loopback_ip = None
    loopback_table = cfg_facts.get("LOOPBACK_INTERFACE", {})
    for key in loopback_table.get("Loopback0", {}).keys():
        if ":" in key:
            loopback_ip = key.split("/")[0]
    pytest_require(loopback_ip is not None, "Cannot get IPv6 address of Loopback0")
    # If bgp_adv_lo_prefix_as_128 is false, a /64 prefix of IPv6 loopback addr is used
    # i.e. fc00:1::32/128 -> fc00:1::/64
    dev_meta = cfg_facts.get('DEVICE_METADATA', {})
    bgp_adv_lo_prefix_as_128 = "false"
    if "localhost" in dev_meta and "bgp_adv_lo_prefix_as_128" in dev_meta["localhost"]:
        bgp_adv_lo_prefix_as_128 = dev_meta["localhost"]["bgp_adv_lo_prefix_as_128"]
    if bgp_adv_lo_prefix_as_128.lower() != "true":
        loopback_ip = str(ip_interface(loopback_ip + "/64").network.network_address)
    yield loopback_ip


def restart_bgp(duthost, tbinfo):
    duthost.reset_service("bgp")
    duthost.restart_service("bgp")
    pytest_assert(wait_until(100, 10, 10, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")
    pytest_assert(wait_until(100, 10, 10, duthost.check_default_route,
                             ipv4=not is_ipv6_only_topology(tbinfo)), "Default route not ready")
    # After restarting bgp, add time wait for bgp_facts to fetch latest status
    time.sleep(20)


@pytest.fixture()
def router_id_setup_and_teardown(duthosts, enum_frontend_dut_hostname, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    duthost.shell("sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" \"bgp_router_id\" \"{}\""
                  .format(CUSTOMIZED_BGP_ROUTER_ID), module_ignore_errors=True)
    restart_bgp(duthost, tbinfo)

    yield

    duthost.shell("sonic-db-cli CONFIG_DB hdel \"DEVICE_METADATA|localhost\" \"bgp_router_id\"",
                  module_ignore_errors=True)
    restart_bgp(duthost, tbinfo)


@pytest.fixture(scope="function")
def router_id_loopback_setup_and_teardown(duthosts, enum_frontend_dut_hostname, loopback_ip, tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    duthost.shell("sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" \"bgp_router_id\" \"{}\""
                  .format(CUSTOMIZED_BGP_ROUTER_ID), module_ignore_errors=True)
    duthost.shell("sonic-db-cli CONFIG_DB del \"LOOPBACK_INTERFACE|Loopback0|{}/32\"".format(loopback_ip))
    restart_bgp(duthost, tbinfo)

    yield

    duthost.shell("sonic-db-cli CONFIG_DB hdel \"DEVICE_METADATA|localhost\" \"bgp_router_id\"",
                  module_ignore_errors=True)
    duthost.shell("sonic-db-cli CONFIG_DB hset \"LOOPBACK_INTERFACE|Loopback0|{}/32\" \"NULL\" \"NULL\""
                  .format(loopback_ip), module_ignore_errors=True)
    restart_bgp(duthost, tbinfo)


def test_bgp_router_id_default(duthosts, enum_frontend_dut_hostname, enum_asic_index, nbrhosts, request, loopback_ip,
                               tbinfo):
    # Test in default config, the BGP router id should be aligned with Loopback IPv4 address
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_asic_index, duthost, loopback_ip, neighbor_type, nbrhosts, tbinfo)


def test_bgp_router_id_set(duthosts, enum_frontend_dut_hostname, enum_asic_index, nbrhosts, request, loopback_ip,
                           router_id_setup_and_teardown, tbinfo):
    # Test in the scenario that bgp_router_id and Loopback IPv4 address both exist in CONFIG_DB, the actual BGP router
    # ID should be aligned with bgp_router_id in CONFIG_DB. And the Loopback IPv4 address should be advertised to BGP
    # neighbor
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
    # Verify Loopback ip has been advertised to neighbor
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for remote_ip in cfg_facts.get("BGP_NEIGHBOR", {}).keys():
        if "." not in remote_ip or "FT2" in cfg_facts["BGP_NEIGHBOR"][remote_ip]["name"]:
            continue
        output = duthost.shell("show ip bgp neighbor {} advertised-routes| grep {}".format(remote_ip, loopback_ip),
                               module_ignore_errors=True)
        pytest_assert(output["rc"] == 0, (
            "Failed to check whether Loopback ipv4 address has been advertised. "
            "Return code: {} "
            "Output: {}"
        ).format(output["rc"], output))

        pytest_assert(loopback_ip in output["stdout"], (
            "Router advertised unexpected. "
            "Expected loopback IP: {} "
            "Actual output: {}"
        ).format(loopback_ip, output["stdout"]))


def test_bgp_router_id_set_ipv6(duthosts, enum_frontend_dut_hostname, enum_asic_index, nbrhosts, request, loopback_ipv6,
                                router_id_setup_and_teardown, tbinfo):
    # Test in the scenario that bgp_router_id and Loopback IPv6 address both exist in CONFIG_DB, the actual BGP router
    # ID should be aligned with bgp_router_id in CONFIG_DB. And the Loopback IPv6 address should be advertised to BGP
    # neighbor
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
    # Verify Loopback ip has been advertised to neighbor
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for remote_ip in cfg_facts.get("BGP_NEIGHBOR", {}).keys():
        if ":" not in remote_ip or "FT2" in cfg_facts["BGP_NEIGHBOR"][remote_ip]["name"]:
            continue
        output = duthost.shell("show ipv6 bgp neighbor {} advertised-routes| grep {}".format(remote_ip, loopback_ipv6),
                               module_ignore_errors=True)
        pytest_assert(output["rc"] == 0, (
            "Failed to check whether Loopback ipv6 address has been advertised. "
            "Return code: {} "
            "Output: {}"
        ).format(output["rc"], output))

        pytest_assert(loopback_ipv6 in output["stdout"], (
            "Router advertised unexpected. "
            "Expected loopback IP: {} "
            "Actual output: {}"
        ).format(loopback_ipv6, output["stdout"]))


def test_bgp_router_id_set_without_loopback(duthosts, enum_frontend_dut_hostname, enum_asic_index, nbrhosts, request,
                                            router_id_loopback_setup_and_teardown, tbinfo):
    # Test in the scenario that bgp_router_id specified but Loopback IPv4 address not set, BGP could work well and the
    # actual BGP router id should be aligned with CONFIG_DB
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
