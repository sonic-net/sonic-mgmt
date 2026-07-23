import pytest
import logging
import re

from tests.common.fixtures.duthost_utils import wait_bgp_sessions
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.helpers.bgp import (
    get_asic_config_facts,
    get_db_cli_prefix,
    get_vtysh_cmd_for_asic,
)
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv6_only_topology
from tests.common.utilities import get_host_visible_vars
from ipaddress import ip_interface


pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

CUSTOMIZED_BGP_ROUTER_ID = "8.8.8.8"
VTYSH_SHOW_CMD_TIMEOUT_SEC = 60
VTYSH_SHOW_CMD_KILL_GRACE_SEC = 5


def run_config_db_cmd(duthost, enum_asic_index, cmd, module_ignore_errors=True):
    duthost.shell("{} CONFIG_DB {}".format(get_db_cli_prefix(duthost, enum_asic_index), cmd),
                  module_ignore_errors=module_ignore_errors)


def verify_bgp_peer(neighbor_type, nbrhost, localip, expected_bgp_router_id, is_v6_topo, vrf="default"):
    if neighbor_type in ("sonic", "csonic"):
        if is_v6_topo:
            cmd = "show ipv6 bgp neighbors {}".format(localip)
        else:
            cmd = "show ip bgp neighbors {}".format(localip)
    elif neighbor_type == "eos":
        if is_v6_topo:
            cmd = "/usr/bin/Cli -c \"show ipv6 bgp peers {} vrf {}\"".format(localip, vrf)
        else:
            cmd = "/usr/bin/Cli -c \"show ip bgp neighbors {} vrf {}\"".format(localip, vrf)
    output = nbrhost["host"].shell(cmd, module_ignore_errors=True)["stdout"]
    pattern = r"BGP version 4, remote router ID (\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, output)
    pytest_assert(match, "Cannot get remote BGP router id from [{}]".format(output))
    pytest_assert(match.group(1) == expected_bgp_router_id,
                  "BGP router id is unexpected, local: {}, fetch from remote:{}".format(
                      expected_bgp_router_id, match.group(1)))


def verify_bgp(enum_asic_index, duthost, expected_bgp_router_id, neighbor_type, nbrhosts, tbinfo):
    is_v6_topo = is_ipv6_only_topology(tbinfo)
    vtysh_cmd = "vtysh -c \"show ipv6 bgp summary\"" if is_v6_topo else "vtysh -c \"show ip bgp summary\""
    vtysh_cmd = get_vtysh_cmd_for_asic(duthost, enum_asic_index, vtysh_cmd)
    bounded_cmd = "timeout -k {} {} {}".format(
        VTYSH_SHOW_CMD_KILL_GRACE_SEC, VTYSH_SHOW_CMD_TIMEOUT_SEC, vtysh_cmd)
    res = duthost.shell(bounded_cmd, module_ignore_errors=True)
    rc = res.get("rc")
    output = res.get("stdout", "") or ""
    pytest_assert(rc == 0, (
        "Failed to run '{}' (rc={}). stderr: {}; stdout: {}"
    ).format(vtysh_cmd, rc, res.get("stderr", ""), output[:200]))

    # Verify router id from DUT itself
    pattern = r"BGP router identifier (\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, output)
    pytest_assert(match, (
        "Cannot get actual BGP router id from [{}]. "
    ).format(output))

    pytest_assert(match.group(1) == expected_bgp_router_id, (
        "BGP router id unexpected, expected: {}, actual: {}. "
    ).format(expected_bgp_router_id, match.group(1)))

    cfg_facts = get_asic_config_facts(duthost, enum_asic_index)
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    addr_char = ":" if is_v6_topo else "."

    local_ip_map = {}
    remote_ip_map = {}
    for remote_ip, item in cfg_facts.get("BGP_NEIGHBOR", {}).items():
        if addr_char not in item["local_addr"] or item["name"] not in nbrhosts:
            continue
        local_ip_map[item["name"]] = item["local_addr"]
        remote_ip_map[remote_ip] = item

    # Verify BGP sessions are established for peers checked by this test.
    for remote_ip in remote_ip_map:
        pytest_assert(remote_ip in bgp_facts['bgp_neighbors'], (
            "Cannot find BGP facts for neighbor {}. "
            "BGP facts neighbors: {}"
        ).format(remote_ip, bgp_facts['bgp_neighbors'].keys()))
        pytest_assert(bgp_facts['bgp_neighbors'][remote_ip]['state'] == "established", (
            "BGP session not established for neighbor {}. Expected 'established', got '{}'."
        ).format(remote_ip, bgp_facts['bgp_neighbors'][remote_ip]['state']))

    # Verify from peer device side to check
    if neighbor_type not in ["sonic", "csonic", "eos"]:
        logger.warning("Unsupport neighbor type for neighbor bgp check: {}".format(neighbor_type))

    verified_neighbors = 0
    for neighbor_name, localip in local_ip_map.items():
        if neighbor_name not in nbrhosts:
            continue
        nbrhost = nbrhosts[neighbor_name]
        vrf = neighbor_name if nbrhost.get("is_multi_vrf_peer", False) else "default"
        verify_bgp_peer(neighbor_type, nbrhost, localip, expected_bgp_router_id, is_v6_topo, vrf=vrf)
        verified_neighbors += 1

    if verified_neighbors == 0:
        pytest.skip(
            "No external BGP neighbor to verify on ASIC {}. Local IP map: {}".format(
                enum_asic_index, local_ip_map
            )
        )


@pytest.fixture()
def loopback_ip(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    cfg_facts = get_asic_config_facts(duthost, enum_frontend_asic_index)
    loopback_ip = None
    loopback_table = cfg_facts.get("LOOPBACK_INTERFACE", {})
    for key in loopback_table.get("Loopback0", {}).keys():
        if "." in key:
            loopback_ip = key.split("/")[0]
    pytest_require(loopback_ip is not None, "Cannot get IPv4 address of Loopback0")
    yield loopback_ip


@pytest.fixture()
def default_bgp_router_id(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, loopback_ip):
    duthost = duthosts[enum_frontend_dut_hostname]
    cfg_facts = get_asic_config_facts(duthost, enum_frontend_asic_index)
    dev_meta = cfg_facts.get('DEVICE_METADATA', {}).get('localhost', {})

    if dev_meta.get('switch_type') in ['voq', 'chassis-packet']:
        host_vars = get_host_visible_vars(duthost.host.options['inventory'], duthost.hostname)
        loopback4096_ips = host_vars.get('loopback4096_ip', [])
        if len(loopback4096_ips) > enum_frontend_asic_index:
            yield loopback4096_ips[enum_frontend_asic_index].split("/")[0]
            return

    yield loopback_ip


@pytest.fixture()
def loopback_ipv6(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    cfg_facts = get_asic_config_facts(duthost, enum_frontend_asic_index)
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
    # wait_bgp_sessions polls per-ASIC BGP state
    # (multi-ASIC aware, default 120s, auto-extended to 900s on modular chassis) so verification
    # only runs once sessions have actually re-established.
    wait_bgp_sessions(duthost)


def is_loopback_advertised_to_neighbor(duthost, asic_index, show_cmd, remote_ip, loopback_ip):
    """Return True if loopback_ip is advertised as a route (prefix) to remote_ip.

    Runs the advertised-routes command directly (bounded by `timeout` like the other vtysh calls in
    this file, since a stuck vtysh would otherwise hang the test) and asserts it succeeded, so a
    vtysh/command failure (e.g. neighbor not found) surfaces as an error instead of being silently
    read as "not advertised". Then checks in Python for the prefix followed by '/' (e.g. '10.1.0.1/').
    The trailing '/' means it does not false-match:
      - the 'local router ID is <loopback_ip>' header line, which contains loopback_ip when the DUT
        router-id equals its loopback IP (the default state, before bgp_router_id is customized), or
      - a longer prefix that merely starts with loopback_ip (e.g. loopback '10.1.0.1' vs an advertised
        '10.1.0.10/32', or an IPv6 '/64' network vs its '/128' host routes).
    """
    vtysh_cmd = get_vtysh_cmd_for_asic(
        duthost,
        asic_index,
        "vtysh -c \"{} {} advertised-routes\"".format(show_cmd, remote_ip)
    )
    bounded_cmd = "timeout -k {} {} {}".format(
        VTYSH_SHOW_CMD_KILL_GRACE_SEC, VTYSH_SHOW_CMD_TIMEOUT_SEC, vtysh_cmd)
    res = duthost.shell(bounded_cmd, module_ignore_errors=True)
    rc = res.get("rc")
    output = res.get("stdout", "") or ""
    pytest_assert(rc == 0, (
        "Failed to run '{}' for neighbor {} (rc={}). stderr: {}; stdout: {}"
    ).format(vtysh_cmd, remote_ip, rc, (res.get("stderr", "") or "")[:200], output[:200]))
    return "{}/".format(loopback_ip) in output


def get_neighbor_loopback_advertised_map(duthost, asic_index, cfg_facts, loopback_ip, is_ipv6):
    """Return a dict {neighbor_ip: bool} for every BGP neighbor of the matching address family,
    where the value is whether loopback_ip is currently advertised to that neighbor.

    Capturing both the advertised and not-advertised neighbors lets the test assert the exact same
    advertisement map after changing bgp_router_id, without hardcoding which neighbor roles are or
    are not expected to receive the loopback (e.g. FabricSpineRouter/FT2 peers that a route-map denies).
    """
    show_cmd = "show ipv6 bgp neighbor" if is_ipv6 else "show ip bgp neighbor"
    addr_char = ":" if is_ipv6 else "."
    advertised_map = {}
    for remote_ip in cfg_facts.get("BGP_NEIGHBOR", {}).keys():
        if addr_char not in remote_ip:
            continue
        advertised_map[remote_ip] = is_loopback_advertised_to_neighbor(
            duthost, asic_index, show_cmd, remote_ip, loopback_ip)
    return advertised_map


@pytest.fixture()
def router_id_setup_and_teardown_ipv4(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, loopback_ip,
                                      tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    # Before customizing bgp_router_id, record for every neighbor whether it is currently advertised the
    # loopback. The test asserts this exact advertised/not-advertised map is unchanged afterwards, so it
    # stays correct on topologies where some peers are intentionally not advertised the loopback (e.g.
    # FabricSpineRouter/FT2 peers) without hardcoding names.
    cfg_facts = get_asic_config_facts(duthost, enum_frontend_asic_index)
    baseline_advertised_map = get_neighbor_loopback_advertised_map(
        duthost, enum_frontend_asic_index, cfg_facts, loopback_ip, False)
    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hset \"DEVICE_METADATA|localhost\" \"bgp_router_id\" \"{}\""
                      .format(CUSTOMIZED_BGP_ROUTER_ID))
    restart_bgp(duthost, tbinfo)

    yield baseline_advertised_map

    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hdel \"DEVICE_METADATA|localhost\" \"bgp_router_id\"")
    restart_bgp(duthost, tbinfo)


@pytest.fixture()
def router_id_setup_and_teardown_ipv6(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, loopback_ipv6,
                                      tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    # Before customizing bgp_router_id, record for every neighbor whether it is currently advertised the
    # loopback. The test asserts this exact advertised/not-advertised map is unchanged afterwards, so it
    # stays correct on topologies where some peers are intentionally not advertised the loopback (e.g.
    # FabricSpineRouter/FT2 peers) without hardcoding names.
    cfg_facts = get_asic_config_facts(duthost, enum_frontend_asic_index)
    baseline_advertised_map = get_neighbor_loopback_advertised_map(
        duthost, enum_frontend_asic_index, cfg_facts, loopback_ipv6, True)
    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hset \"DEVICE_METADATA|localhost\" \"bgp_router_id\" \"{}\""
                      .format(CUSTOMIZED_BGP_ROUTER_ID))
    restart_bgp(duthost, tbinfo)

    yield baseline_advertised_map

    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hdel \"DEVICE_METADATA|localhost\" \"bgp_router_id\"")
    restart_bgp(duthost, tbinfo)


@pytest.fixture(scope="function")
def router_id_loopback_setup_and_teardown(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, loopback_ip,
                                          tbinfo):
    duthost = duthosts[enum_frontend_dut_hostname]
    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hset \"DEVICE_METADATA|localhost\" \"bgp_router_id\" \"{}\""
                      .format(CUSTOMIZED_BGP_ROUTER_ID))
    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "del \"LOOPBACK_INTERFACE|Loopback0|{}/32\"".format(loopback_ip),
                      module_ignore_errors=False)
    restart_bgp(duthost, tbinfo)

    yield

    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hdel \"DEVICE_METADATA|localhost\" \"bgp_router_id\"")
    run_config_db_cmd(duthost, enum_frontend_asic_index,
                      "hset \"LOOPBACK_INTERFACE|Loopback0|{}/32\" \"NULL\" \"NULL\""
                      .format(loopback_ip))
    restart_bgp(duthost, tbinfo)


def test_bgp_router_id_default(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, nbrhosts, request,
                               default_bgp_router_id, tbinfo):
    # Test in default config, the BGP router id should be aligned with Loopback IPv4 address
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_frontend_asic_index, duthost, default_bgp_router_id, neighbor_type, nbrhosts, tbinfo)


# BGP restart in setup/teardown can emit transient loganalyzer noise.
@pytest.mark.disable_loganalyzer
def test_bgp_router_id_set(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, nbrhosts, request,
                           loopback_ip, router_id_setup_and_teardown_ipv4, tbinfo):
    # Test in the scenario that bgp_router_id and Loopback IPv4 address both exist in CONFIG_DB, the actual BGP router
    # ID should be aligned with bgp_router_id in CONFIG_DB. And the Loopback IPv4 address should be advertised to BGP
    # neighbor
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_frontend_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
    # Changing bgp_router_id must not change which neighbors the loopback is advertised to. Compare the
    # current advertised/not-advertised state per neighbor against the baseline captured before the change.
    baseline_advertised_map = router_id_setup_and_teardown_ipv4
    if not baseline_advertised_map:
        pytest.skip("No IPv4 BGP neighbor found to check Loopback {} advertisement.".format(loopback_ip))
    for remote_ip, was_advertised in baseline_advertised_map.items():
        is_advertised = is_loopback_advertised_to_neighbor(
            duthost, enum_frontend_asic_index, "show ip bgp neighbor", remote_ip, loopback_ip)
        pytest_assert(
            is_advertised == was_advertised,
            "Loopback IPv4 {} advertisement to neighbor {} changed after setting bgp_router_id: "
            "was {}, now {}.".format(
                loopback_ip, remote_ip,
                "advertised" if was_advertised else "not advertised",
                "advertised" if is_advertised else "not advertised"))


@pytest.mark.disable_loganalyzer
def test_bgp_router_id_set_ipv6(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, nbrhosts, request,
                                loopback_ipv6, router_id_setup_and_teardown_ipv6, tbinfo):
    # Test in the scenario that bgp_router_id and Loopback IPv6 address both exist in CONFIG_DB, the actual BGP router
    # ID should be aligned with bgp_router_id in CONFIG_DB. And the Loopback IPv6 address should be advertised to BGP
    # neighbor
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_frontend_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
    # Changing bgp_router_id must not change which neighbors the loopback is advertised to. Compare the
    # current advertised/not-advertised state per neighbor against the baseline captured before the change.
    baseline_advertised_map = router_id_setup_and_teardown_ipv6
    if not baseline_advertised_map:
        pytest.skip("No IPv6 BGP neighbor found to check Loopback {} advertisement.".format(loopback_ipv6))
    for remote_ip, was_advertised in baseline_advertised_map.items():
        is_advertised = is_loopback_advertised_to_neighbor(
            duthost, enum_frontend_asic_index, "show ipv6 bgp neighbor", remote_ip, loopback_ipv6)
        pytest_assert(
            is_advertised == was_advertised,
            "Loopback IPv6 {} advertisement to neighbor {} changed after setting bgp_router_id: "
            "was {}, now {}.".format(
                loopback_ipv6, remote_ip,
                "advertised" if was_advertised else "not advertised",
                "advertised" if is_advertised else "not advertised"))


@pytest.mark.disable_loganalyzer
def test_bgp_router_id_set_without_loopback(duthosts, enum_frontend_dut_hostname, enum_frontend_asic_index, nbrhosts,
                                            request, router_id_loopback_setup_and_teardown, tbinfo):
    # Test in the scenario that bgp_router_id specified but Loopback IPv4 address not set, BGP could work well and the
    # actual BGP router id should be aligned with CONFIG_DB
    duthost = duthosts[enum_frontend_dut_hostname]
    neighbor_type = request.config.getoption("neighbor_type")
    verify_bgp(enum_frontend_asic_index, duthost, CUSTOMIZED_BGP_ROUTER_ID, neighbor_type, nbrhosts, tbinfo)
