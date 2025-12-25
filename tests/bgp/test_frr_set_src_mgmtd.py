"""Ensure mgmtd FRR replays preserve default-route set-src even with large configs."""

import ipaddress
import json
import logging
import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.platform.processes_utils import wait_critical_processes


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0', 't1')
]


BLOAT_CONFIG_TMPFILE = "/tmp/mgmtd_set_src_bloat_routes.json"
BLOAT_STATIC_ROUTE_COUNT = 512
ITERATION_LEVEL_MAP = {
    'debug': 1,
    'basic': 1,
    'confident': 2,
    'thorough': 3
}
logger = logging.getLogger(__name__)


def _get_asic_hosts(duthost):
    """
    Provide a normalized list of ASIC hosts to iterate over.
    """
    if duthost.is_multi_asic:
        return [duthost.asic_instance(asic_index) for asic_index in duthost.get_frontend_asic_ids()]
    return [duthost.asic_instance()]


def _extract_loopback_ips(asichost, duthost):
    """
    Return the IPv4/IPv6 addresses configured on Loopback0 for the supplied ASIC.
    """
    config_facts = asichost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    loopbacks = config_facts.get("LOOPBACK_INTERFACE", {})
    pytest_assert("Loopback0" in loopbacks, "Loopback0 missing from config facts")

    lo_ipv4 = None
    lo_ipv6 = None

    for ip_str in loopbacks["Loopback0"]:
        loop_ip = ipaddress.ip_interface(ip_str)
        if loop_ip.version == 4:
            lo_ipv4 = loop_ip
        elif loop_ip.version == 6:
            lo_ipv6 = loop_ip

    pytest_assert(lo_ipv4, "Failed to locate IPv4 Loopback0 address")
    pytest_assert(lo_ipv6, "Failed to locate IPv6 Loopback0 address")

    return lo_ipv4, lo_ipv6


def _verify_default_route_set_src(asichost, lo_ipv4, lo_ipv6):
    """
    Ensure both IPv4 and IPv6 default routes carry the expected source address.
    """
    ipv4_default = asichost.get_ip_route_info(ipaddress.ip_network("0.0.0.0/0"))
    pytest_assert(ipv4_default.get("set_src"), "IPv4 default route missing set_src attribute")
    pytest_assert(
        ipv4_default["set_src"] == lo_ipv4.ip,
        "IPv4 default route set_src {} does not match Loopback0 {}".format(ipv4_default['set_src'], lo_ipv4.ip)
    )

    ipv6_default = asichost.get_ip_route_info(ipaddress.ip_network("::/0"))
    pytest_assert(ipv6_default.get("set_src"), "IPv6 default route missing set_src attribute")
    pytest_assert(
        ipv6_default["set_src"] == lo_ipv6.ip,
        "IPv6 default route set_src {} does not match Loopback0 {}".format(ipv6_default['set_src'], lo_ipv6.ip)
    )


def _verify_route_maps_in_running_config(asichost, lo_ipv4, lo_ipv6):
    """
    Confirm FRR running-config retains the route-maps that install the Loopback source-ip.
    """
    running_cfg = asichost.run_vtysh("-c 'show running-config'")["stdout"]
    pytest_assert("route-map RM_SET_SRC permit 10" in running_cfg, "RM_SET_SRC missing from running-config")
    pytest_assert(
        "set src {}".format(lo_ipv4.ip) in running_cfg,
        "RM_SET_SRC missing the Loopback0 IPv4 address {}".format(lo_ipv4.ip)
    )
    pytest_assert("route-map RM_SET_SRC6 permit 10" in running_cfg, "RM_SET_SRC6 missing from running-config")
    pytest_assert(
        "set src {}".format(lo_ipv6.ip) in running_cfg,
        "RM_SET_SRC6 missing the Loopback0 IPv6 address {}".format(lo_ipv6.ip)
    )


def _verify_set_src_all_asics(duthost):
    """Run the default-route checks on every frontend ASIC."""
    for asichost in _get_asic_hosts(duthost):
        lo_ipv4, lo_ipv6 = _extract_loopback_ips(asichost, duthost)
        _verify_default_route_set_src(asichost, lo_ipv4, lo_ipv6)
        _verify_route_maps_in_running_config(asichost, lo_ipv4, lo_ipv6)


def _find_static_route_anchor(duthost):
    """Find an IPv4 routed interface and peer IP to use as static-route nexthop."""
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    interface_tables = [
        config_facts.get("INTERFACE", {}),
        config_facts.get("PORTCHANNEL_INTERFACE", {})
    ]

    for table in interface_tables:
        for ifname, addr_map in table.items():
            for ip_str in addr_map.keys():
                ip_intf = ipaddress.ip_interface(ip_str)
                if ip_intf.version != 4:
                    continue
                peer_ip = _get_remote_ip(ip_intf)
                if peer_ip:
                    return ifname, str(peer_ip)

    pytest_require(False, "No IPv4 routed interface found to generate static-route config bloat")


def _get_remote_ip(ip_intf):
    """
    Return the other host address within the interface network.
    """
    try:
        for candidate in ip_intf.network.hosts():
            if candidate != ip_intf.ip:
                return candidate
    except StopIteration:
        return None

    return None


def _generate_bloat_prefixes(count):
    """Produce unique doc prefixes (/32) to avoid conflicts with real routes."""
    base_network = ipaddress.ip_network("198.18.0.0/15")
    prefixes = []
    hosts = base_network.hosts()

    while len(prefixes) < count:
        try:
            prefixes.append("{}/32".format(next(hosts)))
        except StopIteration:
            pytest.fail("Insufficient addresses to generate {} prefixes".format(count))

    return prefixes


def _add_static_routes_for_bloat(duthost, interface, nexthop, count=BLOAT_STATIC_ROUTE_COUNT):
    """Write a batch of static routes into CONFIG_DB via sonic-cfggen."""
    prefixes = _generate_bloat_prefixes(count)
    payload = {"STATIC_ROUTE": {}}

    for prefix in prefixes:
        payload["STATIC_ROUTE"]["default|{}".format(prefix)] = {
            "nexthop": nexthop,
            "ifname": interface
        }

    duthost.copy(content=json.dumps(payload, indent=2), dest=BLOAT_CONFIG_TMPFILE)
    duthost.shell("sudo sonic-cfggen -j {} --write-to-db".format(BLOAT_CONFIG_TMPFILE))
    return prefixes


def _remove_static_routes_for_bloat(duthost, prefixes):
    """Remove the injected static routes and temp file."""
    for prefix in prefixes:
        key = "STATIC_ROUTE|default|{}".format(prefix)
        duthost.shell(
            "sonic-db-cli CONFIG_DB DEL \"{}\"".format(key),
            module_ignore_errors=True
        )

    duthost.shell("rm -f {}".format(BLOAT_CONFIG_TMPFILE), module_ignore_errors=True)


def test_mgmtd_preserves_default_route_set_src(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        get_function_completeness_level):
    """
    Regress the mgmtd replay bug by forcing a config reload and ensuring FRR keeps the set src route-maps.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    pytest_require(
        duthost.get_frr_mgmt_framework_config(),
        "Test requires FRR mgmt-framework (mgmtd) mode to be enabled"
    )

    normalized_level = get_function_completeness_level if get_function_completeness_level else 'debug'
    iterations = ITERATION_LEVEL_MAP.get(normalized_level, ITERATION_LEVEL_MAP['debug'])

    logger.info("Running mgmtd set-src regression for %s iteration(s)", iterations)

    for iteration in range(1, iterations + 1):
        logger.info("Iteration %s/%s: issuing config reload", iteration, iterations)
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        wait_critical_processes(duthost)

        _verify_set_src_all_asics(duthost)


def test_mgmtd_preserves_default_route_set_src_with_large_config(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        get_function_completeness_level):
    """
    Inflate the configuration (static routes) before reload to mimic a long FRR config replay.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    pytest_require(
        duthost.get_frr_mgmt_framework_config(),
        "Test requires FRR mgmt-framework (mgmtd) mode to be enabled"
    )

    interface, nexthop = _find_static_route_anchor(duthost)
    checkpoint_name = "set_src_bloat_cp"
    prefixes = []
    checkpoint_created = False

    create_checkpoint(duthost, checkpoint_name)
    checkpoint_created = True

    try:
        prefixes = _add_static_routes_for_bloat(duthost, interface, nexthop)
        logger.info("Injected %d static routes via interface %s", len(prefixes), interface)

        duthost.shell("sudo config save -y")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        wait_critical_processes(duthost)

        _verify_set_src_all_asics(duthost)
    finally:
        if prefixes:
            _remove_static_routes_for_bloat(duthost, prefixes)

        if checkpoint_created:
            rollback_or_reload(duthost, checkpoint_name)
            delete_checkpoint(duthost, checkpoint_name)
            duthost.shell("sudo config save -y")
