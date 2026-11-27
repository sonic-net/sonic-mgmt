"""Explicit IS-IS acceptance on the community Force10 seven-node topology.

Run this module by its file path; see README.md for the image prerequisites.
"""

import ipaddress
import json
import logging
import re
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("force10-7nodes")]

NODE_NETS = {
    "P1": "49.0001.0000.0000.0001.00",
    "PE1": "49.0001.0000.0000.0010.00",
    "PE2": "49.0001.0000.0000.0020.00",
    "PE3": "49.0001.0000.0000.0030.00",
    "P2": "49.0001.0000.0000.0002.00",
    "P3": "49.0001.0000.0000.0003.00",
    "P4": "49.0001.0000.0000.0004.00",
}

# These interfaces follow VM_LINKs, OVS_LINKs, and P1 links in
# ansible/vars/topo_force10-7nodes.yml and its 7nodes_force10 ConfigDB profiles.
NODE_INTERFACES = {
    "P1": ["Ethernet112", "Ethernet116", "Ethernet124", "Ethernet64", "Ethernet68"],
    "PE1": ["Ethernet0", "Ethernet4"],
    "PE2": ["Ethernet0", "Ethernet8"],
    "PE3": ["Ethernet4", "Ethernet12"],
    "P2": ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"],
    "P3": ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12", "Ethernet16"],
    "P4": ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"],
}

EXPECTED_NEIGHBORS = {
    "P1": 5,
    "PE1": 2,
    "PE2": 2,
    "PE3": 2,
    "P2": 4,
    "P3": 5,
    "P4": 4,
}

INSTANCE = "FABRIC"
LINKS = [
    ("P1", "Ethernet112", "PE1", "Ethernet0"),
    ("P1", "Ethernet116", "PE2", "Ethernet0"),
    ("P1", "Ethernet124", "P3", "Ethernet0"),
    ("P1", "Ethernet64", "P2", "Ethernet0"),
    ("P1", "Ethernet68", "P4", "Ethernet0"),
    ("PE1", "Ethernet4", "P3", "Ethernet4"),
    ("PE2", "Ethernet8", "P3", "Ethernet8"),
    ("P3", "Ethernet12", "P2", "Ethernet4"),
    ("P3", "Ethernet16", "P4", "Ethernet4"),
    ("P2", "Ethernet8", "P4", "Ethernet8"),
    ("P2", "Ethernet12", "PE3", "Ethernet4"),
    ("P4", "Ethernet12", "PE3", "Ethernet12"),
]


def _run(node, command, check=True):
    result = node.shell(command, module_ignore_errors=True)
    if check:
        pytest_assert(result.get("rc", 1) == 0,
                      "Command failed on {}: {}\n{}".format(
                          getattr(node, "hostname", "node"), command, result))
    logger.info("%s: %s\n%s", getattr(node, "hostname", "node"), command, result)
    return result.get("stdout", "").strip()


def _config_value(node, table_key, field):
    return _run(node, "sudo sonic-db-cli CONFIG_DB HGET '{}' {}".format(table_key, field))


def _configure_global(node, net):
    _run(node, "sudo config isis add {}".format(INSTANCE))
    _run(node, "sudo config isis net {} {}".format(INSTANCE, net))
    _run(node, "sudo config isis level {} level-2".format(INSTANCE))
    _run(node, "sudo config isis lsp-mtu {} 1400".format(INSTANCE))


def _configure_interface(node, interface):
    _run(node, "sudo config interface isis ipv4 {} enable --instance {}".format(interface, INSTANCE))
    _run(node, "sudo config interface isis network-type {} p2p".format(interface))


def _configure_interfaces(node, interfaces):
    for interface in interfaces:
        _configure_interface(node, interface)
    _run(node, "sudo config interface isis ipv4 Loopback0 enable --instance {}".format(INSTANCE))
    _run(node, "sudo config interface isis passive Loopback0 enable")


def _up_neighbor_count(node):
    result = node.shell("sudo show isis neighbor", module_ignore_errors=True)
    # A failed show command must never look like a successful withdrawal.
    if result.get("rc", 1) != 0:
        logger.warning("Failed to read IS-IS neighbors: %s", result)
        return -1
    output = result.get("stdout", "")
    return sum(1 for line in output.splitlines() if re.search(r"\bUp\b", line, re.IGNORECASE))


def _fabric_neighbors_up(nodes):
    return all(_up_neighbor_count(nodes[name]) >= expected
               for name, expected in EXPECTED_NEIGHBORS.items())


def _neighbor_count_is(node, count):
    return _up_neighbor_count(node) == count


def _route_is_installed(node, prefix, present=True):
    family = "ipv6" if ":" in prefix else "ip"
    # Read the exact prefix from Zebra, distinguishing absence from query failure.
    data = json.loads(_run(node, "sudo vtysh -c 'show {} route {} json'".format(family, prefix)))
    installed = any(route.get("protocol") == "isis" and route.get("selected", False)
                    for route in data.get(prefix, []))
    return installed == present


def _running_commands(node, context):
    output = _run(node, "sudo vtysh -c 'show running-config isisd'")
    block = re.search(r"(?m)^{}\n((?:[ \t].*(?:\n|$))*)".format(re.escape(context)), output)
    return None if block is None else {line.strip() for line in block.group(1).splitlines()}


def _commands_match(node, context, required=(), absent=()):
    commands = _running_commands(node, context)
    if commands is None:
        return bool(absent) and not required
    return set(required) <= commands and not set(absent) & commands


def _await_commands(node, context, required=(), absent=()):
    pytest_assert(wait_until(45, 2, 0, _commands_match, node, context, required, absent),
                  "Unexpected installed commands in {}: {}".format(context, _running_commands(node, context)))


def _config_snapshot(node):
    return json.loads(_run(node, "sudo sonic-cfggen -d --print-data"))


def _bgp_config(node):
    return {key: value for key, value in _config_snapshot(node).items() if key.startswith("BGP")}


def _established_peers(data, path=()):
    """Preserve VRF/AF identity while ignoring counters and uptime."""
    peers = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "peers" and isinstance(value, dict):
                peers.update(path + (peer,) for peer, attributes in value.items()
                             if attributes.get("state") == "Established")
            else:
                peers.update(_established_peers(value, path + (key,)))
    return peers


def _bgp_peers(node):
    return _established_peers(json.loads(_run(node, "sudo vtysh -c 'show bgp vrf all summary json'")))


def _bgp_restored(node, expected):
    return expected <= _bgp_peers(node)


@pytest.fixture(scope="module")
def isis_force10_fabric(rand_selected_dut, nbrhosts):
    """Configure the seven existing Force10 topology nodes through the SONiC CLI."""
    nodes = {"P1": rand_selected_dut}
    missing_nodes = []
    for name in ("PE1", "PE2", "PE3", "P2", "P3", "P4"):
        if name not in nbrhosts:
            missing_nodes.append(name)
        else:
            nodes[name] = nbrhosts[name]["host"]
    pytest_assert(not missing_nodes, "Missing Force10 helper VMs: {}".format(missing_nodes))

    for name, node in nodes.items():
        framework_enabled = _config_value(node, "DEVICE_METADATA|localhost", "frr_mgmt_framework_config")
        pytest_assert(framework_enabled.lower() == "true",
                      "FRR management framework is not enabled in ConfigDB on {}".format(name))

    original_bgp = _bgp_config(nodes["P1"])
    original_peers = _bgp_peers(nodes["P1"])
    addresses = []
    # This suite owns only a clean test fabric; do not erase someone else's IS-IS.
    for node in nodes.values():
        for table in ("ISIS_GLOBALS", "ISIS_INTERFACE", "ISIS_REDISTRIBUTE"):
            pytest_assert(not _run(node, "sudo sonic-db-cli CONFIG_DB KEYS '{}|*'".format(table)),
                          "Remove existing {} configuration before running this suite".format(table))
    # Profiles have IPv6-only transit links. Reserve twelve /31s for IPv4.
    subnet = ipaddress.ip_network("192.0.2.0/27")
    for node in nodes.values():
        for link in json.loads(_run(node, "ip -j -4 address show")):
            for address in link.get("addr_info", []):
                existing = ipaddress.ip_interface("{}/{}".format(address["local"], address["prefixlen"]))
                pytest_assert(not existing.network.overlaps(subnet), "Temporary IPv4 address pool is in use")

    try:
        for index, (left, left_if, right, right_if) in enumerate(LINKS):
            for name, interface, offset in ((left, left_if, 0), (right, right_if, 1)):
                address = "{}/31".format(subnet.network_address + index * 2 + offset)
                _run(nodes[name], "sudo config interface ip add {} {}".format(interface, address))
                addresses.append((nodes[name], interface, address))
        for name, node in nodes.items():
            _configure_global(node, NODE_NETS[name])
            _configure_interfaces(node, NODE_INTERFACES[name])

        pytest_assert(wait_until(120, 5, 0, _fabric_neighbors_up, nodes),
                      "IS-IS adjacencies did not converge on the Force10 seven-node topology")
        pytest_assert(_bgp_config(nodes["P1"]) == original_bgp, "Initial IS-IS setup changed BGP configuration")
        pytest_assert(wait_until(120, 3, 0, _bgp_restored, nodes["P1"], original_peers),
                      "Initial IS-IS setup affected established BGP peers")
        yield nodes
    finally:
        # Leave the shared community testbed without IS-IS configuration.
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis del {}".format(interface), check=False)
            _run(node, "sudo config isis del {}".format(INSTANCE), check=False)
        for node, interface, address in reversed(addresses):
            _run(node, "sudo config interface ip remove {} {}".format(interface, address), check=False)
        for node in nodes.values():
            for table in ("ISIS_GLOBALS", "ISIS_INTERFACE", "ISIS_REDISTRIBUTE"):
                pytest_assert(not _run(node, "sudo sonic-db-cli CONFIG_DB KEYS '{}|*'".format(table)),
                              "Cleanup left test rows in " + table)
        for node, interface, address in addresses:
            pytest_assert(_run(node, "sudo sonic-db-cli CONFIG_DB EXISTS 'INTERFACE|{}|{}'".format(
                interface, address)) == "0", "Cleanup left a temporary transit address")
        pytest_assert(_bgp_config(nodes["P1"]) == original_bgp, "IS-IS tests changed BGP configuration")
        pytest_assert(wait_until(180, 3, 0, _bgp_restored, nodes["P1"], original_peers),
                      "BGP baseline did not recover after IS-IS cleanup")


def test_isis_cli_programs_configdb(isis_force10_fabric):
    """Check representative composite keys and explicit AF bindings on the DUT."""
    p1 = isis_force10_fabric["P1"]
    expected = [
        ("ISIS_GLOBALS|default|FABRIC", "net_title", NODE_NETS["P1"]),
        ("ISIS_GLOBALS|default|FABRIC", "level", "level-2"),
        ("ISIS_GLOBALS|default|FABRIC", "lsp_mtu", "1400"),
        ("ISIS_INTERFACE|default|Ethernet112", "instance_name", INSTANCE),
        ("ISIS_INTERFACE|default|Ethernet112", "ipv4_enabled", "true"),
        ("ISIS_INTERFACE|default|Ethernet112", "network_type", "p2p"),
        ("ISIS_INTERFACE|default|Loopback0", "passive", "true"),
    ]
    for table_key, field, value in expected:
        actual = _config_value(p1, table_key, field)
        pytest_assert(actual == value,
                      "{} {} expected {!r}, got {!r}".format(table_key, field, value, actual))


def test_isis_cli_establishes_adjacencies_and_routes(isis_force10_fabric):
    """Smoke-test the installed show path, a learned route and IPv4 reachability."""
    nodes = isis_force10_fabric
    # The fixture already checks all adjacencies; one DUT query covers this CLI path.
    database = _run(nodes["P1"], "sudo show isis database --detail")
    pytest_assert(database, "IS-IS database is empty on P1")

    prefix = "100.1.0.31/32"  # PE3 Loopback0 from the community 7nodes_force10 profile.
    pytest_assert(wait_until(120, 5, 0, _route_is_installed, nodes["P1"], prefix),
                  "P1 did not learn PE3 Loopback0 through IS-IS")
    _run(nodes["P1"], "ping -I Loopback0 -c 5 -W 2 {}".format(prefix.split("/")[0]))
    _await_commands(nodes["P1"], "router isis FABRIC",
                    ["net " + NODE_NETS["P1"], "is-type level-2-only", "lsp-mtu 1400"])
    _await_commands(nodes["P1"], "interface Ethernet112",
                    ["ip router isis FABRIC", "isis network point-to-point"])
    try:
        _run(nodes["PE3"], "sudo config interface isis del Loopback0")
        pytest_assert(wait_until(90, 3, 0, _route_is_installed, nodes["P1"], prefix, False),
                      "Removing PE3's only passive binding did not withdraw its IPv4 loopback")
    finally:
        _run(nodes["PE3"], "sudo config interface isis ipv4 Loopback0 enable --instance FABRIC")
        _run(nodes["PE3"], "sudo config interface isis passive Loopback0 enable")
    pytest_assert(wait_until(90, 3, 0, _route_is_installed, nodes["P1"], prefix),
                  "Restoring the passive binding did not restore the IPv4 route")


def test_isis_cli_interface_disable_enable(isis_force10_fabric):
    """Verify removal and enable-only binding before restoring the p2p attributes."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config interface isis ipv4 Ethernet112 disable")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS 'ISIS_INTERFACE|default|Ethernet112'") == "0",
                      "Interface disable left an IS-IS row behind")
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"] - 1),
                      "Disabling IS-IS on Ethernet112 did not remove one P1 adjacency")

        _run(p1, "sudo config interface isis ipv4 Ethernet112 enable --instance {}".format(INSTANCE))
        pytest_assert(wait_until(30, 2, 0, _interface_is_bound, p1, "Ethernet112"),
                      "An enable-only row did not bind Ethernet112 in FRR")
        # LAN is the default; restore p2p before expecting this peer to converge.
        _run(p1, "sudo config interface isis network-type Ethernet112 p2p")
        pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                      "Enabling IS-IS on Ethernet112 did not restore the P1 adjacency")
    finally:
        _configure_interface(p1, "Ethernet112")


def _interface_is_bound(node, interface):
    output = _run(node, "sudo show isis interface")
    return bool(re.search(r"\b{}\b".format(re.escape(interface)), output))


def test_isis_cli_instance_delete_add(isis_force10_fabric):
    """Require interface cleanup before deleting and rebuilding a process."""
    p1 = isis_force10_fabric["P1"]
    blocked = p1.shell("sudo config isis del {}".format(INSTANCE), module_ignore_errors=True)
    pytest_assert(blocked.get("rc", 0) != 0 and
                  "Delete IS-IS on interface" in blocked.get("stdout", "") + blocked.get("stderr", ""),
                  "Process deletion should refuse while IS-IS interface rows remain")
    pytest_assert(_config_value(p1, "ISIS_GLOBALS|default|FABRIC", "net_title") == NODE_NETS["P1"],
                  "Rejected process deletion changed its configuration")
    try:
        for interface in NODE_INTERFACES["P1"] + ["Loopback0"]:
            _run(p1, "sudo config interface isis del {}".format(interface))
        _run(p1, "sudo config isis del {}".format(INSTANCE))
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS 'ISIS_GLOBALS|default|FABRIC'") == "0",
                      "Process deletion left its ConfigDB row behind")
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, 0),
                      "Instance deletion did not clear P1 adjacencies")
    finally:
        _configure_global(p1, NODE_NETS["P1"])
        _configure_interfaces(p1, NODE_INTERFACES["P1"])
    pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                  "Instance recreation did not restore P1 adjacencies")


def _interface_metric_applied(node, interface, metric, present):
    output = _run(node, "sudo vtysh -c 'show running-config isisd'")
    block = re.search(r"(?m)^interface {}\n((?:[ \t].*\n)*)".format(re.escape(interface)), output)
    if not block:
        return False
    commands = {line.strip() for line in block.group(1).splitlines()}
    return ("isis metric level-2 {}".format(metric) in commands) == present


def test_isis_cli_metric_reset(isis_force10_fabric):
    """Check one installed reset path; detailed validation stays in unit tests."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config interface isis metric Ethernet112 30 --level level-2")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|default|Ethernet112", "metric_level_2") == "30",
                      "Metric update did not reach ConfigDB")
        pytest_assert(wait_until(30, 2, 0, _interface_metric_applied, p1, "Ethernet112", "30", True),
                      "The level-2 metric update did not reach isisd running-config")
        _run(p1, "sudo config interface isis reset Ethernet112 metric --level level-2")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB HEXISTS "
                           "'ISIS_INTERFACE|default|Ethernet112' metric_level_2") == "0",
                      "Metric reset did not remove the explicit level-2 field")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|default|Ethernet112", "network_type") == "p2p",
                      "Metric reset discarded the circuit type")
        pytest_assert(wait_until(30, 2, 0, _interface_metric_applied, p1, "Ethernet112", "30", False),
                      "Metric reset did not remove the custom level-2 command from running-config")
    finally:
        _run(p1, "sudo config interface isis reset Ethernet112 metric --level level-2")


def test_isis_cli_ipv6_and_dual_af(isis_force10_fabric):
    """Use the profile IPv6 addresses and verify each AF transition in isisd."""
    nodes = isis_force10_fabric
    p1 = nodes["P1"]
    context = "interface Ethernet112"
    try:
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis ipv6 {} enable --instance FABRIC".format(interface))
        _await_commands(p1, context, ["ip router isis FABRIC", "ipv6 router isis FABRIC"])
        prefix = "2064:300::1f/128"
        pytest_assert(wait_until(120, 3, 0, _route_is_installed, p1, prefix),
                      "P1 did not learn PE3's IPv6 loopback")
        _run(p1, "ping -6 -I Loopback0 -c 5 -W 2 2064:300::1f")
        _run(p1, "sudo config interface isis metric Ethernet112 30 --level level-2")
        _run(p1, "sudo config interface isis ipv4 Ethernet112 disable")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|default|Ethernet112", "ipv6_enabled") == "true",
                      "IPv4 disable discarded IPv6")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|default|Ethernet112", "metric_level_2") == "30",
                      "First AF disable discarded interface attributes")
        _await_commands(p1, context, ["ipv6 router isis FABRIC"], ["ip router isis FABRIC"])
        _run(p1, "sudo config interface isis ipv6 Ethernet112 disable")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS 'ISIS_INTERFACE|default|Ethernet112'") == "0",
                      "Final AF disable left a row")
        _await_commands(p1, context, absent=["ip router isis FABRIC", "ipv6 router isis FABRIC"])
        _run(p1, "sudo config interface isis ipv4 Ethernet112 enable --instance FABRIC")
        _await_commands(p1, context, ["ip router isis FABRIC"], ["ipv6 router isis FABRIC"])
        pytest_assert(not _config_value(p1, "ISIS_INTERFACE|default|Ethernet112", "metric_level_2"),
                      "Re-enable retained the deleted metric")
        _run(p1, "sudo config interface isis ipv6 Ethernet112 enable --instance FABRIC")
        _await_commands(p1, context, ["ip router isis FABRIC", "ipv6 router isis FABRIC"])
    finally:
        # Recreate only the interface deleted by this case, then remove temporary IPv6.
        _configure_interface(p1, "Ethernet112")
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis ipv6 {} disable".format(interface), check=False)
    pytest_assert(wait_until(90, 3, 0, _fabric_neighbors_up, nodes), "IPv4 baseline did not recover")


def test_isis_cli_vrf_and_levels(isis_force10_fabric):
    """Install an isolated second process; retain inactive-level saved metrics."""
    p1 = isis_force10_fabric["P1"]
    vrf, interface, instance = "VrfIsisTest", "Loopback901", "ISIS_TEST"
    for key in ("VRF|" + vrf, "LOOPBACK_INTERFACE|" + interface):
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS '{}'".format(key)) == "0",
                      "Temporary context already exists: " + key)
    original = _bgp_config(p1)
    try:
        _run(p1, "sudo config vrf add " + vrf)
        _run(p1, "sudo config loopback add " + interface)
        _run(p1, "sudo config interface vrf bind {} {}".format(interface, vrf))
        _run(p1, "sudo config isis add {} --vrf {}".format(instance, vrf))
        _run(p1, "sudo config interface isis ipv4 {} enable --instance {} --vrf {}".format(
            interface, instance, vrf))
        _run(p1, "sudo config interface isis passive {} enable --vrf {}".format(interface, vrf))
        for level, metric in (("level-1", 21), ("level-2", 31)):
            _run(p1, "sudo config interface isis metric {} {} --level {} --vrf {}".format(
                interface, metric, level, vrf))
        context = "interface {} vrf {}".format(interface, vrf)
        _await_commands(p1, "router isis {} vrf {}".format(instance, vrf), ["metric-style wide"])
        _await_commands(
            p1, context,
            ["ip router isis ISIS_TEST", "isis passive", "isis metric level-1 21", "isis metric level-2 31"])
        for level, installed in (("level-1", "level-1"), ("level-1-2", "level-1-2"),
                                 ("level-2", "level-2-only")):
            _run(p1, "sudo config isis level {} {} --vrf {}".format(instance, level, vrf))
            if level == "level-1-2":
                # FRR may omit this default from its saved configuration.
                _await_commands(p1, context, ["ip router isis ISIS_TEST"],
                                ["isis circuit-type level-1", "isis circuit-type level-2-only"])
            else:
                _await_commands(p1, context, ["isis circuit-type " + installed])
        _run(p1, "sudo config interface isis level {} level-2 --vrf {}".format(interface, vrf))
        _await_commands(p1, context, ["isis circuit-type level-2-only"])
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|{}|{}".format(vrf, interface), "metric_level_1") == "21",
                      "Narrowing the level discarded inactive L1 configuration")
        wrong = p1.shell("sudo config interface isis ipv6 {} enable --instance FABRIC".format(interface),
                         module_ignore_errors=True)
        pytest_assert(wrong.get("rc", 0) != 0, "Wrong-VRF binding was accepted")
        data = json.loads(_run(p1, "sudo show isis configuration --vrf {} --instance {}".format(vrf, instance)))
        pytest_assert("{}|{}".format(vrf, interface) in data["ISIS_INTERFACE"], "VRF query omitted binding")
        json.loads(_run(p1, "sudo show isis interface {} --vrf {} --json".format(interface, vrf)))
        pytest_assert(_bgp_config(p1) == original, "VRF IS-IS changes modified BGP configuration")
    finally:
        _run(p1, "sudo config interface isis del {} --vrf {}".format(interface, vrf), check=False)
        _run(p1, "sudo config isis del {} --vrf {}".format(instance, vrf), check=False)
        _run(p1, "sudo config interface vrf unbind " + interface, check=False)
        _run(p1, "sudo config loopback del " + interface, check=False)
        _run(p1, "sudo config vrf del " + vrf, check=False)


def test_isis_cli_attribute_groups(isis_force10_fabric):
    """One installed snapshot covers distinct command groups, then restores defaults."""
    p1 = isis_force10_fabric["P1"]
    global_context, interface_context = "router isis FABRIC", "interface Loopback0"
    global_updates = [
        ("dynamic-hostname", "disable", "no hostname dynamic"),
        ("lsp-mtu", "1390", "lsp-mtu 1390"),
        ("overload", "enable", "set-overload-bit"),
        ("overload-on-startup", "15", "set-overload-bit on-startup 15"),
        ("ipv6-multi-topology", "enable", "topology ipv6-unicast"),
    ]
    per_level = [
        ("lsp-gen-interval", "20", "lsp-timers level-2 gen-interval 20 refresh-interval 900 max-lifetime 1200"),
        ("spf-interval", "5", "spf-interval level-2 5"),
    ]
    interface_updates = [
        ("hello-interval", "5", "isis hello-interval level-2 5"),
        ("hello-multiplier", "4", "isis hello-multiplier level-2 4"),
        ("metric", "35", "isis metric level-2 35"),
    ]
    before = json.loads(_run(p1, "sudo show isis configuration --instance FABRIC"))
    before_global = _running_commands(p1, global_context)
    before_interface = _running_commands(p1, interface_context)
    try:
        for field, value, expected in global_updates:
            _run(p1, "sudo config isis {} FABRIC {}".format(field, value))
            _await_commands(p1, global_context, [expected])
        for field, value, expected in per_level:
            _run(p1, "sudo config isis {} FABRIC {} --level level-2".format(field, value))
            _await_commands(p1, global_context, [expected])
        _run(p1, "sudo config isis spf-backoff FABRIC --init-delay 10 --short-delay 20 "
                 "--long-delay 30 --hold-down 50 --time-to-learn 40")
        _await_commands(p1, global_context,
                        ["spf-delay-ietf init-delay 10 short-delay 20 long-delay 30 holddown 50 time-to-learn 40"])
        for field, value, expected in interface_updates:
            _run(p1, "sudo config interface isis {} Loopback0 {} --level level-2".format(field, value))
            _await_commands(p1, interface_context, [expected])
        _run(p1, "sudo config interface isis passive Loopback0 disable")
        _await_commands(p1, interface_context, absent=["isis passive"])
        _run(p1, "sudo config interface isis network-type Loopback0 p2p")
        _await_commands(p1, interface_context, ["isis network point-to-point"])
        _run(p1, "sudo config interface isis reset Loopback0 network-type")
        _await_commands(p1, interface_context, absent=["isis network point-to-point"])
    finally:
        for field, _, _ in global_updates:
            if field == "lsp-mtu":
                _run(p1, "sudo config isis lsp-mtu FABRIC 1400")
            else:
                _run(p1, "sudo config isis reset FABRIC " + field)
        for field, _, _ in per_level:
            _run(p1, "sudo config isis reset FABRIC {} --level level-2".format(field))
        _run(p1, "sudo config isis spf-backoff del FABRIC")
        for field, _, _ in interface_updates:
            _run(p1, "sudo config interface isis reset Loopback0 {} --level level-2".format(field))
        _run(p1, "sudo config interface isis reset Loopback0 network-type")
        _run(p1, "sudo config interface isis passive Loopback0 enable")
    after = json.loads(_run(p1, "sudo show isis configuration --instance FABRIC"))
    pytest_assert(after == before, "Attribute reset did not restore the ConfigDB snapshot")
    _await_commands(p1, global_context, before_global)
    _await_commands(p1, interface_context, before_interface)
    _await_commands(p1, global_context, absent=[item[2] for item in global_updates + per_level]
                    + ["spf-delay-ietf init-delay 10 short-delay 20 long-delay 30 holddown 50 time-to-learn 40"])
    _await_commands(p1, interface_context, absent=[item[2] for item in interface_updates])


def test_isis_cli_redistribution(isis_force10_fabric):
    """SONiC owns policy CRUD; a temporary external static route supplies input."""
    nodes = isis_force10_fabric
    source, receiver = nodes["PE3"], nodes["P1"]
    prefix, route_map, context = "198.51.100.253/32", "ISIS_TEST_MAP", "router isis FABRIC"
    policy_key = "ISIS_REDISTRIBUTE|default|FABRIC|ipv4|static|level-2|0"
    for key in ("ROUTE_MAP_SET|" + route_map, "ROUTE_MAP|" + route_map + "|10"):
        pytest_assert(_run(source, "sudo sonic-db-cli CONFIG_DB EXISTS '{}'".format(key)) == "0",
                      "Temporary route map already exists")
    routes = json.loads(_run(source, "sudo vtysh -c 'show ip route {} json'".format(prefix)))
    pytest_assert(prefix not in routes, "Temporary static prefix already exists")
    try:
        _run(source, "sudo sonic-db-cli CONFIG_DB HSET 'ROUTE_MAP_SET|{}' NULL NULL".format(route_map))
        _run(source, "sudo sonic-db-cli CONFIG_DB HSET 'ROUTE_MAP|{}|10' route_operation permit".format(route_map))
        _await_commands(source, "route-map {} permit 10".format(route_map))
        _run(source, "sudo vtysh -c 'configure terminal' -c 'ip route {} Null0'".format(prefix))
        _run(source, "sudo config isis redistribute add FABRIC ipv4 static level-2 "
                     "--metric 25 --route-map " + route_map)
        _await_commands(source, context, ["redistribute ipv4 static level-2 metric 25 route-map " + route_map])
        pytest_assert(_config_value(source, policy_key, "metric") == "25", "Policy metric not saved")
        pytest_assert(_config_value(source, policy_key, "route_map@") == route_map, "Route-map not saved")
        pytest_assert(wait_until(90, 3, 0, _route_is_installed, receiver, prefix), "Static route not advertised")
        _run(source, "sudo config isis redistribute add FABRIC ipv4 static level-2")
        pytest_assert(_config_value(source, policy_key, "metric") == "0", "Replacement did not reset metric")
        pytest_assert(not _config_value(source, policy_key, "route_map@"), "Replacement retained route-map")
        # Native FRR omits metric 0 when serializing defaults.
        _await_commands(source, context, ["redistribute ipv4 static level-2"],
                        ["redistribute ipv4 static level-2 metric 25 route-map " + route_map])
        for metric, suffix in ((40, " metric 40 route-map " + route_map), (0, "")):
            options = "--metric 40 --route-map " + route_map if metric else ""
            _run(source, "sudo config isis redistribute add FABRIC ipv4 table level-2 --table-id 1234 " + options)
            _await_commands(source, context, ["redistribute ipv4 table 1234 level-2" + suffix],
                            [] if metric else ["redistribute ipv4 table 1234 level-2 metric 40 route-map " + route_map])
            pytest_assert(_config_value(source,
                          "ISIS_REDISTRIBUTE|default|FABRIC|ipv4|table|level-2|1234", "metric") == str(metric),
                          "Table-id policy replacement not saved")
        _run(source, "sudo config isis redistribute del FABRIC ipv4 table level-2 --table-id 1234")
        _await_commands(source, context, absent=["redistribute ipv4 table 1234 level-2"])
        _run(source, "sudo config isis redistribute del FABRIC ipv4 static level-2")
        _await_commands(source, context, absent=["redistribute ipv4 static level-2"])
        pytest_assert(_run(source, "sudo sonic-db-cli CONFIG_DB EXISTS '{}'".format(policy_key)) == "0",
                      "Policy deletion left a ConfigDB row")
        pytest_assert(wait_until(90, 3, 0, _route_is_installed, receiver, prefix, False),
                      "Deleting the policy did not withdraw its static prefix")
    finally:
        _run(source, "sudo config isis redistribute del FABRIC ipv4 table level-2 --table-id 1234", check=False)
        _run(source, "sudo config isis redistribute del FABRIC ipv4 static level-2", check=False)
        _run(source, "sudo vtysh -c 'configure terminal' -c 'no ip route {} Null0'".format(prefix), check=False)
        _run(source, "sudo sonic-db-cli CONFIG_DB DEL 'ROUTE_MAP|{}|10'".format(route_map), check=False)
        _run(source, "sudo sonic-db-cli CONFIG_DB DEL 'ROUTE_MAP_SET|{}'".format(route_map), check=False)


def test_isis_cli_saved_restoration_and_bgp(isis_force10_fabric):
    """Restart/reload once each, then mutate/delete a restored interface field."""
    nodes = isis_force10_fabric
    p1 = nodes["P1"]
    original_bgp, original_peers = _bgp_config(p1), _bgp_peers(p1)
    pytest_assert(original_peers, "BGP coexistence requires established baseline peers on P1")
    backup = _run(p1, "mktemp /tmp/isis-config-db.XXXXXX")
    _run(p1, "sudo cp -p /etc/sonic/config_db.json " + shlex.quote(backup))
    try:
        _run(p1, "sudo config interface isis metric Ethernet112 32 --level level-2")
        _run(p1, "sudo config isis spf-backoff FABRIC --init-delay 10 --short-delay 20 "
                 "--long-delay 30 --hold-down 50 --time-to-learn 40")
        _await_commands(p1, "interface Ethernet112", ["isis metric level-2 32"])
        snapshot = json.loads(_run(p1, "sudo show isis configuration --instance FABRIC"))
        _run(p1, "sudo config save -y")
        for command in ("sudo systemctl restart bgp", "sudo config reload -y"):
            _run(p1, command)
            pytest_assert(wait_until(240, 5, 0, _fabric_neighbors_up, nodes), "IS-IS restoration failed")
            _await_commands(p1, "interface Ethernet112", ["ip router isis FABRIC", "isis metric level-2 32"])
            _await_commands(p1, "router isis FABRIC",
                            ["spf-delay-ietf init-delay 10 short-delay 20 long-delay 30 holddown 50 time-to-learn 40"])
            restored = json.loads(_run(p1, "sudo show isis configuration --instance FABRIC"))
            pytest_assert(restored == snapshot, "Saved IS-IS configuration changed after " + command)
            pytest_assert(wait_until(120, 3, 0, _route_is_installed, p1, "100.1.0.31/32"),
                          "Learned route did not recover")
            pytest_assert(_bgp_config(p1) == original_bgp, "Restoration modified BGP configuration")
            pytest_assert(wait_until(240, 5, 0, _bgp_restored, p1, original_peers),
                          "Previously established BGP peers did not recover")
            logger.info("Restored BGP peers: %s; pre-test peers: %s", _bgp_peers(p1), original_peers)
        _run(p1, "sudo config interface isis metric Ethernet112 33 --level level-2")
        _await_commands(p1, "interface Ethernet112", ["isis metric level-2 33"], ["isis metric level-2 32"])
        _run(p1, "sudo config interface isis reset Ethernet112 metric --level level-2")
        _await_commands(p1, "interface Ethernet112", absent=["isis metric level-2 33"])
        _run(p1, "sudo config isis spf-backoff del FABRIC")
        _await_commands(
            p1, "router isis FABRIC",
            absent=["spf-delay-ietf init-delay 10 short-delay 20 long-delay 30 holddown 50 time-to-learn 40"])
    finally:
        _run(p1, "sudo config interface isis reset Ethernet112 metric --level level-2", check=False)
        _run(p1, "sudo config isis spf-backoff del FABRIC", check=False)
        _run(p1, "sudo cp -p {} /etc/sonic/config_db.json".format(shlex.quote(backup)))
        _run(p1, "sudo rm " + shlex.quote(backup))


def _stable_json(value):
    """Drop only live counters/timestamps; retain protocol/interface/route content."""
    volatile = {"uptime", "up-time", "holdtime", "holdTime", "lastUpdate", "lastUpdated", "lastChange",
                "age", "expires", "lspAge", "lifetime", "remainingLifetime"}
    if isinstance(value, dict):
        return {key: _stable_json(item) for key, item in value.items() if key not in volatile}
    if isinstance(value, list):
        return [_stable_json(item) for item in value]
    return value


def test_isis_cli_query_equivalence(isis_force10_fabric):
    """Compare installed wrappers with daemon JSON and ConfigDB explicit rows."""
    p1 = isis_force10_fabric["P1"]
    for wrapper, native in (("interface Ethernet112", "interface Ethernet112"),
                            ("route --level level-2", "route level-2")):
        actual = json.loads(_run(p1, "sudo show isis {} --vrf default --json".format(wrapper)))
        expected = json.loads(_run(p1, "sudo vtysh -c 'show isis vrf default {} json'".format(native)))
        pytest_assert(bool(actual) and _stable_json(actual) == _stable_json(expected),
                      "Wrapper JSON differs from daemon JSON: " + wrapper)
    json.loads(_run(p1, "sudo show isis neighbor --vrf all --json"))
    shown = json.loads(_run(p1, "sudo show isis configuration --instance FABRIC"))
    config = _config_snapshot(p1)
    for table, rows in shown.items():
        expected = {key: {field: value for field, value in row.items() if field != "NULL"}
                    for key, row in config.get(table, {}).items()
                    if key.startswith("default|") and
                    (row.get("instance_name") == INSTANCE if table == "ISIS_INTERFACE"
                     else key.split("|")[1] == INSTANCE)}
        pytest_assert({key: row["explicit"] for key, row in rows.items()} == expected,
                      "Configuration wrapper differs from ConfigDB: " + table)
