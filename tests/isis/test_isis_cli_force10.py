"""IS-IS CLI integration tests for the community Force10 seven-node topology."""

import ipaddress
import json
import logging
import re
from contextlib import contextmanager

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

# Preserve the profile's IPv6/BGP topology. The fixture temporarily numbers
# these same twelve links for its IPv4 forwarding assertions, then removes only
# addresses it added. Link order assigns consecutive /31s from 198.19.0.0/27.
FABRIC_LINKS = (
    (("P1", "Ethernet112"), ("PE1", "Ethernet0")),
    (("P1", "Ethernet116"), ("PE2", "Ethernet0")),
    (("P1", "Ethernet124"), ("P3", "Ethernet0")),
    (("P1", "Ethernet64"), ("P2", "Ethernet0")),
    (("P1", "Ethernet68"), ("P4", "Ethernet0")),
    (("PE1", "Ethernet4"), ("P3", "Ethernet4")),
    (("PE2", "Ethernet8"), ("P3", "Ethernet8")),
    (("P3", "Ethernet12"), ("P2", "Ethernet4")),
    (("P3", "Ethernet16"), ("P4", "Ethernet4")),
    (("P2", "Ethernet8"), ("P4", "Ethernet8")),
    (("P2", "Ethernet12"), ("PE3", "Ethernet4")),
    (("P4", "Ethernet12"), ("PE3", "Ethernet12")),
)


EXPECTED_NEIGHBORS = {
    "P1": 5,
    "PE1": 2,
    "PE2": 2,
    "PE3": 2,
    "P2": 4,
    "P3": 5,
    "P4": 4,
}


def _run(node, command, check=True):
    result = node.shell(command, module_ignore_errors=True)
    if check:
        pytest_assert(result.get("rc", 1) == 0,
                      "Command failed on {}: {}\n{}".format(
                          getattr(node, "hostname", "node"), command, result))
    return result.get("stdout", "").strip()


def _config_value(node, table_key, field):
    return _run(node, "sudo sonic-db-cli CONFIG_DB HGET '{}' {}".format(table_key, field))


def _ipv4_underlay_plan(nodes):
    """Preflight every node before changing any addressing in the shared lab."""
    tables = {name: json.loads(_run(node, "sudo sonic-cfggen -d --var-json INTERFACE"))
              for name, node in nodes.items()}
    planned = []
    first = ipaddress.IPv4Address("198.19.0.0")
    expected = {(name, interface): ipaddress.ip_interface("{}/31".format(first + index * 2 + side))
                for index, endpoints in enumerate(FABRIC_LINKS)
                for side, (name, interface) in enumerate(endpoints)}
    reserved = ipaddress.ip_network("198.19.0.0/27")
    for name, rows in tables.items():
        for key in rows:
            if "|" not in key:
                continue
            interface, prefix = key.split("|", 1)
            address = ipaddress.ip_interface(prefix.strip())
            if address.version == 4 and address.network.overlaps(reserved):
                pytest_assert(expected.get((name, interface)) == address,
                              "Test IPv4 subnet conflicts with {}:{}".format(name, key))
    for index, endpoints in enumerate(FABRIC_LINKS):
        for side, (name, interface) in enumerate(endpoints):
            rows = tables[name]
            pytest_assert(interface in rows, "Missing routed interface {}:{}".format(name, interface))
            address = ipaddress.ip_interface("{}/31".format(first + index * 2 + side))
            present = False
            for key in rows:
                if "|" not in key:
                    continue
                existing_port, prefix = key.split("|", 1)
                existing = ipaddress.ip_interface(prefix.strip())
                if existing.version != 4 or not existing.network.overlaps(address.network):
                    continue
                pytest_assert(existing_port == interface and existing == address,
                              "Test IPv4 subnet conflicts with {}:{}".format(name, key))
                present = True
            if not present:
                planned.append((name, interface, str(address)))
    return planned


def _configure_global(node, net):
    _run(node, "sudo config isis instance add CORE")
    _run(node, "sudo config isis net add CORE {}".format(net))
    _run(node, "sudo config isis set CORE level-type level-2-only")
    _run(node, "sudo config isis set CORE dynamic-hostname true")
    _run(node, "sudo config isis set CORE lsp-mtu 1400")
    _run(node, "sudo config isis level set CORE both lsp-refresh-interval 900")
    _run(node, "sudo config isis level set CORE both lsp-maximum-lifetime 1200")
    _run(node, "sudo config isis instance enable CORE")


def _configure_interfaces(node, interfaces):
    for interface in interfaces + ["Loopback0"]:
        _run(node, "sudo config interface isis bind {} CORE".format(interface))
        if interface == "Loopback0":
            _run(node, "sudo config interface isis set {} passive true".format(interface))
        else:
            _run(node, "sudo config interface isis set {} network-type point-to-point".format(interface))
            _run(node, "sudo config interface isis level set {} both metric 10".format(interface))
        for family in ("ipv4", "ipv6"):
            _run(node, "sudo config interface isis af {} {} enable".format(interface, family))
        _run(node, "sudo config interface isis enable {}".format(interface))


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


def _route_is_installed(node, prefix):
    family = "ipv6" if ":" in prefix else "ip"
    result = node.shell("sudo docker exec bgp vtysh -c 'show {} route {} json'".format(family, prefix),
                        module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return False
    try:
        rows = json.loads(result.get("stdout", "")).get(prefix, [])
        return any(row.get("protocol") == "isis" and row.get("selected") and row.get("installed")
                   and any(hop.get("active") and hop.get("fib") for hop in row.get("nexthops", []))
                   for row in rows)
    except (ValueError, TypeError, AttributeError):
        return False


@contextmanager
def _isis_forwarding_only(nodes):
    """Keep BGP sessions, but withdraw competing endpoint connected prefixes."""
    key = "BGP_GLOBALS_AF|default|ipv6_unicast"
    previous = {name: _config_value(nodes[name], key, "redistribute_connected") for name in ("P1", "PE3")}
    for name, value in previous.items():
        pytest_assert(value in ("", "true", "false"),
                      "Unexpected BGP redistribute_connected value on {}: {!r}".format(name, value))
    changed = []
    try:
        for name, value in previous.items():
            if value == "true":
                changed.append(name)
                _run(nodes[name], "sudo sonic-db-cli CONFIG_DB HSET '{}' redistribute_connected false".format(key))
        yield
    finally:
        failures = []
        for name in reversed(changed):
            try:
                result = nodes[name].shell(
                    "sudo sonic-db-cli CONFIG_DB HSET '{}' redistribute_connected true".format(key),
                    module_ignore_errors=True)
                if result.get("rc", 1) != 0:
                    failures.append(name)
            except Exception:
                failures.append(name)
        pytest_assert(not failures, "Failed to restore BGP connected redistribution on {}".format(failures))


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

    address_plan = _ipv4_underlay_plan(nodes)
    added_addresses = []
    try:
        # Remove stale IS-IS state from a previous interrupted run.
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis unbind {}".format(interface))
            _run(node, "sudo config isis instance del CORE")

        for name, interface, address in address_plan:
            # Record before execution so an uncertain CLI reply is cleaned up.
            added_addresses.append((name, interface, address))
            _run(nodes[name], "sudo config interface ip add {} {}".format(interface, address))

        for name, node in nodes.items():
            _configure_global(node, NODE_NETS[name])
            _configure_interfaces(node, NODE_INTERFACES[name])

        pytest_assert(wait_until(120, 5, 0, _fabric_neighbors_up, nodes),
                      "IS-IS adjacencies did not converge on the Force10 seven-node topology")
        yield nodes
    finally:
        # Leave the shared community testbed without IS-IS configuration.
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis unbind {}".format(interface), check=False)
            _run(node, "sudo config isis instance del CORE", check=False)
        for name, interface, address in reversed(added_addresses):
            _run(nodes[name], "sudo config interface ip remove {} {}".format(interface, address), check=False)


def test_isis_cli_programs_configdb(isis_force10_fabric):
    """Verify global, timer, interface, and passive settings written by config CLI."""
    p1 = isis_force10_fabric["P1"]
    expected = [
        ("ISIS_INSTANCE|default|CORE", "enabled", "true"),
        ("ISIS_INSTANCE|default|CORE", "net_titles@", NODE_NETS["P1"]),
        ("ISIS_INSTANCE|default|CORE", "level_type", "level-2-only"),
        ("ISIS_INSTANCE|default|CORE", "dynamic_hostname", "true"),
        ("ISIS_INSTANCE|default|CORE", "lsp_mtu", "1400"),
        ("ISIS_INSTANCE_LEVEL|default|CORE|level-2", "lsp_refresh_interval", "900"),
        ("ISIS_INSTANCE_LEVEL|default|CORE|level-2", "lsp_maximum_lifetime", "1200"),
        ("ISIS_INTERFACE|Ethernet112", "enabled", "true"),
        ("ISIS_INTERFACE|Ethernet112", "network_type", "point-to-point"),
        ("ISIS_INTERFACE_LEVEL|Ethernet112|level-2", "metric", "10"),
        ("ISIS_INTERFACE|Loopback0", "passive", "true"),
    ]
    for table_key, field, value in expected:
        actual = _config_value(p1, table_key, field)
        pytest_assert(actual == value,
                      "{} {} expected {!r}, got {!r}".format(table_key, field, value, actual))


def test_isis_cli_establishes_adjacencies_and_routes(isis_force10_fabric):
    """Verify CLI show commands report the expected adjacencies and an IS-IS route."""
    nodes = isis_force10_fabric
    for name, expected in EXPECTED_NEIGHBORS.items():
        actual = _up_neighbor_count(nodes[name])
        pytest_assert(actual >= expected,
                      "{} has {} Up IS-IS neighbors, expected at least {}".format(name, actual, expected))
        database = _run(nodes[name], "sudo show isis database detail")
        pytest_assert(database, "IS-IS database is empty on {}".format(name))

    # BGP also advertises the profiles' IPv6 Loopbacks. Confirm selected native
    # IS-IS paths in both directions, rather than allowing BGP to mask a failure.
    with _isis_forwarding_only(nodes):
        for prefix, reverse in (("100.1.0.31/32", "100.1.0.35/32"),
                                ("2064:300::1f/128", "2064:700::23/128")):
            for name, target in (("P1", prefix), ("PE3", reverse)):
                pytest_assert(wait_until(120, 5, 0, _route_is_installed, nodes[name], target),
                              "{} has no installed IS-IS route for {}".format(name, target))
            destination, source = prefix.split("/")[0], reverse.split("/")[0]
            family = "-6" if ":" in prefix else "-4"
            _run(nodes["P1"], "ping {} -I {} -c 5 -W 2 {}".format(family, source, destination))


def test_isis_cli_interface_disable_enable(isis_force10_fabric):
    """Verify disable retains attributes and enable restores the same circuit."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config interface isis disable Ethernet112")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|Ethernet112", "enabled") == "false",
                      "Interface disable did not retain its disabled configuration")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|Ethernet112", "network_type") == "point-to-point",
                      "Interface disable discarded the configured network type")
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"] - 1),
                      "Disabling IS-IS on Ethernet112 did not remove one P1 adjacency")

        _run(p1, "sudo config interface isis enable Ethernet112")
        pytest_assert(wait_until(30, 2, 0, _interface_is_bound, p1, "Ethernet112"),
                      "Re-enable did not restore Ethernet112 in FRR")
        pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                      "Enabling IS-IS on Ethernet112 did not restore the P1 adjacency")
    finally:
        _configure_interfaces(p1, NODE_INTERFACES["P1"])


def _interface_is_bound(node, interface):
    output = _run(node, "sudo show isis interface")
    return bool(re.search(r"\b{}\b".format(re.escape(interface)), output))


def test_isis_cli_global_disable_enable(isis_force10_fabric):
    """Disable retains desired state; enable alone must restore the fabric."""
    p1 = isis_force10_fabric["P1"]
    blocked = p1.shell("sudo config isis instance del CORE", module_ignore_errors=True)
    pytest_assert(blocked.get("rc", 0) != 0 and
                  "Unbind IS-IS interface" in blocked.get("stdout", "") + blocked.get("stderr", ""),
                  "Process deletion should refuse while IS-IS interface rows remain")
    try:
        _run(p1, "sudo config isis instance disable CORE")
        pytest_assert(_config_value(p1, "ISIS_INSTANCE|default|CORE", "enabled") == "false",
                      "Process disable did not retain its disabled row")
        for key, field, expected in (
                ("ISIS_INSTANCE|default|CORE", "net_titles@", NODE_NETS["P1"]),
                ("ISIS_INSTANCE|default|CORE", "lsp_mtu", "1400"),
                ("ISIS_INTERFACE|Ethernet112", "network_type", "point-to-point"),
                ("ISIS_INTERFACE|Loopback0", "passive", "true")):
            pytest_assert(_config_value(p1, key, field) == expected,
                          "Disable discarded {} {}".format(key, field))
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, 0),
                      "Global IS-IS disable did not clear P1 adjacencies")
        blocked = p1.shell("sudo config isis instance del CORE", module_ignore_errors=True)
        pytest_assert(blocked.get("rc", 0) != 0, "Disabled interface references must also prevent deletion")
        _run(p1, "sudo config isis instance enable CORE")
        pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                      "Re-enable alone did not restore P1 adjacencies")
    finally:
        _configure_global(p1, NODE_NETS["P1"])
        _configure_interfaces(p1, NODE_INTERFACES["P1"])


def test_isis_cli_reset_and_repeated_enable(isis_force10_fabric):
    """Reset removes fields, preserves siblings and supports subsequent timer commands."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config isis instance enable CORE")
        pytest_assert(_config_value(p1, "ISIS_INSTANCE|default|CORE", "net_titles@") == NODE_NETS["P1"],
                      "Repeated enable discarded the configured NET")
        _run(p1, "sudo config interface isis level set Ethernet112 both metric 30")
        _run(p1, "sudo config interface isis enable Ethernet112")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE_LEVEL|Ethernet112|level-2", "metric") == "30",
                      "Repeated interface enable discarded the metric")
        _run(p1, "sudo config interface isis level reset Ethernet112 both metric")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB HEXISTS "
                               "'ISIS_INTERFACE_LEVEL|Ethernet112|level-2' metric") == "0",
                      "Metric reset did not remove the field")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|Ethernet112", "network_type") == "point-to-point",
                      "Metric reset discarded the circuit type")

        _run(p1, "sudo config isis level set CORE both lsp-maximum-lifetime 1500")
        _run(p1, "sudo config isis level set CORE both lsp-refresh-interval 1000")
        rejected = p1.shell("sudo config isis level reset CORE both lsp-maximum-lifetime", module_ignore_errors=True)
        pytest_assert(rejected.get("rc", 0) != 0,
                      "Reset accepted a lifetime smaller than refresh + 300")
        _run(p1, "sudo config isis level reset CORE both lsp-refresh-interval")
        _run(p1, "sudo config isis level reset CORE both lsp-maximum-lifetime")
        for field in ("lsp_refresh_interval", "lsp_maximum_lifetime"):
            pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB HEXISTS 'ISIS_INSTANCE_LEVEL|default|CORE|level-2' {}".
                               format(field)) == "0", "Reset did not remove {}".format(field))
        pytest_assert(_config_value(p1, "ISIS_INSTANCE|default|CORE", "lsp_mtu") == "1400",
                      "Timer reset discarded the MTU")
        _run(p1, "sudo config isis level set CORE both lsp-refresh-interval 900")
        _run(p1, "sudo config isis level set CORE both lsp-maximum-lifetime 1200")
    finally:
        # Set lifetime first so restoration also works after a failed reset.
        _run(p1, "sudo config isis level set CORE both lsp-maximum-lifetime 1500")
        _configure_global(p1, NODE_NETS["P1"])
        _configure_interfaces(p1, NODE_INTERFACES["P1"])
    pytest_assert(wait_until(90, 3, 0, _fabric_neighbors_up, isis_force10_fabric),
                  "IS-IS adjacencies did not recover after reset validation")


# Adapted from gs1571's offline UPDATE/DELETE and BGP continuity checks in
# sonic-mgmt #29119, commit 7bf6203851ff7d287e6cfb2838d21893823d0576.
# Original author: Grigorii Solovev <gs1571@gmail.com>.
def _supervisor(node, command):
    return _run(node, "sudo docker exec bgp supervisorctl {}".format(command))


def _running(node):
    return _run(node, "sudo docker exec bgp vtysh -c 'show running-config'")


def _interface_stanza(config, interface):
    match = re.search(r"^interface {}\n(.*?)(?=^\S|\Z)".format(re.escape(interface)),
                      config, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def _offline_profile_applied(node, metric=30, bound=False):
    config = _running(node)
    circuit = _interface_stanza(config, "Ethernet112")
    loopback = _interface_stanza(config, "Loopback0")
    metric_applied = (" isis metric {}\n".format(metric) in circuit or all(
        " isis metric {} {}\n".format(level, metric) in circuit for level in ("level-1", "level-2")))
    return metric_applied and (("router isis CORE" in loopback) == bound)


def test_isis_cli_offline_update_delete_preserves_bgp(isis_force10_fabric):
    """Recovery follows durable ownership after updates missed during daemon downtime."""
    p1 = isis_force10_fabric["P1"]
    counters = ("connections established", "connections dropped")
    neighbors = p1.bgp_facts()["ansible_facts"]["bgp_neighbors"]
    candidates = [(peer, facts) for peer, facts in neighbors.items()
                  if facts.get("state") == "established" and all(key in facts for key in counters)]
    if not candidates:
        pytest.skip("Offline recovery/BGP coexistence requires an established BGP peer with session counters")
    peer, before = candidates[0]
    bgpd_pid = _supervisor(p1, "pid bgpd")
    pytest_assert(bgpd_pid.isdigit() and int(bgpd_pid) > 0, "bgpd is not running")
    _configure_interfaces(p1, NODE_INTERFACES["P1"])
    pytest_assert(wait_until(90, 3, 0, _fabric_neighbors_up, isis_force10_fabric),
                  "Fabric must converge before recovery injection")
    pytest_assert(wait_until(30, 2, 0, _offline_profile_applied, p1, 10, True),
                  "Native IS-IS baseline has not been applied")
    try:
        _supervisor(p1, "stop frrcfgd")
        pytest_assert("STOPPED" in _run(p1, "sudo docker exec bgp supervisorctl status frrcfgd", check=False),
                      "frrcfgd did not stop")
        native_before = _running(p1)
        _run(p1, "sudo config interface isis level set Ethernet112 both metric 30")
        _run(p1, "sudo config interface isis unbind Loopback0")
        native_offline = _running(p1)
        for interface in ("Ethernet112", "Loopback0"):
            pytest_assert(_interface_stanza(native_before, interface) ==
                          _interface_stanza(native_offline, interface),
                          "Offline CLI writes unexpectedly changed native configuration")
    finally:
        _supervisor(p1, "start frrcfgd")
    try:
        pytest_assert(wait_until(90, 3, 0, _offline_profile_applied, p1),
                      "Recovery did not apply missed metric update and binding deletion")
        after = p1.bgp_facts()["ansible_facts"]["bgp_neighbors"].get(peer, {})
        pytest_assert(_supervisor(p1, "pid bgpd") == bgpd_pid, "IS-IS recovery restarted bgpd")
        pytest_assert(after.get("state") == "established", "IS-IS recovery disrupted BGP")
        pytest_assert(after.get("accepted prefixes", 0) >= before.get("accepted prefixes", 0),
                      "BGP route count decreased during IS-IS recovery")
        for counter in counters:
            pytest_assert(after.get(counter) == before[counter], "BGP {} changed".format(counter))
    finally:
        _configure_interfaces(p1, NODE_INTERFACES["P1"])
        pytest_assert(wait_until(90, 3, 0, _fabric_neighbors_up, isis_force10_fabric),
                      "Fabric did not recover after offline update/delete test")
