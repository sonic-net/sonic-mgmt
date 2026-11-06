"""IS-IS CLI integration tests for the community Force10 seven-node topology."""

import logging
import re

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


def _run(node, command, check=True):
    result = node.shell(command, module_ignore_errors=True)
    if check:
        pytest_assert(result.get("rc", 1) == 0,
                      "Command failed on {}: {}\n{}".format(
                          getattr(node, "hostname", "node"), command, result))
    return result.get("stdout", "").strip()


def _config_value(node, table_key, field):
    return _run(node, "sudo sonic-db-cli CONFIG_DB HGET '{}' {}".format(table_key, field))


def _configure_global(node, net):
    _run(node, "sudo config isis enable")
    _run(node, "sudo config isis net {}".format(net))
    _run(node, "sudo config isis level level-2")
    _run(node, "sudo config isis hostname enable")
    _run(node, "sudo config isis timer lsp-mtu 1400")
    _run(node, "sudo config isis timer lsp-refresh 900")
    _run(node, "sudo config isis timer lsp-lifetime 1200")


def _configure_interfaces(node, interfaces):
    for interface in interfaces:
        _run(node, "sudo config interface isis enable {}".format(interface))
        _run(node, "sudo config interface isis circuit-type {} p2p".format(interface))
        _run(node, "sudo config interface isis metric {} 10".format(interface))

    _run(node, "sudo config interface isis enable Loopback0")
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


def _route_is_installed(node, prefix):
    output = _run(node, "sudo show ip route isis {}".format(prefix), check=False)
    return prefix in output and "via" in output


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

    try:
        # Remove stale IS-IS state from a previous interrupted run.
        for name, node in nodes.items():
            for interface in NODE_INTERFACES[name] + ["Loopback0"]:
                _run(node, "sudo config interface isis disable {}".format(interface))
            _run(node, "sudo config isis disable")

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
                _run(node, "sudo config interface isis disable {}".format(interface), check=False)
            _run(node, "sudo config isis disable", check=False)


def test_isis_cli_programs_configdb(isis_force10_fabric):
    """Verify global, timer, interface, and passive settings written by config CLI."""
    p1 = isis_force10_fabric["P1"]
    expected = [
        ("ISIS_GLOBALS|default", "enabled", "true"),
        ("ISIS_GLOBALS|default", "net_title", NODE_NETS["P1"]),
        ("ISIS_GLOBALS|default", "level", "level-2"),
        ("ISIS_GLOBALS|default", "dynamic_hostname", "true"),
        ("ISIS_GLOBALS_TIMERS|default", "lsp_mtu", "1400"),
        ("ISIS_GLOBALS_TIMERS|default", "lsp_refresh_interval", "900"),
        ("ISIS_GLOBALS_TIMERS|default", "lsp_lifetime", "1200"),
        ("ISIS_INTERFACE|Ethernet112", "enabled", "true"),
        ("ISIS_INTERFACE|Ethernet112", "circuit_type", "p2p"),
        ("ISIS_INTERFACE|Ethernet112", "metric", "10"),
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

    prefix = "100.1.0.31/32"  # PE3 Loopback0 from the community 7nodes_force10 profile.
    pytest_assert(wait_until(120, 5, 0, _route_is_installed, nodes["P1"], prefix),
                  "P1 did not learn PE3 Loopback0 through IS-IS")


def test_isis_cli_interface_disable_enable(isis_force10_fabric):
    """Verify removal and enable-only binding before restoring the p2p attributes."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config interface isis disable Ethernet112")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS 'ISIS_INTERFACE|Ethernet112'") == "0",
                      "Interface disable left an IS-IS row behind")
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"] - 1),
                      "Disabling IS-IS on Ethernet112 did not remove one P1 adjacency")

        _run(p1, "sudo config interface isis enable Ethernet112")
        pytest_assert(wait_until(30, 2, 0, _interface_is_bound, p1, "Ethernet112"),
                      "An enable-only row did not bind Ethernet112 in FRR")
        # LAN is the default; restore p2p before expecting this peer to converge.
        _run(p1, "sudo config interface isis circuit-type Ethernet112 p2p")
        _run(p1, "sudo config interface isis metric Ethernet112 10")
        pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                      "Enabling IS-IS on Ethernet112 did not restore the P1 adjacency")
    finally:
        _configure_interfaces(p1, NODE_INTERFACES["P1"])


def _interface_is_bound(node, interface):
    output = _run(node, "sudo show isis interface")
    return bool(re.search(r"\b{}\b".format(re.escape(interface)), output))


def test_isis_cli_global_disable_enable(isis_force10_fabric):
    """Require interface cleanup before deleting and rebuilding a process."""
    p1 = isis_force10_fabric["P1"]
    blocked = p1.shell("sudo config isis disable", module_ignore_errors=True)
    pytest_assert(blocked.get("rc", 0) != 0 and
                  "Disable IS-IS on interface" in blocked.get("stdout", "") + blocked.get("stderr", ""),
                  "Process deletion should refuse while IS-IS interface rows remain")
    pytest_assert(_config_value(p1, "ISIS_GLOBALS|default", "enabled") == "true",
                  "Rejected process deletion changed its enable state")
    try:
        for interface in NODE_INTERFACES["P1"] + ["Loopback0"]:
            _run(p1, "sudo config interface isis disable {}".format(interface))
        _run(p1, "sudo config isis disable")
        for key in ("ISIS_GLOBALS|default", "ISIS_GLOBALS_TIMERS|default"):
            pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB EXISTS '{}'".format(key)) == "0",
                          "Process deletion left {} behind".format(key))
        pytest_assert(wait_until(60, 3, 0, _neighbor_count_is, p1, 0),
                      "Global IS-IS disable did not clear P1 adjacencies")
    finally:
        _configure_global(p1, NODE_NETS["P1"])
        _configure_interfaces(p1, NODE_INTERFACES["P1"])
    pytest_assert(wait_until(90, 3, 0, _neighbor_count_is, p1, EXPECTED_NEIGHBORS["P1"]),
                  "Global IS-IS re-enable did not restore P1 adjacencies")


def test_isis_cli_reset_and_repeated_enable(isis_force10_fabric):
    """Reset removes fields, preserves siblings and supports subsequent timer commands."""
    p1 = isis_force10_fabric["P1"]
    try:
        _run(p1, "sudo config isis enable")
        pytest_assert(_config_value(p1, "ISIS_GLOBALS|default", "net_title") == NODE_NETS["P1"],
                      "Repeated enable discarded the configured NET")
        _run(p1, "sudo config interface isis metric Ethernet112 30")
        _run(p1, "sudo config interface isis enable Ethernet112")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|Ethernet112", "metric") == "30",
                      "Repeated interface enable discarded the metric")
        _run(p1, "sudo config interface isis reset Ethernet112 metric")
        pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB HEXISTS 'ISIS_INTERFACE|Ethernet112' metric") == "0",
                      "Metric reset did not remove the field")
        pytest_assert(_config_value(p1, "ISIS_INTERFACE|Ethernet112", "circuit_type") == "p2p",
                      "Metric reset discarded the circuit type")

        _run(p1, "sudo config isis timer lsp-lifetime 1500")
        _run(p1, "sudo config isis timer lsp-refresh 1000")
        rejected = p1.shell("sudo config isis reset lsp-lifetime", module_ignore_errors=True)
        pytest_assert(rejected.get("rc", 0) != 0,
                      "Reset accepted a lifetime smaller than refresh + 300")
        _run(p1, "sudo config isis reset lsp-refresh")
        _run(p1, "sudo config isis reset lsp-lifetime")
        for field in ("lsp_refresh_interval", "lsp_lifetime"):
            pytest_assert(_run(p1, "sudo sonic-db-cli CONFIG_DB HEXISTS 'ISIS_GLOBALS_TIMERS|default' {}".
                               format(field)) == "0", "Reset did not remove {}".format(field))
        pytest_assert(_config_value(p1, "ISIS_GLOBALS_TIMERS|default", "lsp_mtu") == "1400",
                      "Timer reset discarded the MTU")
        _run(p1, "sudo config isis timer lsp-refresh 900")
        _run(p1, "sudo config isis timer lsp-lifetime 1200")
    finally:
        # Set lifetime first so restoration also works after a failed reset.
        _run(p1, "sudo config isis timer lsp-lifetime 1500")
        _configure_global(p1, NODE_NETS["P1"])
        _configure_interfaces(p1, NODE_INTERFACES["P1"])
    pytest_assert(wait_until(90, 3, 0, _fabric_neighbors_up, isis_force10_fabric),
                  "IS-IS adjacencies did not recover after reset validation")
