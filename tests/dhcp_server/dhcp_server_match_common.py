"""Shared helpers for the IPv4 MATCH mode DHCP server tests.

MATCH mode selects a pool from named ``circuit_id`` (Option 82 sub-option 1) and
``option60`` conditions. These helpers discover the topology, build equivalent CLI
and GCU configuration, drive DHCP clients from the PTF and inspect the running Kea
configuration and leases so that tests wait for convergence instead of sleeping.
"""
import binascii
import ipaddress
import json
import logging
import os
import random
import shlex
import shutil
import tempfile
import time
import uuid
from collections import OrderedDict, namedtuple
from contextlib import contextmanager

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from dhcp_server_test_common import DHCP_MESSAGE_TYPE_DISCOVER_NUM, DHCP_MESSAGE_TYPE_OFFER_NUM, \
    DHCP_MESSAGE_TYPE_REQUEST_NUM, DHCP_MESSAGE_TYPE_ACK_NUM, DHCP_MESSAGE_TYPE_NAK_NUM, \
    DHCP_MESSAGE_TYPE_RELEASE_NUM, DHCP_SERVER_CONFIG_TOOL_CLI, DHCP_SERVER_CONFIG_TOOL_GCU, \
    apply_dhcp_server_config_cli, apply_dhcp_server_config_gcu, create_dhcp_client_packet

logger = logging.getLogger(__name__)

MATCH_LEASE_TIME = 600
VENDOR_A = "VendorA"
VENDOR_B = "VendorB"
TEST_MAC_PREFIX = "02:dc"
REPLY_TIMEOUT = 6
NO_REPLY_TIMEOUT = 4
KEA_CONVERGE_TIMEOUT = 60
KEA_CTRL_SOCKET = "/run/kea/kea4-ctrl-socket"
DHCP_SERVER_CONTAINER = "dhcp_server"
KEA_LEASE_FILE = "/var/lib/kea/kea-lease.csv"
KEA_PROGRAM = "dhcp-server-ipv4:kea-dhcp4"
SAVED_CONFIG_DB = "/etc/sonic/config_db.json"
ADDRESS_WINDOW = 200

# Tables in an order that satisfies their references; delete in reverse.
DHCP_SERVER_TABLES = [
    "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS",
    "DHCP_SERVER_IPV4_RANGE",
    "DHCP_SERVER_IPV4_MATCH",
    "DHCP_SERVER_IPV4",
    "DHCP_SERVER_IPV4_PORT",
    "DHCP_SERVER_IPV4_BINDING",
]

KEA_GENERATION_ERROR = r".*Cannot generate Kea candidate config.*"

Port = namedtuple("Port", ["name", "alias", "ptf_index"])


class MatchEnv(object):
    """Topology facts discovered from the DUT for one MATCH test module."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def ip(self, offset):
        """Return the free host address at ``offset`` within the reserved test window."""
        pytest_assert(offset < len(self.hosts), "Address offset {} is outside the test window".format(offset))
        return self.hosts[offset]

    def ip_range(self, first, last):
        return [self.ip(offset) for offset in range(first, last + 1)]

    @property
    def p1(self):
        return self.members[0]

    @property
    def p2(self):
        return self.members[1]

    @property
    def p3(self):
        pytest_require(len(self.members) >= 3, "Test requires a third PTF-connected VLAN member")
        return self.members[2]


def get_running_config(duthost):
    return json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])


def discover_match_env(duthost, tbinfo, vlan_name=None):
    """Discover the VLAN (the first one with IPv4 unless named), its PTF-connected members and free addresses."""
    config = get_running_config(duthost)
    vlan_brief = duthost.get_vlan_brief()
    vlan_name, vlan_info = next(((name, info) for name, info in vlan_brief.items()
                                 if info.get("interface_ipv4") and vlan_name in (None, name)), (None, None))
    pytest_require(vlan_name is not None, "No VLAN with an IPv4 address found")
    vlan_intf = ipaddress.ip_interface(vlan_info["interface_ipv4"][0])
    topology = tbinfo["topo"]["properties"]["topology"]
    disabled = topology.get("disabled_host_interfaces", [])
    connected_idx = [idx for idx in topology.get("host_interfaces", []) if idx not in disabled]
    ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
    port_table = config.get("PORT", {})

    def make_port(name, ptf_index=None):
        return Port(name, port_table.get(name, {}).get("alias", name), ptf_index)

    members = sorted([make_port(m, ptf_indices[m]) for m in vlan_info["members"]
                      if m in ptf_indices and ptf_indices[m] in connected_idx],
                     key=lambda port: port.ptf_index)
    pytest_require(len(members) >= 2, "Test requires at least two PTF-connected VLAN members")
    vlan_member_names = set(key.split("|")[1] for key in config.get("VLAN_MEMBER", {}))
    lag_members = set(key.split("|")[1] for key in config.get("PORTCHANNEL_MEMBER", {}))
    non_members = sorted(name for name in port_table if name not in vlan_member_names)
    # A non-member port that still receives PTF traffic: prefer PortChannel members (they are up).
    ptf_non_members = [make_port(name, idx) for name, idx in sorted(ptf_indices.items(), key=lambda item: item[1])
                       if name in lag_members and name not in vlan_member_names]

    leased = set(lease["ip-address"] for lease in get_kea_leases(duthost)
                 if not lease.get("hw-address", "").startswith(TEST_MAC_PREFIX))
    hosts = [str(host) for host in vlan_intf.network.hosts() if host != vlan_intf.ip]
    env = MatchEnv(
        vlan=vlan_name,
        vlan_id=vlan_name.replace("Vlan", ""),
        gateway=str(vlan_intf.ip),
        netmask=str(vlan_intf.netmask),
        vlan_interface=str(vlan_intf),
        network=vlan_intf.network,
        hostname=config["DEVICE_METADATA"]["localhost"]["hostname"],
        router_mac=duthost.facts["router_mac"],
        members=members,
        px=ptf_non_members[0] if ptf_non_members else None,
        non_member=make_port(non_members[0]) if non_members else None,
        hosts=_find_free_window(hosts, leased, ADDRESS_WINDOW),
    )
    logger.info("MATCH test environment: %s", {k: v for k, v in env.__dict__.items() if k != "hosts"})
    return env


def _find_free_window(hosts, leased, size):
    window = []
    for host in hosts:
        if host in leased:
            window = []
            continue
        window.append(host)
        if len(window) == size:
            return window
    pytest_require(False, "VLAN prefix has no window of {} free host addresses".format(size))


@pytest.fixture(scope="module")
def match_env(duthost, tbinfo):
    return discover_match_env(duthost, tbinfo)


def _fetch_saved_config(duthost, local_dir):
    if not duthost.stat(path=SAVED_CONFIG_DB)["stat"]["exists"]:
        return None
    local_path = os.path.join(local_dir, "config_db.json")
    duthost.fetch(src=SAVED_CONFIG_DB, dest=local_path, flat=True)
    return local_path


def _restore_saved_config(duthost, local_path):
    if local_path is None:
        duthost.file(path=SAVED_CONFIG_DB, state="absent")
        return
    with open(local_path) as saved:
        content = saved.read()
    current = duthost.shell("cat {}".format(SAVED_CONFIG_DB), module_ignore_errors=True)
    if current["rc"] != 0 or current["stdout"] != content.rstrip("\n"):
        logger.info("Restoring saved %s", SAVED_CONFIG_DB)
        duthost.copy(src=local_path, dest=SAVED_CONFIG_DB)


def clean_match_server_config(duthost):
    """Remove every DHCP_SERVER_IPV4* entry, dependents first."""
    keys = duthost.shell("sonic-db-cli CONFIG_DB KEYS 'DHCP_SERVER_IPV4*'")["stdout_lines"]
    for table in reversed(DHCP_SERVER_TABLES):
        for key in keys:
            if key.startswith(table + "|"):
                duthost.shell("sonic-db-cli CONFIG_DB DEL {}".format(shlex.quote(key)))


def write_config_tables(duthost, tables):
    """Write Config DB tables one at a time in dependency order."""
    for table in DHCP_SERVER_TABLES:
        if not tables.get(table):
            continue
        tmpfile = duthost.shell("mktemp")["stdout"]
        try:
            duthost.copy(content=json.dumps({table: tables[table]}, indent=4), dest=tmpfile)
            duthost.shell("sonic-cfggen -j {} --write-to-db".format(tmpfile))
        finally:
            duthost.file(path=tmpfile, state="absent")


@pytest.fixture(scope="module")
def match_config_snapshot(duthost):
    """Back up and restore the DHCP server tables and the saved configuration file.

    The running DHCP server tables and the saved ``config_db.json`` (including its
    absence) are captured independently on the test controller, so scenarios that
    run ``config save`` do not leave the test configuration behind.
    """
    dhcp_tables = get_dhcp_server_config_db(duthost)
    local_dir = tempfile.mkdtemp(prefix="dhcp_match_")
    saved_path = _fetch_saved_config(duthost, local_dir)
    original_pools = get_kea_pools_by_subnet(duthost)
    yield
    try:
        clean_match_server_config(duthost)
        write_config_tables(duthost, dhcp_tables)
        cleanup_test_leases(duthost)
        if original_pools is not None and not wait_until(
                KEA_CONVERGE_TIMEOUT, 2, 0, lambda: get_kea_pools_by_subnet(duthost) == original_pools):
            logger.warning("Kea pools after restore differ from the original %s: %s",
                           original_pools, get_kea_pools_by_subnet(duthost))
    finally:
        _restore_saved_config(duthost, saved_path)
        shutil.rmtree(local_dir, ignore_errors=True)


@pytest.fixture
def match_test_isolation(duthost):
    """Remove test-created leases before and after each scenario."""
    cleanup_test_leases(duthost)
    yield
    cleanup_test_leases(duthost)


@pytest.fixture
def ignore_expected_errors(duthost, loganalyzer):
    """Return a callable that adds regexes to the loganalyzer ignore list for this test."""
    def _ignore(*regexes):
        if loganalyzer and duthost.hostname in loganalyzer:
            loganalyzer[duthost.hostname].ignore_regex.extend(regexes)
    return _ignore


# ---------------------------------------------------------------------------
# Configuration builders
# ---------------------------------------------------------------------------

class MatchConfig(object):
    """A DHCP interface configuration that renders as equivalent CLI commands or a GCU patch."""

    def __init__(self, env, lease_time=MATCH_LEASE_TIME, mode="MATCH", state="enabled"):
        self.env = env
        self.lease_time = lease_time
        self.mode = mode
        self.state = state
        self.options = OrderedDict()
        self.ranges = OrderedDict()
        self.matches = OrderedDict()
        self.bindings = OrderedDict()
        self.port_bindings = OrderedDict()

    def add_option(self, name, option_id, option_type, value):
        self.options[name] = {"id": str(option_id), "type": option_type, "value": value}
        return self

    def add_range(self, name, start, end=None):
        self.ranges[name] = [start, end or start]
        return self

    def add_match(self, name, match_type, value):
        self.matches[name] = {"type": match_type, "value": value}
        return self

    def add_binding(self, name, matches, ips=None, ranges=None):
        pytest_assert(bool(ips) != bool(ranges), "Binding needs exactly one pool form")
        binding = {"matches": list(matches)}
        if ips:
            binding["ips"] = list(ips)
        else:
            binding["ranges"] = list(ranges)
        self.bindings[name] = binding
        return self

    def add_port_binding(self, port, ranges):
        self.port_bindings[port] = list(ranges)
        return self

    def _ordered(self, items, reverse):
        items = list(items)
        return list(reversed(items)) if reverse else items

    def cli_commands(self, reverse=False):
        env = self.env
        cmds = ["config dhcp_server ipv4 add --mode {} --lease_time {} --dup_gw_nm {}".format(
            self.mode, self.lease_time, env.vlan)]
        for name, option in self.options.items():
            cmds.append("config dhcp_server ipv4 option add {} {} {} {}".format(
                name, option["id"], option["type"], shlex.quote(option["value"])))
        if self.options:
            cmds.append("config dhcp_server ipv4 option bind {} {}".format(env.vlan, ",".join(self.options)))
        for name, (start, end) in self.ranges.items():
            cmds.append("config dhcp_server ipv4 range add {} {} {}".format(name, start, end))
        for name, match in self._ordered(self.matches.items(), reverse):
            cmds.append("config dhcp_server ipv4 match add {} --type {} --value {}".format(
                shlex.quote(name), match["type"], shlex.quote(match["value"])))
        for port, ranges in self.port_bindings.items():
            cmds.append("config dhcp_server ipv4 bind {} {} --range {}".format(env.vlan, port, ",".join(ranges)))
        for name in self._ordered(self.bindings, reverse):
            cmds.append(binding_command(env.vlan, name, self.bindings[name]))
        if self.state == "enabled":
            cmds.append("config dhcp_server ipv4 enable {}".format(env.vlan))
        return cmds

    def config_db_tables(self, reverse=False):
        env = self.env
        interface = {"gateway": env.gateway, "netmask": env.netmask, "lease_time": str(self.lease_time),
                     "mode": self.mode, "state": self.state}
        if self.options:
            interface["customized_options"] = list(self.options)
        tables = OrderedDict()
        tables["DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"] = OrderedDict(self.options)
        tables["DHCP_SERVER_IPV4_RANGE"] = OrderedDict((name, {"range": value})
                                                       for name, value in self.ranges.items())
        tables["DHCP_SERVER_IPV4_MATCH"] = OrderedDict(self._ordered(self.matches.items(), reverse))
        tables["DHCP_SERVER_IPV4"] = OrderedDict([(env.vlan, interface)])
        tables["DHCP_SERVER_IPV4_PORT"] = OrderedDict(("{}|{}".format(env.vlan, port), {"ranges": ranges})
                                                      for port, ranges in self.port_bindings.items())
        tables["DHCP_SERVER_IPV4_BINDING"] = OrderedDict(("{}|{}".format(env.vlan, name), self.bindings[name])
                                                         for name in self._ordered(self.bindings, reverse))
        return tables

    def gcu_patch(self, reverse=False):
        return tables_gcu_patch(self.config_db_tables(reverse))

    def apply(self, duthost, config_tool=DHCP_SERVER_CONFIG_TOOL_CLI, reverse=False, wait=True):
        clean_match_server_config(duthost)
        if config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
            apply_dhcp_server_config_gcu(duthost, self.gcu_patch(reverse))
        else:
            apply_dhcp_server_config_cli(duthost, self.cli_commands(reverse))
        if wait:
            wait_for_kea_pools(duthost, self.env, self.expected_pools())

    def expected_pools(self):
        """Kea pools that this configuration should produce on the VLAN subnet."""
        if self.state != "enabled":
            return set()
        if self.mode == "PORT":
            intervals = [tuple(self.ranges[r]) for ranges in self.port_bindings.values() for r in ranges]
        else:
            intervals = []
            for binding in self.bindings.values():
                if "ips" in binding:
                    intervals += [(ip, ip) for ip in binding["ips"]]
                else:
                    intervals += [tuple(self.ranges[r]) for r in binding["ranges"]]
        # Bindings sharing an identical pool produce one Kea pool; distinct pools are never merged.
        return set(intervals)


def json_pointer_escape(key):
    return key.replace("~", "~0").replace("/", "~1")


def tables_gcu_patch(tables):
    patch = []
    for table, entries in tables.items():
        if not entries:
            continue
        patch.append({"op": "add", "path": "/{}".format(table), "value": {}})
        for key, value in entries.items():
            patch.append({"op": "add", "path": "/{}/{}".format(table, json_pointer_escape(key)), "value": value})
    return patch


def apply_match_configs(duthost, cfgs, wait=True):
    """Apply the configurations of several DHCP interfaces in one GCU patch.

    Matches and ranges are global tables, so entries with the same name must be identical.
    """
    merged = OrderedDict((table, OrderedDict()) for table in DHCP_SERVER_TABLES)
    for cfg in cfgs:
        for table, entries in cfg.config_db_tables().items():
            for key, value in entries.items():
                pytest_assert(merged[table].get(key, value) == value,
                              "Conflicting {} entry {} across configurations".format(table, key))
                merged[table][key] = value
    clean_match_server_config(duthost)
    apply_dhcp_server_config_gcu(duthost, tables_gcu_patch(merged))
    if wait:
        for cfg in cfgs:
            wait_for_kea_pools(duthost, cfg.env, cfg.expected_pools())


def _vlan_gcu_patch(vlan, vlan_id, interface, members, from_vlan, adding):
    """Patch that moves ``members`` from ``from_vlan`` to a new ``vlan`` (or back when not ``adding``)."""
    vlan_ops = [("/VLAN/{}".format(vlan), {"vlanid": vlan_id}),
                ("/VLAN_INTERFACE/{}".format(vlan), {}),
                ("/VLAN_INTERFACE/{}".format(json_pointer_escape("{}|{}".format(vlan, interface))), {})]
    old_members = ["/VLAN_MEMBER/{}|{}".format(from_vlan, member) for member in members]
    new_members = ["/VLAN_MEMBER/{}|{}".format(vlan, member) for member in members]
    untagged = {"tagging_mode": "untagged"}
    if adding:
        return ([{"op": "remove", "path": path} for path in old_members] +
                [{"op": "add", "path": path, "value": value} for path, value in vlan_ops] +
                [{"op": "add", "path": path, "value": untagged} for path in new_members])
    return ([{"op": "remove", "path": path} for path in new_members] +
            [{"op": "remove", "path": path} for path, _ in reversed(vlan_ops)] +
            [{"op": "add", "path": path, "value": untagged} for path in old_members])


@contextmanager
def second_vlan(duthost, tbinfo, env, vlan="Vlan4001", interface="192.168.200.1/24", member_count=3):
    """Move the last PTF-connected members of ``env.vlan`` into a new VLAN with its own prefix.

    The original VLAN keeps its other members, IP addresses and relay settings, so P1 and P2
    of ``env`` are unaffected. Yields (refreshed env of the original VLAN, env of the new VLAN).
    The DHCP server tables are cleared on exit, because they may reference the new VLAN or its members.
    """
    new_net = ipaddress.ip_interface(interface).network
    for name in duthost.shell("sonic-db-cli CONFIG_DB KEYS '*INTERFACE|*|*'")["stdout_lines"]:
        address = name.split("|")[-1]
        if "." in address:
            pytest_require(not ipaddress.ip_interface(address).network.overlaps(new_net),
                           "{} overlaps existing interface address {}".format(interface, name))
    pytest_require(len(env.members) >= member_count + 2, "Not enough PTF-connected members to split the VLAN")
    moved = [port.name for port in env.members[-member_count:]]
    for port in moved:
        mode = duthost.shell("sonic-db-cli CONFIG_DB HGET 'VLAN_MEMBER|{}|{}' tagging_mode".format(
            env.vlan, port))["stdout"].strip()
        pytest_require(mode == "untagged", "{} is not an untagged member of {}".format(port, env.vlan))
    vlan_id = vlan.replace("Vlan", "")
    apply_dhcp_server_config_gcu(duthost, _vlan_gcu_patch(vlan, vlan_id, interface, moved, env.vlan, True))
    try:
        pytest_assert(wait_until(60, 2, 0, lambda: vlan in duthost.get_vlan_brief()),
                      "{} was not created".format(vlan))
        yield discover_match_env(duthost, tbinfo, env.vlan), discover_match_env(duthost, tbinfo, vlan)
    finally:
        clean_match_server_config(duthost)
        apply_dhcp_server_config_gcu(duthost, _vlan_gcu_patch(vlan, vlan_id, interface, moved, env.vlan, False))


def binding_command(vlan, name, binding, verb="add"):
    cmd = "config dhcp_server ipv4 binding {} {} {} --match {}".format(
        verb, vlan, shlex.quote(name), ",".join(binding["matches"]))
    if "ranges" in binding:
        return cmd + " --range {}".format(",".join(binding["ranges"]))
    return cmd + " {}".format(",".join(binding["ips"]))


def baseline_config(env, **kwargs):
    """The baseline bindings from the test plan."""
    cfg = MatchConfig(env, **kwargs)
    cfg.add_range("any_p1_range", env.ip(100), env.ip(104))
    cfg.add_match("port_p1", "circuit_id", env.p1.alias)
    cfg.add_match("port_p2", "circuit_id", env.p2.alias)
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_b", "option60", VENDOR_B)
    cfg.add_binding("a_on_p1", ["port_p1", "vendor_a"], ips=[env.ip(21)])
    cfg.add_binding("b_on_p1", ["port_p1", "vendor_b"], ips=[env.ip(22)])
    cfg.add_binding("any_on_p1", ["port_p1"], ranges=["any_p1_range"])
    cfg.add_binding("any_on_p2", ["port_p2"], ips=[env.ip(30)])
    return cfg


def run_cli(duthost, cmd):
    """Run a command that is expected to succeed."""
    result = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, "Command failed: {}\n{}{}".format(cmd, result["stdout"], result["stderr"]))
    return result


def run_cli_expect_failure(duthost, cmd, expected_error):
    """Run a command that must fail and report ``expected_error``."""
    result = duthost.shell(cmd, module_ignore_errors=True)
    output = result["stdout"] + result["stderr"]
    pytest_assert(result["rc"] != 0, "Command unexpectedly succeeded: {}\n{}".format(cmd, output))
    pytest_assert(expected_error in output, "Command '{}' did not report '{}': {}".format(cmd, expected_error, output))
    return output


def get_dhcp_server_config_db(duthost):
    """Return the DHCP_SERVER_IPV4* tables from the running Config DB."""
    config = get_running_config(duthost)
    return {table: config[table] for table in DHCP_SERVER_TABLES if table in config}


def hset_config_db(duthost, key, fields):
    args = " ".join("{} {}".format(shlex.quote(field), shlex.quote(value)) for field, value in fields.items())
    duthost.shell("sonic-db-cli CONFIG_DB HSET {} {}".format(shlex.quote(key), args))


def del_config_db(duthost, key):
    duthost.shell("sonic-db-cli CONFIG_DB DEL {}".format(shlex.quote(key)))


# ---------------------------------------------------------------------------
# Kea inspection
# ---------------------------------------------------------------------------

def kea_command(duthost, command, arguments=None):
    payload = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    result = duthost.shell("echo {} | docker exec -i {} socat -t 5 - UNIX-CONNECT:{}".format(
        shlex.quote(json.dumps(payload)), DHCP_SERVER_CONTAINER, KEA_CTRL_SOCKET), module_ignore_errors=True)
    if result["rc"] != 0 or not result["stdout"].strip():
        return None
    try:
        response = json.loads(result["stdout"])
    except ValueError:
        return None
    return response[0] if isinstance(response, list) else response


def get_kea_dhcp4_config(duthost):
    response = kea_command(duthost, "config-get")
    if not response or response.get("result") != 0:
        return None
    return response["arguments"]["Dhcp4"]


def _normalize_pool(pool):
    pool = pool.replace(" ", "")
    if "/" in pool:
        network = ipaddress.ip_network(pool, strict=False)
        return str(network[0]), str(network[-1])
    start, end = pool.split("-")
    return start, end


def get_kea_pools_by_subnet(duthost):
    """Return {subnet: {(start, end): client_class}} from the running Kea configuration."""
    dhcp4 = get_kea_dhcp4_config(duthost)
    if dhcp4 is None:
        return None
    return {subnet["subnet"]: {_normalize_pool(pool["pool"]): pool.get("client-class")
                               for pool in subnet.get("pools", [])}
            for subnet in dhcp4.get("subnet4", [])}


def get_kea_pools(duthost, env):
    by_subnet = get_kea_pools_by_subnet(duthost)
    if by_subnet is None:
        return None
    return by_subnet.get(str(env.network), {})


def wait_for_kea_pools(duthost, env, expected, timeout=KEA_CONVERGE_TIMEOUT):
    """Wait until the VLAN subnet in running Kea serves exactly ``expected`` pools."""
    expected = set(tuple(pool) for pool in expected)
    state = {}

    def _converged():
        state["pools"] = get_kea_pools(duthost, env)
        return state["pools"] is not None and set(state["pools"]) == expected

    pytest_assert(wait_until(timeout, 2, 0, _converged), "Kea pools did not converge to {}; running pools: {}".format(
        sorted(expected), state.get("pools")))
    return state["pools"]


def get_kea_config_hash(duthost):
    response = kea_command(duthost, "config-get")
    if not response or response.get("result") != 0:
        return None
    return response["arguments"].get("hash")


def get_kea_match_state(duthost):
    """Normalized classes and pools of the running Kea configuration, for equality checks."""
    dhcp4 = get_kea_dhcp4_config(duthost)
    if dhcp4 is None:
        return None
    classes = sorted((c["name"], c.get("test", "")) for c in dhcp4.get("client-classes", []))
    pools = sorted((subnet["subnet"], _normalize_pool(pool["pool"]), pool.get("client-class") or "")
                   for subnet in dhcp4.get("subnet4", []) for pool in subnet.get("pools", []))
    return {"classes": classes, "pools": pools}


def get_kea_class_test(duthost, class_name):
    for client_class in get_kea_dhcp4_config(duthost).get("client-classes", []):
        if client_class["name"] == class_name:
            return client_class.get("test", "")
    return None


def get_kea_leases(duthost):
    """Return the current Kea leases parsed from the memfile lease database.

    The memfile is read so that the helpers also work on images whose Kea does not load
    the lease_cmds hook. It appends one row per lease change (a release or deletion is a row with
    a zero lifetime), so the last row for an address is its current state. Files left
    by lease file cleanup (LFC) are read first, in the order Kea itself loads them.
    """
    result = duthost.shell(
        "docker exec {} sh -c 'cd {} && if [ -f {f}.completed ]; then cat {f}.completed; "
        "else cat {f}.2 {f}.1 2>/dev/null; fi; cat {f}'".format(
            DHCP_SERVER_CONTAINER, os.path.dirname(KEA_LEASE_FILE), f=os.path.basename(KEA_LEASE_FILE)),
        module_ignore_errors=True)
    leases = {}
    for line in result["stdout_lines"]:
        fields = line.split(",")
        if len(fields) < 10 or fields[0] == "address":
            continue
        valid_lft, expire = int(fields[3]), int(fields[4])
        leases[fields[0]] = {"ip-address": fields[0], "hw-address": fields[1], "valid-lft": valid_lft,
                             "cltt": expire - valid_lft, "subnet-id": int(fields[5]), "state": int(fields[9])}
    return list(leases.values())


def get_kea_lease(duthost, ip):
    for lease in get_kea_leases(duthost):
        if lease["ip-address"] == ip:
            return lease
    return None


def kea_lease_active(duthost, ip, mac=None):
    lease = get_kea_lease(duthost, ip)
    return (lease is not None and lease["state"] == 0 and lease["valid-lft"] > 0 and
            lease["cltt"] + lease["valid-lft"] > time.time() and (mac is None or lease["hw-address"] == mac))


def wait_for_kea_lease(duthost, ip, mac=None, present=True, timeout=15):
    pytest_assert(wait_until(timeout, 1, 0, lambda: kea_lease_active(duthost, ip, mac) == present),
                  "Kea lease for {} is {}expected to be active".format(ip, "" if present else "not "))


def remaining_lease_seconds(duthost, ip):
    lease = get_kea_lease(duthost, ip)
    if not lease:
        return 0
    return lease["cltt"] + lease["valid-lft"] - int(time.time())


def cleanup_test_leases(duthost):
    """Delete only leases created by these tests from Kea and State DB.

    Kea without the lease_cmds hook has no ``lease4-del``, so kea-dhcp4 is stopped, the test
    rows are removed from the memfile and kea-dhcp4 is started again. This happens only
    when test leases exist, and only between scenarios, never inside one.
    """
    if any(lease["hw-address"].startswith(TEST_MAC_PREFIX) for lease in get_kea_leases(duthost)):
        lease_dir, lease_file = os.path.dirname(KEA_LEASE_FILE), os.path.basename(KEA_LEASE_FILE)
        script = ("supervisorctl stop {prog} > /dev/null && cd {dir} && "
                  "for f in {file} {file}.1 {file}.2 {file}.completed; do "
                  "[ -f $f ] && grep -v ',{mac}' $f > $f.tmp; [ -f $f.tmp ] && cat $f.tmp > $f && rm -f $f.tmp; "
                  "done; supervisorctl start {prog} > /dev/null").format(
                      prog=KEA_PROGRAM, dir=lease_dir, file=lease_file, mac=TEST_MAC_PREFIX)
        duthost.shell("docker exec {} bash -c {}".format(DHCP_SERVER_CONTAINER, shlex.quote(script)))
        pytest_assert(wait_until(30, 1, 0, lambda: get_kea_config_hash(duthost) is not None),
                      "kea-dhcp4 did not come back after lease cleanup")
        pytest_assert(not any(lease["hw-address"].startswith(TEST_MAC_PREFIX) for lease in get_kea_leases(duthost)),
                      "Test leases are still present after cleanup")
    duthost.shell("for k in $(sonic-db-cli STATE_DB KEYS 'DHCP_SERVER_IPV4_LEASE|*|{}:*'); do "
                  "sonic-db-cli STATE_DB DEL \"$k\" > /dev/null; done".format(TEST_MAC_PREFIX),
                  module_ignore_errors=True)


def get_state_db_lease(duthost, vlan, mac):
    lines = duthost.shell("sonic-db-cli STATE_DB HGETALL 'DHCP_SERVER_IPV4_LEASE|{}|{}'".format(vlan, mac))["stdout"]
    lines = lines.strip()
    if not lines or lines == "{}":
        return {}
    return json.loads(lines.replace("'", '"'))


def get_state_db_leases(duthost, vlan):
    """Return {mac: ip} of the State DB leases on ``vlan``."""
    leases = {}
    for key in duthost.shell("sonic-db-cli STATE_DB KEYS 'DHCP_SERVER_IPV4_LEASE|{}|*'".format(vlan))["stdout_lines"]:
        mac = key.split("|")[-1]
        leases[mac] = get_state_db_lease(duthost, vlan, mac).get("ip")
    return leases


def get_kea_subnet_leases(duthost, subnet_id):
    """Return {mac: ip} of the leases that Kea holds in ``subnet_id``, using the lease_cmds hook."""
    response = kea_command(duthost, "lease4-get-all", {"subnets": [int(subnet_id)]})
    pytest_assert(response is not None and response.get("result") in (0, 3),
                  "lease4-get-all failed (is the lease_cmds hook loaded?): {}".format(response))
    return {lease["hw-address"]: lease["ip-address"] for lease in response.get("arguments", {}).get("leases", [])}


def wait_for_state_db_lease(duthost, vlan, mac, present=True, timeout=20):
    """Wait for the State DB lease of ``mac`` to appear (or disappear) and return it."""
    state = {}

    def _check():
        state["lease"] = get_state_db_lease(duthost, vlan, mac)
        return bool(state["lease"]) == present

    pytest_assert(wait_until(timeout, 1, 0, _check), "State DB lease for {} on {} is {}expected to exist: {}".format(
        mac, vlan, "" if present else "not ", state.get("lease")))
    return state["lease"]


def verify_client_lease(duthost, env, client, ip, lease_time=MATCH_LEASE_TIME):
    """Correlate an ACKed address with the Kea lease and the State DB lease."""
    wait_for_kea_lease(duthost, ip, mac=client.mac)
    lease = wait_for_state_db_lease(duthost, env.vlan, client.mac)
    pytest_assert(lease.get("ip") == ip, "State DB lease for {} has ip {}, expected {}".format(
        client.mac, lease.get("ip"), ip))
    pytest_assert(int(lease["lease_end"]) - int(lease["lease_start"]) == lease_time,
                  "State DB lease for {} has unexpected lifetime: {}".format(client.mac, lease))
    return lease


def get_dhcp_server_pids(duthost):
    """Return (dhcpservd, kea-dhcp4) PIDs to prove that changes apply without a restart."""
    return tuple(duthost.shell("docker exec {} supervisorctl pid {}".format(DHCP_SERVER_CONTAINER, program),
                               module_ignore_errors=True)["stdout"].strip()
                 for program in ("dhcp-server-ipv4:dhcpservd", "dhcp-server-ipv4:kea-dhcp4"))


# ---------------------------------------------------------------------------
# Syslog helpers
# ---------------------------------------------------------------------------

def add_syslog_marker(duthost):
    marker = "dhcp_match_test_{}".format(uuid.uuid4().hex)
    duthost.shell("logger -t dhcp_match_test {}".format(marker))
    return marker


def wait_for_syslog(duthost, marker, text, timeout=30):
    """Wait for ``text`` to appear in syslog after ``marker`` and return the matching lines."""
    cmd = "sudo awk -v m={} 'f; index($0, m) {{f=1}}' /var/log/syslog | grep -F -- {}".format(
        shlex.quote(marker), shlex.quote(text))
    pytest_assert(wait_until(timeout, 2, 0, lambda: duthost.shell(cmd, module_ignore_errors=True)["rc"] == 0),
                  "Did not find '{}' in syslog".format(text))
    return duthost.shell(cmd, module_ignore_errors=True)["stdout_lines"]


# ---------------------------------------------------------------------------
# DHCP client helpers
# ---------------------------------------------------------------------------

def new_client_mac():
    return "{}:{:02x}:{:02x}:{:02x}:{:02x}".format(TEST_MAC_PREFIX, *[random.randint(0, 255) for _ in range(4)])


def new_xid():
    return random.randint(1, 0xffffffff)


def dhcp_option(pkt, name):
    for option in pkt[scapy.DHCP].options:
        if isinstance(option, tuple) and option[0] == name:
            return option[1] if len(option) == 2 else option[1:]
    return None


def parse_relay_agent_info(raw):
    """Return {sub_option: bytes} from an Option 82 payload."""
    raw = bytes(raw)
    sub_options = {}
    index = 0
    while index + 2 <= len(raw):
        code, length = raw[index], raw[index + 1]
        sub_options[code] = raw[index + 2:index + 2 + length]
        index += 2 + length
    return sub_options


def validate_reply(env, pkt, msg_type, expected_ip=None, lease_time=MATCH_LEASE_TIME, options=None):
    """Validate message type, address, netmask, router, lease time and Option 54."""
    got_type = dhcp_option(pkt, "message-type")
    pytest_assert(got_type == msg_type, "Expected DHCP message type {}, got {}: {}".format(
        msg_type, got_type, pkt.summary()))
    yiaddr = pkt[scapy.BOOTP].yiaddr
    if expected_ip is not None:
        candidates = [expected_ip] if isinstance(expected_ip, str) else list(expected_ip)
        pytest_assert(yiaddr in candidates, "Assigned {} is not in expected {}".format(yiaddr, candidates))
    pytest_assert(dhcp_option(pkt, "subnet_mask") == env.netmask,
                  "Unexpected netmask {}".format(dhcp_option(pkt, "subnet_mask")))
    pytest_assert(dhcp_option(pkt, "router") == env.gateway, "Unexpected router {}".format(dhcp_option(pkt, "router")))
    pytest_assert(dhcp_option(pkt, "server_id") == env.gateway,
                  "Option 54 {} is not the VLAN SVI {}".format(dhcp_option(pkt, "server_id"), env.gateway))
    if lease_time is not None:
        pytest_assert(dhcp_option(pkt, "lease_time") == lease_time,
                      "Unexpected lease time {}".format(dhcp_option(pkt, "lease_time")))
    for option_id, value in (options or {}).items():
        pytest_assert(dhcp_option(pkt, int(option_id)) == value, "Option {} is {!r}, expected {!r}".format(
            option_id, dhcp_option(pkt, int(option_id)), value))


def expect_nak(reply, what):
    pytest_assert(reply is not None and dhcp_option(reply, "message-type") == DHCP_MESSAGE_TYPE_NAK_NUM,
                  "{}: expected NAK, got {}".format(what, reply.summary() if reply else "no reply"))


def expect_ack(env, reply, ip, what, lease_time=MATCH_LEASE_TIME):
    pytest_assert(reply is not None, "{}: expected ACK for {}, got no reply".format(what, ip))
    validate_reply(env, reply, DHCP_MESSAGE_TYPE_ACK_NUM, ip, lease_time)


class DhcpClient(object):
    """A DHCP client injected from a PTF port with a unique, locally administered test MAC.

    The relay may broadcast replies to every VLAN member, so replies are correlated by
    transaction ID and client hardware address rather than by receiving port.
    """

    def __init__(self, env, ptfadapter, port, opt60=None, mac=None):
        self.env = env
        self.ptfadapter = ptfadapter
        self.port = port
        self.opt60 = opt60
        self.mac = mac or new_client_mac()
        self.mac_bytes = binascii.unhexlify(self.mac.replace(":", ""))
        self.ip = None

    def _opt60(self, opt60):
        value = self.opt60 if opt60 is Ellipsis else opt60
        return value.encode("utf-8") if isinstance(value, str) else value

    def _packet(self, msg_type, xid, opt60, requested=None, server_id=None, ciaddr="0.0.0.0"):
        options = []
        if requested:
            options.append(("requested_addr", requested))
        if server_id:
            options.append(("server_id", server_id))
        if opt60 is not None:
            options.append(("vendor_class_id", opt60))
        return create_dhcp_client_packet(self.mac, msg_type, options, xid=xid, ciaddr=ciaddr)

    def _reply_filter(self, xid):
        def _is_reply(raw):
            try:
                pkt = scapy.Ether(raw)
            except Exception:
                return False
            return (scapy.BOOTP in pkt and pkt[scapy.BOOTP].op == 2 and pkt[scapy.BOOTP].xid == xid and
                    bytes(pkt[scapy.BOOTP].chaddr)[:6] == self.mac_bytes)
        return _is_reply

    def exchange(self, pkt, xid, timeout=REPLY_TIMEOUT):
        """Send ``pkt`` and return the server reply, or None if none arrives within ``timeout``."""
        self.ptfadapter.dataplane.flush()
        testutils.send_packet(self.ptfadapter, self.port.ptf_index, pkt)
        result = self.ptfadapter.dataplane.poll(device_number=0, timeout=timeout, filters=[self._reply_filter(xid)])
        if result.packet is None:
            return None
        reply = scapy.Ether(result.packet)
        logger.info("Client %s on %s got %s", self.mac, self.port.name, reply.summary())
        return reply

    def discover(self, opt60=Ellipsis, timeout=REPLY_TIMEOUT):
        xid = new_xid()
        return self.exchange(self._packet(DHCP_MESSAGE_TYPE_DISCOVER_NUM, xid, self._opt60(opt60)), xid, timeout)

    def request(self, ip, opt60=Ellipsis):
        """SELECTING-state REQUEST: broadcast with requested address and server identifier."""
        xid = new_xid()
        pkt = self._packet(DHCP_MESSAGE_TYPE_REQUEST_NUM, xid, self._opt60(opt60), requested=ip,
                           server_id=self.env.gateway)
        return self.exchange(pkt, xid)

    def init_reboot(self, ip, opt60=Ellipsis):
        """INIT-REBOOT REQUEST: broadcast with requested address and no server identifier."""
        xid = new_xid()
        return self.exchange(self._packet(DHCP_MESSAGE_TYPE_REQUEST_NUM, xid, self._opt60(opt60), requested=ip), xid)

    def renew(self, ip, opt60=Ellipsis):
        """RENEWING-state REQUEST: unicast to the gateway with ``ciaddr`` set."""
        xid = new_xid()
        pkt = self._packet(DHCP_MESSAGE_TYPE_REQUEST_NUM, xid, self._opt60(opt60), ciaddr=ip)
        pkt[scapy.Ether].dst = self.env.router_mac
        pkt[scapy.IP].src = ip
        pkt[scapy.IP].dst = self.env.gateway
        return self.exchange(pkt, xid)

    def release(self, duthost, ip=None):
        """Send RELEASE and wait until Kea no longer holds an active lease for the address."""
        ip = ip or self.ip
        xid = new_xid()
        pkt = self._packet(DHCP_MESSAGE_TYPE_RELEASE_NUM, xid, None, server_id=self.env.gateway, ciaddr=ip)
        testutils.send_packet(self.ptfadapter, self.port.ptf_index, pkt)
        wait_for_kea_lease(duthost, ip, present=False)
        if ip == self.ip:
            self.ip = None

    def expect_offer(self, expected, opt60=Ellipsis, lease_time=MATCH_LEASE_TIME, options=None):
        """DISCOVER and assert an OFFER from ``expected`` (an address or a collection)."""
        reply = self.discover(opt60)
        pytest_assert(reply is not None, "Client {} on {} (opt60={!r}) got no OFFER, expected {}".format(
            self.mac, self.port.name, self._opt60(opt60), expected))
        validate_reply(self.env, reply, DHCP_MESSAGE_TYPE_OFFER_NUM, expected, lease_time, options)
        return reply[scapy.BOOTP].yiaddr

    def expect_no_offer(self, opt60=Ellipsis):
        reply = self.discover(opt60, timeout=NO_REPLY_TIMEOUT)
        pytest_assert(reply is None, "Client {} on {} (opt60={!r}) unexpectedly got {}".format(
            self.mac, self.port.name, self._opt60(opt60), reply.summary() if reply else None))

    def dora(self, expected, opt60=Ellipsis, lease_time=MATCH_LEASE_TIME, options=None):
        """Complete DISCOVER/OFFER/REQUEST/ACK and return the leased address."""
        ip = self.expect_offer(expected, opt60, lease_time, options)
        ack = self.request(ip, opt60)
        pytest_assert(ack is not None, "No reply to REQUEST for {} from {}".format(ip, self.mac))
        validate_reply(self.env, ack, DHCP_MESSAGE_TYPE_ACK_NUM, ip, lease_time, options)
        self.ip = ip
        return ip


def learn_mac_on_port(ptfadapter, port, mac):
    """Make the DUT FDB learn ``mac`` behind ``port`` using a harmless broadcast frame."""
    pkt = testutils.simple_udp_packet(eth_dst="ff:ff:ff:ff:ff:ff", eth_src=mac, ip_src="0.0.0.0",
                                      ip_dst="255.255.255.255", udp_sport=12345, udp_dport=12346)
    testutils.send_packet(ptfadapter, port.ptf_index, pkt)


def fdb_port_of(duthost, mac):
    for line in duthost.shell("show mac", module_ignore_errors=True)["stdout_lines"]:
        fields = line.split()
        if len(fields) >= 4 and fields[2].lower() == mac.lower():
            return fields[3]
    return None


# ---------------------------------------------------------------------------
# Show output parsing
# ---------------------------------------------------------------------------

def parse_grid_table(output):
    """Parse a tabulate ``grid`` table into dicts; multi-line cells are joined with newlines.

    Columns are sliced by the ``+`` positions of the border line, because cell values
    such as ``Vlan1000|Ethernet4`` may themselves contain ``|``.
    """
    header = None
    rows = []
    current = None
    spans = None
    for line in output.splitlines():
        if line.startswith("+"):
            if spans is None:
                edges = [index for index, char in enumerate(line) if char == "+"]
                spans = list(zip(edges[:-1], edges[1:]))
            if current is not None:
                rows.append(current)
                current = None
            continue
        if not line.startswith("|") or spans is None:
            continue
        cells = [line[start + 1:end].strip() for start, end in spans]
        if header is None:
            header = cells
        elif current is None:
            current = [[cell] if cell else [] for cell in cells]
        else:
            for column, cell in enumerate(cells):
                if cell:
                    current[column].append(cell)
    return [dict(zip(header, ["\n".join(cell) for cell in row])) for row in rows]


def show_table(duthost, cmd):
    return parse_grid_table(duthost.shell(cmd)["stdout"])
