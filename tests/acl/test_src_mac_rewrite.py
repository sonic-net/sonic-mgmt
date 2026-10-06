"""
Tests ACL to modify inner source MAC in VXLAN packets in SONiC.

This test suite validates the INNER_SRC_MAC_REWRITE_ACTION functionality
for ACL rules that can rewrite the inner source MAC address of VXLAN-encapsulated packets.
"""

import os
import time
import logging
import pytest
import json
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.common.plugins.test_completeness import CompletenessLevel
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

ecmp_utils = Ecmp_Utils()

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),  # Only run on T0 testbed
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')  # Only run on Cisco-8000 ASICs that support INNER_SRC_MAC_REWRITE_ACTION
]

# Test configuration constants
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
TMP_DIR = '/tmp'
CONFIG_DB_PATH = "/etc/sonic/config_db.json"

# VXLAN/VNET configuration constants
PTF_VTEP_IP = "100.0.1.10"  # PTF VTEP endpoint IP
VXLAN_UDP_PORT = 4789       # Standard VXLAN UDP port
VXLAN_VNI = 10000           # Primary VXLAN Network Identifier
UNPROVISIONED_VNI = 30000   # VNI intentionally not provisioned; used to test the VNI-mismatch (no-rewrite) case
VNET_PRIMARY_NAME = "Vnet-0"          # Primary VNET name (ecmp_utils default naming)
VNET_PRIMARY_ROUTE_IP = "150.0.3.1"   # Primary VNET route destination IP
VNET_PRIMARY_ROUTE_PREFIX = f"{VNET_PRIMARY_ROUTE_IP}/32"
VNET_INGRESS_IP = "201.0.0.1/24"      # Routed IP on the VNET ingress interface
# Tunnel MAC the ASIC uses as inner eth_dst on VNET encap; must be DISTINCT from the system
# router_mac or Cisco-8000 ignores it. Matches the other VNET tests (test_vxlan_vnet_bgp_subintf).
VXLAN_ROUTER_MAC = "00:12:34:56:78:9a"

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_RULE_PRIORITY = "1000"  # All ACL rules in this module use the same priority
ACL_RULES_FILE = 'acl_config.json'  # Bulk ACL rule config file used by the scale test

# Scale test rule count per completeness level. One packet is sent per rule, so the runtime
# grows linearly with the count; 'thorough' targets the maximum hardware capacity.
SCALE_RULE_COUNT_LEVEL_MAP = {
    "debug": 100,
    "basic": 2000,
    "confident": 5000,
    "thorough": 9000
}

# IP range used for scale testing
SCALE_IP_BASE = "201.0.0.0"
SCALE_IP_PREFIX = 16
# Arbitrary MAC used as the pre-rewrite inner source MAC for scale test packets. VNET L3 routing
# rebuilds the inner Ethernet header regardless of the injected value, so it need not be unique.
SCALE_TEST_ORIG_MAC = "00:11:22:33:44:55"
# Circuit breaker: abort the per-rule packet test loop after this many consecutive failures,
# instead of grinding through every remaining rule one at a time. Without this, a systemic
# datapath problem (e.g. rules unexpectedly cleared mid-test) would only be detected after every
# single rule times out AND runs its own multi-command diagnostic dump - potentially hours for
# 'thorough', instead of failing fast.
CONSECUTIVE_FAILURE_LIMIT = 10


def _check_acl_rule_active(duthost, table_name, rule_name):
    result = duthost.show_and_parse(f'show acl rule {table_name} {rule_name}')
    return any(entry.get('status', '').lower() == 'active' for entry in result)


def _check_acl_rule_absent(duthost, table_name, rule_name):
    result = duthost.show_and_parse(f'show acl rule {table_name} {rule_name}')
    return len(result) == 0


def _check_acl_table_present(duthost, table_name):
    result = duthost.show_and_parse(f'show acl table {table_name}')
    return any(entry.get('name') == table_name and entry.get('status', '').lower() == 'active' for entry in result)


def _check_acl_table_absent(duthost, table_name):
    result = duthost.show_and_parse(f'show acl table {table_name}')
    return not any(entry.get('name') == table_name for entry in result)


def _check_acl_table_type_in_config_db(duthost, type_name):
    result = duthost.shell(f'redis-cli -n 4 KEYS "ACL_TABLE_TYPE|{type_name}"')["stdout"]
    return type_name in result


def _check_acl_counter_updated(dut, tbl, rule, prev):
    result = dut.show_and_parse('aclshow -a')
    for entry in result:
        if entry.get('table name') == tbl and entry.get('rule name') == rule:
            try:
                return int(entry.get('packets count', 0)) > prev
            except ValueError:
                return False
    return False


def _vnet_route_state_db_key(vnet, prefix):
    return "VNET_ROUTE_TUNNEL_TABLE|{}|{}".format(vnet, prefix)


def _check_vnet_route(duthost, vnet=VNET_PRIMARY_NAME, prefix=VNET_PRIMARY_ROUTE_PREFIX):
    result = duthost.shell(
        "redis-cli -n 6 HGET '{}' 'state'".format(_vnet_route_state_db_key(vnet, prefix)),
        module_ignore_errors=True
    )["stdout"]
    return result.strip().lower() == "active"


def _check_vxlan_tunnel_config(duthost, tunnel_name):
    result = duthost.show_and_parse('show vxlan tunnel')
    return any(entry.get('vxlan tunnel name') == tunnel_name for entry in result)


def _get_vxlan_tunnel_src_ip(duthost, tunnel_name):
    """Fetch the VXLAN tunnel's source IP via CLI ('show vxlan tunnel' has a 'source ip' column)."""
    result = duthost.show_and_parse('show vxlan tunnel')
    for entry in result:
        if entry.get('vxlan tunnel name') == tunnel_name:
            return entry.get('source ip', '').strip()
    return None


def _check_vxlan_switch_config(duthost):
    result = duthost.shell('redis-cli -n 0 KEYS "SWITCH_TABLE:switch"', module_ignore_errors=True)
    return "SWITCH_TABLE:switch" in result.get("stdout", "")


def _select_vnet_ingress_port(mg_facts, cfg_facts):
    """Pick a server-facing VLAN-member port (guaranteed PTF-connected) to repurpose as the
    VNET ingress. It is removed from its VLAN and rebound as a routed VNET interface so the
    DUT VXLAN-encapsulates traffic entering it. Returns (port_name, vlan_id, ptf_index) or
    (None, None, None) if none is available.
    """
    port_indices = mg_facts["minigraph_ptf_indices"]
    for vlan_name, members in cfg_facts.get("VLAN_MEMBER", {}).items():
        for member in members.keys():
            if member in port_indices:
                vlan_id = "".join(ch for ch in vlan_name if ch.isdigit())
                return member, vlan_id, port_indices[member]
    return None, None, None


def setup_vnet_ingress_datapath(duthost, ingress_port, vlan_id):
    """Detach the ingress port from its VLAN and bind it into the VNET as a routed L3 port so
    packets entering it are VNET-routed and VXLAN-encapsulated toward the tunnel endpoint
    (reachable via the default route). Reverted by the config_db backup restore during cleanup.
    """
    duthost.shell(f"config vlan member del {vlan_id} {ingress_port}", module_ignore_errors=True)
    intf_config = {
        "INTERFACE": {
            ingress_port: {"vnet_name": VNET_PRIMARY_NAME},
            f"{ingress_port}|{VNET_INGRESS_IP}": {},
        }
    }
    apply_config_chunk(duthost, intf_config, "vnet_ingress_intf")
    duthost.shell(f"config interface startup {ingress_port}", module_ignore_errors=True)


def generate_mac_address(index):
    """
    Generate a unique unicast MAC address from an index. Encodes the index across the last two
    octets (up to 65535 distinct values) so it also supports the large rule counts used by the
    scale test (up to SCALE_RULE_COUNT_LEVEL_MAP['thorough']).
    """
    if index >= 0x10000:
        raise ValueError(f"Index {index} exceeds the 65535 addresses encodable in the last two MAC octets")

    return f"aa:bb:cc:dd:{(index >> 8) & 0xff:02x}:{index & 0xff:02x}"


def generate_ip_address(index, base_ip="10.0.0.0", prefix=16):
    """
    Generate an IP address from a base network using an index.
    """
    network = ipaddress.IPv4Network(f"{base_ip}/{prefix}", strict=False)
    # Ensure we don't exceed the network size
    max_hosts = 2**(32 - prefix) - 2  # Subtract network and broadcast
    if index >= max_hosts:
        raise ValueError(f"Index {index} exceeds maximum hosts {max_hosts} for network {network}")

    # Get the nth host in the network
    return str(network.network_address + (index + 1))


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(request, rand_selected_dut, tbinfo, ptfadapter):
    if 'dualtor' in tbinfo['topo']['name']:
        pytest.skip("test_src_mac_rewrite does not support dualtor topology - "
                    "VXLAN tunnel config does not propagate to APP_DB on dualtor")

    data = {}

    data['duthost'] = rand_selected_dut
    data['ptfadapter'] = ptfadapter

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    # Extract Loopback0 IP
    loopback0_ips = mg_facts["minigraph_lo_interfaces"]
    loopback_src_ip = None
    for intf in loopback0_ips:
        if intf["name"] == "Loopback0":
            loopback_src_ip = intf["addr"]
            break

    if not loopback_src_ip:
        pytest.fail("Could not find Loopback0 IP address")

    data['loopback_src_ip'] = loopback_src_ip

    cfg_facts = rand_selected_dut.get_running_config_facts()

    # Get topology info for PTF port availability
    topo = tbinfo['topo']['properties']['topology']
    ptf_ports_available_in_topo = topo.get('ptf_map_disabled', {}).keys() if 'ptf_map_disabled' in topo else []
    if not ptf_ports_available_in_topo:
        # If ptf_map_disabled not available, use all PTF indices from minigraph
        ptf_ports_available_in_topo = list(mg_facts["minigraph_ptf_indices"].values())

    # Get port configuration using CONFIG_DB approach
    pc_members = cfg_facts.get("PORTCHANNEL_MEMBER", {})
    port_indexes = mg_facts["minigraph_ptf_indices"]

    # PortChannel (uplink) members are the RECEIVE ports: the encapsulated packet egresses
    # one of the uplinks (default route to the tunnel endpoint is ECMP-hashed across them).
    receive_ptf_ports = []
    for members_dict in pc_members.values():
        for member in members_dict.keys():
            if member in port_indexes:
                ptf_index = port_indexes[member]
                if ptf_index in ptf_ports_available_in_topo:
                    receive_ptf_ports.append(ptf_index)

    if not receive_ptf_ports:
        pytest.fail("No PortChannel member PTF ports found for receiving encapsulated packets")

    # Repurpose a server-facing VLAN-member port (PTF-connected) as the VNET ingress.
    ingress_port_name, ingress_vlan_id, ingress_ptf_port = _select_vnet_ingress_port(mg_facts, cfg_facts)
    if not ingress_port_name:
        pytest.fail("Could not find a VLAN-member port to repurpose as the VNET ingress")

    data['ptf_port_1'] = ingress_ptf_port
    data['ptf_port_2'] = receive_ptf_ports
    data['vnet_ingress_port'] = ingress_port_name
    data['vnet_ingress_vlan'] = ingress_vlan_id
    data['bind_ports'] = list(pc_members.keys())

    # Test scenarios using consistent configuration
    data['test_scenarios'] = {
        'single_ip_test': {
            'original_mac': generate_mac_address(1),
            'first_modified_mac': generate_mac_address(2),
            'second_modified_mac': generate_mac_address(3)
        },
        'range_test': {
            'original_mac': generate_mac_address(4),
            'first_modified_mac': generate_mac_address(5),
            'second_modified_mac': generate_mac_address(6)
        },
        'multi_vni_test': {
            'original_mac': generate_mac_address(7),
            'first_modified_mac': generate_mac_address(8),
            'second_modified_mac': generate_mac_address(9),
            'third_modified_mac': generate_mac_address(10)
        }
    }

    data['vxlan_tunnel_name'] = "tunnel_v4"

    # Create configuration backup before making any changes
    backup_config(rand_selected_dut)

    # Register cleanup as a finalizer (instead of a separate tearDown fixture that
    # depends on setUp) so it still runs even if setUp fails partway through below.
    # Otherwise a mid-setup failure leaves the DUT with unclean/invalid CONFIG_DB
    # that then fails pre-test YANG validation on subsequent runs.
    request.addfinalizer(lambda: cleanup_test_configuration(rand_selected_dut, data['vxlan_tunnel_name']))

    # Configure VXLAN/VNET infrastructure once for all test scenarios
    create_vxlan_vnet_config(
        duthost=rand_selected_dut,
        tunnel_name=data['vxlan_tunnel_name'],
        src_ip=data['loopback_src_ip'],
    )

    # Verify VNET was created and wait for its route to be active (confirms orchagent programmed it)
    vnet_list = rand_selected_dut.show_and_parse('show vnet brief')
    pytest_assert(any(entry.get('vnet name') == VNET_PRIMARY_NAME for entry in vnet_list),
                  f"{VNET_PRIMARY_NAME} not found in 'show vnet brief' output")

    # Wait for VNET route to be active in STATE_DB (confirms orchagent programmed it)
    if not wait_until(60, 5, 5, _check_vnet_route, rand_selected_dut):
        vnet_route_state = rand_selected_dut.shell(
            "redis-cli -n 6 HGETALL '{}'".format(
                _vnet_route_state_db_key(VNET_PRIMARY_NAME, VNET_PRIMARY_ROUTE_PREFIX)
            ),
            module_ignore_errors=True
        )["stdout"]
        logger.error("STATE_DB VNET route entry:\n%s", vnet_route_state)
        pytest.fail(f"VNET route for {VNET_PRIMARY_ROUTE_PREFIX} is not active in STATE_DB")

    # Bind the ingress interface into the VNET so the DUT VXLAN-encapsulates ingress traffic
    # (without this the packet is plain-routed and the ACL never matches).
    setup_vnet_ingress_datapath(rand_selected_dut, data['vnet_ingress_port'], data['vnet_ingress_vlan'])

    return data


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL, prev_count=0):
    # Wait for orchagent to update the ACL counters
    if timeout > 0:
        wait_until(timeout, 2, 0, _check_acl_counter_updated, duthost, table_name, rule_name, prev_count)
    result = duthost.show_and_parse('aclshow -a')

    pytest_assert(result, "Failed to retrieve ACL counter for {}|{}".format(table_name, rule_name))

    matched = next((rule for rule in result
                    if table_name == rule.get('table name') and rule_name == rule.get('rule name')), None)
    pytest_assert(matched, "ACL rule {} not found in table {}".format(rule_name, table_name))

    pkt_count = matched.get('packets count', '0')
    if pkt_count == 'N/A':
        return 0
    try:
        return int(pkt_count)
    except ValueError:
        logger.warning(
            f"ACL counter for {table_name}|{rule_name} has unexpected value: '{pkt_count}', returning 0"
        )
        return 0


def get_acl_counters(duthost, table_name):
    """
    Get ACL counter packets value for all rules in a table in a single call. Used by the scale
    test to diff before/after counters in bulk instead of issuing one 'aclshow -a' per rule.
    """
    result = duthost.show_and_parse('aclshow -a')

    if not result:
        logger.warning("Failed to retrieve ACL counters for table {}".format(table_name))
        return {}

    counters = {}
    for rule in result:
        if rule.get('table name') != table_name:
            continue

        rule_name = rule.get('rule name')
        if not rule_name:
            continue

        pkt_count = rule.get('packets count', '0')
        try:
            counters[rule_name] = int(pkt_count)
        except ValueError:
            logger.warning(f"ACL counter for {table_name}|{rule_name} is not integer: {pkt_count}, returning 0")
            counters[rule_name] = 0

    return counters


def check_rule_counters(duthost):
    """
    Check if ACL rule counters are initialized.
    """
    res = duthost.shell("aclshow -a")['stdout_lines']
    if len(res) <= 2 or [line for line in res if 'N/A' in line]:
        return False
    else:
        return True


def count_active_acl_rules(duthost):
    """
    Return the number of rules reported as Active for the test ACL table.
    """
    rules = duthost.show_and_parse("show acl rule", module_ignore_errors=True)
    return len([r for r in rules
                if r.get('table') == ACL_TABLE_NAME and r.get('status', '').lower() == 'active'])


def setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE):
    acl_table_type_data = {
        "ACL_TABLE_TYPE": {
            acl_type_name: {
                "BIND_POINTS": [
                    "PORT",
                    "PORTCHANNEL"
                ],
                "MATCHES": [
                    "INNER_SRC_IP",
                    "TUNNEL_VNI"
                ],
                "ACTIONS": [
                    "COUNTER",
                    "INNER_SRC_MAC_REWRITE_ACTION"
                ]
            }
        }
    }

    acl_type_json = json.dumps(acl_table_type_data, indent=4)
    acl_type_file = os.path.join(TMP_DIR, f"{acl_type_name.lower()}_acl_type.json")

    logger.info("Writing ACL table type definition to %s:\n%s", acl_type_file, acl_type_json)
    duthost.copy(content=acl_type_json, dest=acl_type_file)

    logger.info("Loading ACL table type definition using config load")
    duthost.shell(f"config load -y {acl_type_file}")

    pytest_assert(wait_until(30, 5, 2, _check_acl_table_type_in_config_db, duthost, acl_type_name),
                  f"ACL table type {acl_type_name} not found in CONFIG_DB after loading")


def setup_acl_table(duthost, ports):
    logger.info(f"Cleaning up any existing ACL table named {ACL_TABLE_NAME}")
    duthost.shell(f"config acl remove table {ACL_TABLE_NAME}", module_ignore_errors=True)

    cmd = "config acl add table {} {} -s {} -p {}".format(
        ACL_TABLE_NAME,
        ACL_TABLE_TYPE,
        "egress",
        ",".join(ports)
    )

    logger.info(f"Creating ACL table {ACL_TABLE_NAME} with ports: {ports}")
    duthost.shell(cmd)

    pytest_assert(wait_until(30, 5, 2, _check_acl_table_present, duthost, ACL_TABLE_NAME),
                  f"ACL table {ACL_TABLE_NAME} not found or not active in 'show acl table' output after creation")

    logger.info(f"ACL table {ACL_TABLE_NAME} is successfully created and active")


def remove_acl_table(duthost):
    logger.info(f"Removing ACL table {ACL_TABLE_NAME}")
    cmd = f"config acl remove table {ACL_TABLE_NAME}"
    result = duthost.shell(cmd, module_ignore_errors=True)

    if result["rc"] != 0:
        logger.warning(f"Failed to remove ACL table via config command. Output:\n{result.get('stdout', '')}")
        pytest.fail(f"Failed to remove ACL table {ACL_TABLE_NAME}")

    pytest_assert(wait_until(30, 5, 2, _check_acl_table_absent, duthost, ACL_TABLE_NAME),
                  f"ACL table {ACL_TABLE_NAME} still present in STATE_DB after removal")

    logger.info(f"ACL table {ACL_TABLE_NAME} successfully removed from STATE_DB")


def setup_acl_rule(duthost, inner_src_ip, vni, new_src_mac, rule_name="rule_1", priority=ACL_RULE_PRIORITY):
    """Create (or update) an ACL rule via 'config load -y' and wait until it is active."""
    acl_rule = {
        "ACL_RULE": {
            f"{ACL_TABLE_NAME}|{rule_name}": {
                "PRIORITY": priority,
                "TUNNEL_VNI": vni,
                "INNER_SRC_IP": inner_src_ip,
                "INNER_SRC_MAC_REWRITE_ACTION": new_src_mac
            }
        }
    }

    logger.info("Loading ACL rule config:\n%s", json.dumps(acl_rule, indent=4))
    apply_config_chunk(duthost, acl_rule, f"acl_rule_{rule_name}")

    logger.info(f"Waiting for ACL rule {rule_name} to be applied...")
    pytest_assert(wait_until(30, 5, 2, _check_acl_rule_active, duthost, ACL_TABLE_NAME, rule_name),
                  f"ACL rule {rule_name} not active in STATE_DB after loading")

    logger.info(f"ACL rule {rule_name} for table {ACL_TABLE_NAME} is successfully created and active")


def setup_bulk_acl_rules(duthost, rule_count, vni=str(VXLAN_VNI), start_index=0):
    """
    Setup ALL ACL rules at once using a single JSON operation - maximum performance. Used by the
    scale test, where applying rule_count individual 'config load' calls would be far too slow.
    """
    logger.info(f"Building ALL {rule_count} ACL rules for single application")

    start_time = time.time()

    # Create complete JSON config with ALL rules at once
    acl_rules = {"ACL_RULE": {}}

    logger.info(f"Generating {rule_count} rule configurations...")
    generation_start = time.time()

    for i in range(rule_count):
        rule_index = start_index + i
        rule_name = f"scale_rule_{i + 1:04d}"
        inner_src_ip = generate_ip_address(rule_index, base_ip=SCALE_IP_BASE, prefix=SCALE_IP_PREFIX)
        new_src_mac = generate_mac_address(rule_index)

        # Create rule entry for config
        rule_key = f"{ACL_TABLE_NAME}|{rule_name}"
        acl_rules["ACL_RULE"][rule_key] = {
            "INNER_SRC_IP": f"{inner_src_ip}/32",
            "TUNNEL_VNI": str(vni),
            "INNER_SRC_MAC_REWRITE_ACTION": new_src_mac,
            "PRIORITY": ACL_RULE_PRIORITY  # SAME PRIORITY for all rules to observe behavior
        }

    generation_time = time.time() - generation_start
    logger.info(f"Generated {rule_count} rule configurations in {generation_time:.2f} seconds")

    # Convert to JSON string
    logger.info("Converting to JSON format...")
    json_start = time.time()
    acl_rules_json = json.dumps(acl_rules, indent=4)
    json_time = time.time() - json_start
    logger.info(f"JSON conversion completed in {json_time:.2f} seconds")
    logger.info(f"JSON size: {len(acl_rules_json)/1024:.1f} KB")

    # Create temporary file on DUT
    dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)
    logger.info(f"Transferring {len(acl_rules_json)/1024:.1f} KB config file to DUT...")
    transfer_start = time.time()
    duthost.copy(content=acl_rules_json, dest=dest_path)
    transfer_time = time.time() - transfer_start
    logger.info(f"Config file transferred in {transfer_time:.2f} seconds")

    # Apply ALL rules in a single operation
    logger.info("Loading bulk ACL rules from %s", dest_path)
    load_result = duthost.shell(f"config load -y {dest_path}", module_ignore_errors=True)
    logger.info("Config load result: rc=%s, stdout=%s", load_result.get("rc", "unknown"), load_result.get("stdout", ""))

    if load_result.get("rc", 0) != 0:
        logger.error("Config load failed: %s", load_result.get("stderr", ""))
        pytest.fail(f"Failed to load bulk ACL rule configuration for {rule_count} rules")
    else:
        total_time = time.time() - start_time
        rate = rule_count / total_time
        logger.info(f"SUCCESS: {rule_count} ACL rules applied in {total_time:.2f}s ({rate:.0f} rules/sec)")

    # Programming time on the DUT grows with the rule count, so poll instead of sleeping a fixed time
    active_timeout = 60 + rule_count // 10
    logger.info(f"Waiting up to {active_timeout}s for all {rule_count} ACL rules to become Active...")

    def _all_rules_active(duthost, expected_count):
        active_count = count_active_acl_rules(duthost)
        logger.info(f"ACL rules Active: {active_count}/{expected_count}")
        return active_count == expected_count

    if not wait_until(active_timeout, 10, 0, _all_rules_active, duthost, rule_count):
        pytest.fail(f"Only {count_active_acl_rules(duthost)} of {rule_count} ACL rules became Active "
                    f"within {active_timeout} seconds")

    # Verify rules are installed
    logger.info("Verifying ALL rules installation...")
    verify_acl_rules_installation(duthost, rule_count)


def verify_acl_rules_installation(duthost, expected_count):
    """
    Verify that the expected number of ACL rules are installed.
    """
    logger.info(f"Verifying {expected_count} ACL rules are installed")

    # Check CONFIG_DB first
    config_rules_cmd = f"redis-cli -n 4 KEYS 'ACL_RULE|{ACL_TABLE_NAME}|*'"
    config_rules = duthost.shell(config_rules_cmd)["stdout_lines"]
    config_rule_count = len([key for key in config_rules if key.strip()])
    logger.info(f"Number of rules in CONFIG_DB: {config_rule_count}")

    if config_rule_count != expected_count:
        logger.error(f"CONFIG_DB rule count mismatch: expected {expected_count}, found {config_rule_count}")
        pytest.fail(f"CONFIG_DB has {config_rule_count} rules, expected {expected_count}")

    # Check STATE_DB
    state_rules_cmd = f"redis-cli -n 6 KEYS 'ACL_RULE_TABLE|{ACL_TABLE_NAME}|*'"
    state_rules = duthost.shell(state_rules_cmd)["stdout_lines"]
    state_rule_count = len([key for key in state_rules if key.strip()])
    logger.info(f"Number of rules in STATE_DB: {state_rule_count}")

    # Use 'show acl rule' for final verification with exact status-column matching (a substring
    # search for "Active" would also match "Inactive" rows and silently overcount/mask failures)
    table_rules = [r for r in duthost.show_and_parse("show acl rule", module_ignore_errors=True)
                   if r.get('table') == ACL_TABLE_NAME]

    if table_rules is not None:
        rule_count = len(table_rules)
        active_count = len([r for r in table_rules if r.get('status', '').lower() == 'active'])
        inactive_count = rule_count - active_count

        logger.info(f"Number of rules found in 'show acl rule': {rule_count}")
        logger.info(f"Rule status summary: {active_count} Active, {inactive_count} Inactive")

        if rule_count < expected_count:
            logger.error(f"'show acl rule' count mismatch: expected {expected_count}, found {rule_count}")
            logger.info("Sample of show acl rule output:")
            logger.info(str(table_rules[:10]))  # Show a sample for debugging
            pytest.fail(f"Not all ACL rules are programmed. Expected: {expected_count}, Found: {rule_count}")

        if inactive_count > 0:
            pytest.fail(f"Found {inactive_count} Inactive rules out of {rule_count} total rules. "
                        f"This indicates hardware resource limits or priority conflicts")
        else:
            logger.info(f"All {active_count} rules are active")
    else:
        # Fall back to STATE_DB count
        if state_rule_count < expected_count:
            pytest.fail(f"STATE_DB rule count insufficient: {state_rule_count}/{expected_count}")

    # Check ACL rule counters
    logger.info("Waiting for ACL rule counters to become ready...")
    counter_ready = wait_until(60, 5, 0, check_rule_counters, duthost)
    if not counter_ready:
        logger.warning("ACL rule counters are not ready after scale rule installation")
        # Don't fail the test for counter issues, just warn
    else:
        logger.info("ACL rule counters are ready")

    logger.info(f"Successfully verified {expected_count} ACL rules installation")


def modify_acl_rule(duthost, inner_src_ip, vni, new_src_mac):
    logger.info("Modifying ACL rule with new MAC: %s", new_src_mac)
    # Re-applying the rule via config load properly triggers change notifications.
    setup_acl_rule(duthost, inner_src_ip, vni, new_src_mac)
    logger.info("ACL rule successfully modified to use MAC: %s", new_src_mac)


def remove_acl_rules(duthost, rule_names=("rule_1",)):
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))

    for rule_name in rule_names:
        pytest_assert(wait_until(30, 5, 2, _check_acl_rule_absent, duthost, ACL_TABLE_NAME, rule_name),
                      f"ACL rule {rule_name} still in STATE_DB after removal")


def remove_bulk_acl_rules(duthost):
    """
    Remove all ACL rules from the test table. Unlike remove_acl_rules(), which polls each rule
    name individually, this scans CONFIG_DB/STATE_DB in bulk - required for the scale test where
    there may be thousands of individually-named rules.
    """
    logger.info(f"Removing all ACL rules from table {ACL_TABLE_NAME}")

    rule_pattern = f"ACL_RULE|{ACL_TABLE_NAME}|*"
    count_cmd = f"redis-cli -n 4 --scan --pattern '{rule_pattern}' | wc -l"
    rule_count = int(duthost.shell(count_cmd)["stdout"].strip() or 0)
    logger.info(f"Found {rule_count} rules to remove from CONFIG_DB")

    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))

    def _check_acl_rules_absent(duthost, database, pattern):
        result = duthost.shell(
            f"redis-cli -n {database} --scan --pattern '{pattern}' | head -n 1"
        )
        return not result["stdout"].strip()

    pytest_assert(wait_until(60 + rule_count // 10, 1, 0, _check_acl_rules_absent, duthost, 4, rule_pattern),
                  f"ACL rules for {ACL_TABLE_NAME} still present in CONFIG_DB after batch deletion")
    state_rule_pattern = f"ACL_RULE_TABLE*{ACL_TABLE_NAME}*"
    pytest_assert(wait_until(60 + rule_count // 10, 2, 0, _check_acl_rules_absent, duthost, 6, state_rule_pattern),
                  f"ACL rules for {ACL_TABLE_NAME} still present in STATE_DB after batch deletion")

    logger.info(f"Successfully removed {rule_count} ACL rules")


def create_vxlan_vnet_config(duthost, tunnel_name, src_ip):
    # --- VXLAN parameters ---
    vnet_base = VXLAN_VNI
    ptf_vtep = PTF_VTEP_IP

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True
    ecmp_utils.Constants['DEBUG'] = False

    # First create the VXLAN tunnel manually (since we need specific src_ip)
    vxlan_tunnel_entry = {"src_ip": src_ip}
    # On cisco-8000, base IP-in-IP decap tunnels use pipe TTL mode; set VXLAN decap ttl_mode to
    # pipe so orchagent programs DECAP_TTL_MODE consistently (upstream #26084).
    if duthost.facts.get("asic_type") == "cisco-8000":
        vxlan_tunnel_entry["ttl_mode"] = "pipe"
    tunnel_config = {
        "VXLAN_TUNNEL": {
            tunnel_name: vxlan_tunnel_entry
        }
    }

    logger.info("Creating VXLAN tunnel:\n%s", json.dumps(tunnel_config, indent=4))
    apply_config_chunk(duthost, tunnel_config, "vxlan_tunnel")

    # Wait for VXLAN tunnel to appear in CONFIG_DB before ecmp_utils consumes it
    pytest_assert(wait_until(30, 2, 2, _check_vxlan_tunnel_config, duthost, tunnel_name),
                  f"VXLAN tunnel {tunnel_name} not found in CONFIG_DB after apply")

    # Use ecmp_utils.create_vnets() for primary VNET (handles complex setup)
    logger.info("Creating primary VNET using ecmp_utils.create_vnets()")
    vnet_vni_map = ecmp_utils.create_vnets(
        duthost,
        tunnel_name=tunnel_name,
        vnet_count=1,
        vni_base=vnet_base,
        vnet_name_prefix="Vnet",
        advertise_prefix="false"
    )

    logger.info(f"Created primary VNET: {vnet_vni_map}")

    # Get the VNET name (should be VNET_PRIMARY_NAME based on ecmp_utils naming)
    vnet_name = list(vnet_vni_map.keys())[0]

    # Configure VNET route via CONFIG_DB so 'show vnet route all' can see it
    logger.info("Configuring primary VNET route via CONFIG_DB")
    route_config = {
        "VNET_ROUTE_TUNNEL": {
            f"{vnet_name}|{VNET_PRIMARY_ROUTE_PREFIX}": {
                "endpoint": ptf_vtep
            }
        }
    }
    apply_config_chunk(duthost, route_config, "vnet_route")

    pytest_assert(wait_until(60, 5, 5, _check_vxlan_tunnel_config, duthost, tunnel_name),
                  f"VXLAN tunnel {tunnel_name} not found in CONFIG_DB after setup")

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=VXLAN_UDP_PORT, dutmac=VXLAN_ROUTER_MAC)

    # Allow time for VXLAN switch config to propagate through swss pipeline
    pytest_assert(wait_until(10, 2, 2, _check_vxlan_switch_config, duthost),
                  "SWITCH_TABLE:switch not found in APP_DB after configure_vxlan_switch")


def apply_config_chunk(duthost, payload, config_name):
    """Apply configuration chunk using config load for proper notification"""
    content = json.dumps(payload, indent=2)
    file_dest = f"/tmp/{config_name}_chunk.json"
    duthost.copy(content=content, dest=file_dest)
    result = duthost.shell(f"config load -y {file_dest}", module_ignore_errors=True)
    duthost.shell(f"rm -f {file_dest}", module_ignore_errors=True)
    pytest_assert(result.get("rc", 1) == 0,
                  f"config load failed for {file_dest}: {result.get('stderr', result.get('stdout', ''))}")


def backup_config(duthost):
    logger.info("Creating configuration backup...")
    try:
        duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")
        logger.info("Configuration backup created successfully")
    except Exception as e:
        logger.error(f"Failed to create configuration backup: {e}")
        raise


def cleanup_test_configuration(duthost, vxlan_tunnel_name=None):
    try:
        # Restore original configuration from backup
        logger.info("Restoring original configuration from backup...")
        result = duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}", module_ignore_errors=True)

        if result.get("rc", 0) != 0:
            logger.warning("Backup file not found or move failed, trying alternative cleanup...")
            # Fallback to manual cleanup if backup restoration fails
            try:
                logger.info("Attempting manual ACL cleanup as fallback...")
                duthost.shell(f"config acl remove table {ACL_TABLE_NAME}", module_ignore_errors=True)
            except Exception as e:
                logger.warning(f"Manual ACL cleanup failed: {e}")
        else:
            logger.info("Configuration backup restored successfully")

        # Reload configuration to apply the restored config
        logger.info("Reloading configuration to apply restored settings...")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        logger.info("Configuration reload completed")

    except Exception as e:
        logger.error(f"Failed during configuration cleanup: {e}")
        # Don't raise the exception to avoid masking test failures

    finally:
        # Clean up temporary files
        try:
            logger.info("Cleaning up temporary files...")
            temp_files = [
                f"/tmp/{ACL_REMOVE_RULES_FILE}",  # acl_rules_del.json
                f"/tmp/{ACL_RULES_FILE}",  # Created by setup_bulk_acl_rules (scale test)
                "/tmp/inner_src_mac_rewrite_type_acl_type.json",  # Created by setup_acl_table_type
                "/tmp/vxlan_tunnel_chunk.json",  # Created by create_vxlan_vnet_config
            ]

            for file_path in temp_files:
                try:
                    duthost.shell(f"rm -f {file_path}", module_ignore_errors=True)
                except Exception as e:
                    logger.debug(f"Could not remove {file_path}: {e}")

            logger.info("Temporary file cleanup completed")

        except Exception as e:
            logger.warning(f"Failed to clean up temporary files: {e}")

    logger.info("=== Configuration cleanup completed ===")


def _log_vxlan_datapath_state(duthost, inner_src_ip, inner_dst_ip, rule_name):
    """Dump VNET/underlay/ACL state to distinguish a missing-encap datapath problem from a
    packet-content mismatch when no encapsulated packet is received."""
    diag_cmds = [
        "show vnet route all",
        "show vxlan tunnel",
        "show ip route {}".format(PTF_VTEP_IP),
        "show arp {}".format(PTF_VTEP_IP),
        "show ip route {}".format(inner_dst_ip),
        "aclshow -a",
    ]
    logger.error("=== VXLAN datapath diagnostics (no encapsulated packet received for "
                 "inner_src=%s inner_dst=%s rule=%s) ===", inner_src_ip, inner_dst_ip, rule_name)
    for cmd in diag_cmds:
        try:
            out = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
        except Exception as e:
            out = "<failed to run '{}': {}>".format(cmd, e)
        logger.error("--- %s ---\n%s", cmd, out)


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, ptf_ports, duthost,
                                 src_ip, dst_ip, orig_src_mac, rewrite_mac,
                                 table_name, rule_name, expect_rewrite=True,
                                 vni=VXLAN_VNI, test_description="", scale_test=False,
                                 dut_vtep_ip=None):
    """
    Send one test packet from the PTF host and verify whether the ACL rewrote the inner
    source MAC of the DUT-emitted VXLAN packet.

    The DUT VXLAN-encapsulates the injected inner packet toward the PTF VTEP. A full expected
    VXLAN packet is built and matched exactly on the inner frame (only the dynamic outer fields
    are masked). The inner source MAC we expect depends on the case: the rewrite MAC when the
    rule fires, otherwise the DUT's router_mac. VNET L3 routing rebuilds the inner Ethernet
    header before encap, so the original injected src MAC is gone and the un-rewritten inner src
    MAC is router_mac. Either way we positively assert the encapped packet IS received over the
    egress PortChannel-member port(s), which confirms end to end whether the src MAC was rewritten.

    The ACL counter is checked in addition: it must increment when expect_rewrite is True and
    stay flat for a partial/no-match case. Pass scale_test=True to skip this per-call check
    (e.g. the scale test diffs 'aclshow -a' in bulk before/after instead, since polling every
    individual rule's counter does not scale to thousands of rules).

    dut_vtep_ip should be the VXLAN tunnel's source IP (setUp['loopback_src_ip'], fixed for the
    whole test module). Pass it in so callers avoid an extra 'show vxlan tunnel' CLI round trip
    on every single packet - that lookup is only done here as a fallback if omitted.
    """
    router_mac = duthost.facts["router_mac"]
    if dut_vtep_ip is None:
        dut_vtep_ip = _get_vxlan_tunnel_src_ip(duthost, "tunnel_v4")
    pytest_assert(dut_vtep_ip, "VXLAN tunnel src_ip is empty in 'show vxlan tunnel' output")
    # The ASIC uses the configured tunnel MAC (VXLAN_ROUTER_MAC) as the inner eth_dst.
    vxlan_router_mac = VXLAN_ROUTER_MAC
    logger.info("vxlan_router_mac=%s, router_mac=%s", vxlan_router_mac, router_mac)

    input_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_dst=router_mac, eth_src=orig_src_mac,
        ip_dst=dst_ip, ip_src=src_ip, ip_id=105, ip_ttl=64,
        tcp_sport=1234, tcp_dport=5000, ip_ecn=0)
    # Inner src MAC of the encapped packet: the ACL rewrite MAC when the rule fires, otherwise the
    # DUT router_mac. VNET L3 routing rebuilds the inner Ethernet header, so orig_src_mac is gone
    # and the un-rewritten inner src MAC is router_mac. Matching it exactly confirms e2e whether
    # the rewrite happened.
    expected_inner_src_mac = rewrite_mac if expect_rewrite else router_mac
    inner_exp = testutils.simple_tcp_packet(
        pktlen=100, eth_src=expected_inner_src_mac, eth_dst=vxlan_router_mac,
        ip_src=src_ip, ip_dst=dst_ip, ip_id=105, ip_ttl=63,
        tcp_sport=1234, tcp_dport=5000, ip_ecn=0)
    expected_pkt = testutils.simple_vxlan_packet(
        eth_src=router_mac, eth_dst="ff:ff:ff:ff:ff:ff",
        ip_src=dut_vtep_ip, ip_dst=PTF_VTEP_IP, ip_id=0, ip_flags=0x2,
        udp_sport=0, udp_dport=VXLAN_UDP_PORT, with_udp_chksum=False,
        vxlan_vni=vni, inner_frame=inner_exp)

    masked = Mask(expected_pkt)
    masked.set_ignore_extra_bytes()
    masked.set_do_not_care_packet(scapy.Ether, "dst")
    masked.set_do_not_care_packet(scapy.UDP, "sport")
    masked.set_do_not_care_packet(scapy.UDP, "dport")
    masked.set_do_not_care_packet(scapy.UDP, "chksum")
    masked.set_do_not_care_packet(scapy.IP, "ttl")
    masked.set_do_not_care_packet(scapy.IP, "chksum")
    masked.set_do_not_care_packet(scapy.IP, "id")
    masked.set_do_not_care_packet(scapy.IP, "len")
    masked.set_do_not_care_packet(scapy.IP, "tos")

    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0) if not scale_test else None
    logger.info("=== MAC Rewrite Test (expect_rewrite=%s, rule=%s, %s) ===",
                expect_rewrite, rule_name, test_description)
    logger.info("Sending test packet for rule %s", rule_name)

    # Inject via testutils.send (not send_packet): the ptfadapter overrides send/dp_poll to rewrite
    # the L4 payload to a per-module pattern on BOTH the injected packet and the expected mask, so
    # they stay symmetric. send_packet skips that rewrite and would mismatch the payload here.
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port_1, input_pkt, 1)

    # `masked` already encodes the expected inner src MAC for this case (rewrite MAC when the rule
    # fires, router_mac when it must not), so the same positive verify confirms e2e whether the
    # rewrite happened. Only the ACL-counter expectation differs between the two cases.
    # timeout=1: the rule is already confirmed Active before any packet is sent, so the
    # encapped packet should arrive almost immediately; a short timeout caps the per-packet
    # miss penalty (important at scale, where thousands of packets are sent serially).
    try:
        testutils.verify_packet_any_port(ptfadapter, masked, ptf_ports, timeout=1)
    except Exception:
        # Dump VNET/underlay/ACL state to distinguish a datapath problem (no encap at all)
        # from a packet-content mismatch, then fail.
        _log_vxlan_datapath_state(duthost, src_ip, dst_ip, rule_name)
        raise

    if not scale_test:
        if expect_rewrite:
            # The rule fired: wait for orchagent to flush the incremented counter.
            count_after = get_acl_counter(duthost, table_name, rule_name, prev_count=count_before)
            pytest_assert(count_after >= count_before + 1,
                          f"ACL counter did not increment for {src_ip}. "
                          f"before={count_before}, after={count_after}.")
        else:
            # The rule must NOT fire: read immediately (no reason to wait) and require a flat counter.
            count_after = get_acl_counter(duthost, table_name, rule_name, timeout=0)
            pytest_assert(count_after == count_before,
                          f"ACL counter incremented unexpectedly for partial match "
                          f"({test_description}): before={count_before}, after={count_after}")
        logger.info("ACL counter for IP %s: before=%s, after=%s",
                    src_ip, count_before, count_after)


def _test_inner_src_mac_rewrite(setUp, scenario_name):
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios'][scenario_name]

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    # Extract scenario-specific MAC addresses
    original_inner_src_mac = scenario['original_mac']
    first_modified_mac = scenario['first_modified_mac']
    second_modified_mac = scenario['second_modified_mac']

    # Configuration values
    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME

    # Standard values from VXLAN/VNET configuration
    inner_dst_ip = VNET_PRIMARY_ROUTE_IP  # Route destination
    vni_id = str(VXLAN_VNI)  # VNI from configuration
    inner_src_ip = "201.0.0.101"  # Source IP for test packets

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Configure ACL rule based on scenario
        if scenario_name == "single_ip_test":
            # Use specific source IP for ACL rule matching (single IP)
            acl_rule_prefix = f"{inner_src_ip}/32"
            logger.info(f"Single IP test: Using ACL rule prefix {acl_rule_prefix}")
        else:  # range_test
            # Use broader subnet for range testing (matches multiple IPs)
            acl_rule_prefix = "201.0.0.0/24"  # Matches the 201.0.0.x range including 201.0.0.101
            logger.info(f"Range test: Using ACL rule prefix {acl_rule_prefix}")

        setup_acl_rule(duthost, acl_rule_prefix, vni_id, first_modified_mac)

        # Test with the configured source IP
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
            first_modified_mac, table_name, RULE_NAME, dut_vtep_ip=dut_vtep_ip
        )

        # For range test, also test with different IPs in the range
        if scenario_name == "range_test":
            test_ips = ["201.0.0.102", "201.0.0.103", "201.0.0.104"]  # Additional IPs in the 201.0.0.0/24 range
            for test_ip in test_ips:
                logger.info(f"Range test: Verifying rewrite with IP {test_ip}")
                _send_and_verify_mac_rewrite(
                    ptfadapter, ptf_port_1, ptf_port_2, duthost, test_ip, inner_dst_ip, original_inner_src_mac,
                    first_modified_mac, table_name, RULE_NAME, dut_vtep_ip=dut_vtep_ip)

        # Modify ACL rule to use new MAC address (much more efficient than remove/recreate)
        logger.info("Step 3: Modifying ACL rule to use new MAC: %s", second_modified_mac)
        modify_acl_rule(duthost, acl_rule_prefix, vni_id, second_modified_mac)

        logger.info("Step 4: Verifying rewrite with second modified MAC: %s", second_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
            second_modified_mac, table_name, RULE_NAME, dut_vtep_ip=dut_vtep_ip
        )

        logger.info("=== All test steps completed successfully ===")

    finally:
        # Clean up ACL configuration (VXLAN/VNET cleanup handled at module level)
        try:
            remove_acl_rules(duthost)
            remove_acl_table(duthost)
            logger.info("ACL cleanup completed successfully")
        except Exception as e:
            logger.warning(f"ACL cleanup failed: {e}")
            # Don't raise the exception to avoid masking test failures


def test_single_ip_acl_rule(setUp):
    """
    Test ACL rule for inner source MAC rewriting with single IP (/32) matching.
    Validates that ACL rules can target specific IP addresses for MAC rewriting.
    """
    _test_inner_src_mac_rewrite(setUp, "single_ip_test")


def test_range_ip_acl_rule(setUp):
    """
    Test ACL rule for inner source MAC rewriting with IP range (/24) matching.
    Validates that ACL rules can target IP subnets and rewrite MAC for multiple IPs.
    """
    _test_inner_src_mac_rewrite(setUp, "range_test")


def test_partial_match(setUp):
    """
    Test partial match cases for ACL rules:
      1. VNI matches but source IP does not - rule should not trigger.
      2. Source IP matches but VNI does not - rule should not trigger.
    Validates that both INNER_SRC_IP and TUNNEL_VNI must match for an ACL
    rule to fire; a partial match should not increment counters or rewrite the MAC.
    """
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']
    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']
    rule_name_1 = "rule_vni_match_no_ip"
    rule_name_2 = "rule_ip_match_no_vni"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Case 1: VNI matches but source IP does not match
        logger.info("=== Case 1: VNI matches but IP does not ===")
        setup_acl_rule(duthost, "202.1.1.100/32", str(VXLAN_VNI), rewrite_mac_1, rule_name_1)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "202.1.1.200", VNET_PRIMARY_ROUTE_IP, original_inner_src_mac,
            rewrite_mac_1, ACL_TABLE_NAME, rule_name_1,
            expect_rewrite=False,
            test_description="VNI matches but IP does not",
            dut_vtep_ip=dut_vtep_ip
        )
        logger.info("=== Case 1 completed successfully ===")

        # Case 2: Source IP matches but VNI does not match. UNPROVISIONED_VNI is never provisioned
        # as a VNET; traffic is encapped with the primary VNET's VNI, so the rule can't match and
        # no extra VNET provisioning is needed.
        logger.info("=== Case 2: IP matches but VNI does not ===")
        setup_acl_rule(duthost, "202.2.2.100/32", str(UNPROVISIONED_VNI), rewrite_mac_2, rule_name_2)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "202.2.2.100", VNET_PRIMARY_ROUTE_IP, original_inner_src_mac,
            rewrite_mac_2, ACL_TABLE_NAME, rule_name_2,
            expect_rewrite=False,
            test_description="IP matches but VNI does not",
            dut_vtep_ip=dut_vtep_ip
        )
        logger.info("=== Case 2 completed successfully ===")

        logger.info("=== All partial match test cases completed successfully ===")

    finally:
        try:
            remove_acl_rules(duthost, [rule_name_1, rule_name_2])
            remove_acl_table(duthost)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def test_multiple_acl_rules(setUp):
    """
    Test two ACL rules with different source IPs and the same VNI.
    Validates that each rule matches only its configured source IP and that their
    counters increment independently.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    # Extract MAC addresses
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']

    # Test parameters
    test_src_ip_1 = "203.1.1.100"
    test_src_ip_2 = "203.1.1.200"  # Different source IP
    test_dst_ip = VNET_PRIMARY_ROUTE_IP
    test_vni = str(VXLAN_VNI)  # Same VNI for both rules
    rule_name_1 = "rule_multi_1"
    rule_name_2 = "rule_multi_2"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info("Creating two ACL rules with different source IPs and the same VNI")
        logger.info(f"Rule 1: src_ip={test_src_ip_1}, VNI={test_vni}, MAC={rewrite_mac_1}")
        logger.info(f"Rule 2: src_ip={test_src_ip_2}, VNI={test_vni}, MAC={rewrite_mac_2}")

        setup_acl_rule(duthost, f"{test_src_ip_1}/32", test_vni, rewrite_mac_1, rule_name_1)
        setup_acl_rule(duthost, f"{test_src_ip_2}/32", test_vni, rewrite_mac_2, rule_name_2)

        # Test Rule 1: Send packet matching first source IP
        logger.info(f"=== Testing Rule 1: {rule_name_1} with source IP {test_src_ip_1} ===")

        # Get initial counter for rule 1
        counter_1_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Initial counters - Rule 1: {counter_1_before}, Rule 2: {counter_2_before}")

        # Send packet that should match rule 1
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            test_src_ip_1, test_dst_ip, original_inner_src_mac,
            rewrite_mac_1,  # Should use MAC from rule 1
            ACL_TABLE_NAME, rule_name_1,
            dut_vtep_ip=dut_vtep_ip
        )

        # Check counters after rule 1 test
        counter_1_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Counters after rule 1 test - Rule 1: {counter_1_after}, Rule 2: {counter_2_after}")

        # Rule 1's own increment is asserted inside _send_and_verify_mac_rewrite; here we only
        # need the cross-rule isolation check that rule 2 did NOT match.
        pytest_assert(counter_2_after == counter_2_before,
                      f"Rule 2 counter should not have incremented: {counter_2_before} -> {counter_2_after}")

        # Test Rule 2: Send packet matching second source IP
        logger.info(f"=== Testing Rule 2: {rule_name_2} with source IP {test_src_ip_2} ===")

        # Update counters baseline
        counter_1_baseline = counter_1_after

        # Send packet that should match rule 2
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            test_src_ip_2, test_dst_ip, original_inner_src_mac,
            rewrite_mac_2,  # Should use MAC from rule 2
            ACL_TABLE_NAME, rule_name_2,
            dut_vtep_ip=dut_vtep_ip
        )

        # Check final counters
        counter_1_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Final counters - Rule 1: {counter_1_final}, Rule 2: {counter_2_final}")

        # Rule 2's own increment is asserted inside _send_and_verify_mac_rewrite; here we only
        # need the cross-rule isolation check that rule 1 did NOT match.
        pytest_assert(counter_1_final == counter_1_baseline,
                      f"Rule 1 counter should not have incremented: {counter_1_baseline} -> {counter_1_final}")

        # Summary
        logger.info("=== Test Summary ===")
        logger.info(
            f"Rule 1 ({test_src_ip_1}): {counter_1_before} -> {counter_1_final} "
            f"(increment: {counter_1_final - counter_1_before})"
        )
        logger.info(
            f"Rule 2 ({test_src_ip_2}): {counter_2_before} -> {counter_2_final} "
            f"(increment: {counter_2_final - counter_2_before})"
        )

        logger.info("=== Multiple ACL rules test completed successfully ===")

    finally:
        try:
            remove_acl_rules(duthost, [rule_name_1, rule_name_2])
            remove_acl_table(duthost)
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


@pytest.mark.supported_completeness_level(CompletenessLevel.debug, CompletenessLevel.basic,
                                          CompletenessLevel.confident, CompletenessLevel.thorough)
def test_scale_acl_rule(setUp, request):
    """
    Scale test: Program ACL rules with SAME PRIORITIES and test packet forwarding.

    The rule count is driven by --completeness_level (see SCALE_RULE_COUNT_LEVEL_MAP),
    ranging from 100 rules for 'debug' up to 9000 rules for 'thorough'.
    It verifies that all rules become Active and tests packet forwarding functionality
    at scale.

    Purpose:
    1. Behavioral analysis of same-priority rule handling
    2. Packet forwarding verification with priority conflicts
    3. Performance testing with scale + same priorities

    All programmed rules are expected to become Active; any Inactive rule fails the test.
    """

    normalized_level = CompletenessLevel.get_normalized_level(request)
    scale_rule_count = SCALE_RULE_COUNT_LEVEL_MAP[normalized_level]

    logger.info(f"=== STARTING {scale_rule_count}-RULE SCALE TEST (completeness level: {normalized_level}) ===")

    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    # Configuration values
    vxlan_tunnel_name = setUp['vxlan_tunnel_name']
    table_name = ACL_TABLE_NAME

    # Standard values from VXLAN/VNET configuration
    inner_dst_ip = VNET_PRIMARY_ROUTE_IP
    vni_id = str(VXLAN_VNI)  # VNI from configuration

    logger.info("=== Starting ACL Source MAC Rewrite Scale Test ===")
    logger.info(f"Target: {scale_rule_count} ACL rules")
    logger.info(f"Using VNI: {vni_id}")
    logger.info(f"IP range: {SCALE_IP_BASE}/{SCALE_IP_PREFIX}")

    try:
        # ===================================================================
        # STEP 1: Verify VXLAN/VNET infrastructure configured by the module fixture
        # ===================================================================
        logger.info("STEP 1: Verifying VXLAN/VNET infrastructure")

        logger.info("Verifying VNET route")
        pytest_assert(_check_vnet_route(duthost), "VNET route not found")

        logger.info("Verifying VXLAN tunnel")
        pytest_assert(_check_vxlan_tunnel_config(duthost, vxlan_tunnel_name),
                      f"VXLAN tunnel {vxlan_tunnel_name} not found")

        # ===================================================================
        # STEP 2: Setup ACL table and scale rules
        # ===================================================================
        logger.info("STEP 2: Setting up ACL table and scale rules")

        # Verify platform support for inner source MAC rewrite
        logger.info("Checking platform capabilities...")
        asic_type = duthost.facts.get('asic_type', 'unknown')
        hwsku = duthost.facts.get('hwsku', 'unknown')
        logger.info(f"Platform: {hwsku}, ASIC: {asic_type}")

        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Setup ACL rules with bulk JSON operation
        logger.info(f"Programming {scale_rule_count} ACL rules...")
        start_time = time.time()

        setup_bulk_acl_rules(duthost, scale_rule_count, vni_id, start_index=0)

        setup_time = time.time() - start_time
        logger.info(f"ACL rule programming completed in {setup_time:.2f} seconds")
        logger.info(f"Average time per rule: {(setup_time/scale_rule_count)*1000:.2f} ms")

        # ===================================================================
        # STEP 3: Packet testing with same-priority rules
        # ===================================================================
        logger.info("STEP 3: Testing packet forwarding with same-priority ACL rules")

        test_rule_count = scale_rule_count
        logger.info(f"Testing packet forwarding for {test_rule_count} rules with same priority "
                    f"({ACL_RULE_PRIORITY})")
        logger.info("Sending ONE packet per rule to test both MAC rewrite AND counter increment")

        packet_test_start = time.time()
        successful_tests = 0
        failed_tests = 0
        consecutive_failures = 0

        # Get ACL counters before testing (single bulk read instead of one per rule)
        counter_before = get_acl_counters(duthost, ACL_TABLE_NAME)

        for i in range(test_rule_count):
            rule_name = f"scale_rule_{i + 1:04d}"
            inner_src_ip = generate_ip_address(i, SCALE_IP_BASE, SCALE_IP_PREFIX)
            expected_new_src_mac = generate_mac_address(i)

            logger.info(f"Testing rule {i+1}/{test_rule_count}: {rule_name}")

            try:
                # Send single packet to test MAC rewrite; counter increments are checked in bulk below.
                _send_and_verify_mac_rewrite(
                    ptfadapter=ptfadapter,
                    ptf_port_1=ptf_port_1,
                    ptf_ports=ptf_port_2,
                    duthost=duthost,
                    src_ip=inner_src_ip,
                    dst_ip=inner_dst_ip,
                    orig_src_mac=SCALE_TEST_ORIG_MAC,
                    rewrite_mac=expected_new_src_mac,
                    table_name=table_name,
                    rule_name=rule_name,
                    scale_test=True,
                    test_description=f"scale test rule {rule_name}",
                    dut_vtep_ip=dut_vtep_ip
                )

                successful_tests += 1
                consecutive_failures = 0
                logger.info(f"✓ Rule {rule_name} packet test PASSED")

            except Exception as e:
                failed_tests += 1
                consecutive_failures += 1
                logger.error(f"✗ Rule {rule_name} packet test FAILED: {e}")
                # Continue testing other rules even if one fails, unless failures are piling up
                # consecutively - that points to a systemic problem (e.g. rules unexpectedly
                # cleared mid-test), and grinding through every remaining rule (each paying the
                # poll timeout plus a multi-command diagnostic dump) would waste hours.
                if consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT:
                    logger.error(
                        f"Aborting packet testing early after {consecutive_failures} consecutive "
                        f"failures (tested {i + 1}/{test_rule_count} rules) - this points to a "
                        f"systemic datapath/ACL issue rather than isolated rule failures"
                    )
                    break

        # Wait a moment for counters to update after testing
        time.sleep(20)
        # Get ACL counters after testing
        counter_after = get_acl_counters(duthost, ACL_TABLE_NAME)
        # Analyze counter increments
        counter_increment_successes = 0
        counter_increment_failures = 0
        for i in range(test_rule_count):
            rule_name = f"scale_rule_{i + 1:04d}"
            counter_before_value = counter_before.get(rule_name, 0)
            counter_after_value = counter_after.get(rule_name, 0)
            if counter_after_value > counter_before_value:
                logger.info(
                    f"✓ ACTIVE rule {rule_name} counter incremented: "
                    f"{counter_before_value} → {counter_after_value}"
                )
                counter_increment_successes += 1
            else:
                counter_increment_failures += 1
                logger.warning(
                    f"✗ ACTIVE rule {rule_name} counter did not increment: "
                    f"{counter_before_value} → {counter_after_value}"
                )

        packet_test_time = time.time() - packet_test_start
        success_rate = (successful_tests / test_rule_count) * 100

        logger.info("=== PACKET TESTING RESULTS ===")
        logger.info(f"Total rules tested: {test_rule_count}")
        logger.info(f"Successful packet tests: {successful_tests}")
        logger.info(f"Failed packet tests: {failed_tests}")
        logger.info(f"Counter increment successes: {counter_increment_successes}")
        logger.info(f"Counter increment failures: {counter_increment_failures}")
        logger.info(f"Packet test success rate: {success_rate:.1f}%")
        logger.info(f"Testing time: {packet_test_time:.2f} seconds")
        logger.info(f"Average time per test: {(packet_test_time/test_rule_count):.2f} seconds")

        if success_rate < 100:
            logger.error(f"Packet test success rate too low: {success_rate:.1f}%")
            logger.error(f"Failed tests: {failed_tests}/{test_rule_count}")
            pytest.fail(f"MAC rewrite verification failed - only {success_rate:.1f}% of packets passed verification. "
                        f"This indicates the INNER_SRC_MAC_REWRITE_ACTION is not working correctly.")
        else:
            logger.info("All packet tests passed successfully!")

        if counter_increment_failures > 0:
            counter_total = counter_increment_successes + counter_increment_failures
            logger.error(f"Counter increment failures detected: {counter_increment_failures}/{counter_total}")
            pytest.fail(f"ACL counter increments failed for {counter_increment_failures} rules. "
                        f"Verify that rules are properly active and packets are being matched.")

        # ===================================================================
        # STEP 4: Verify system performance and stability
        # ===================================================================
        logger.info("STEP 4: Verifying system performance and stability")

        # Check that ACL table is still functional
        logger.info("Verifying ACL table status")
        pytest_assert(_check_acl_table_present(duthost, ACL_TABLE_NAME),
                      f"ACL table {ACL_TABLE_NAME} missing after scale test")

        # Use the existing verify_acl_rules_installation function for comprehensive rule verification
        logger.info("Performing final verification of all ACL rules with SAME PRIORITY...")
        try:
            verify_acl_rules_installation(duthost, scale_rule_count)
            logger.info(f"All {scale_rule_count} ACL rules verified successfully")
        except Exception as e:
            logger.error(f"Final rule verification failed: {e}")

            # Additional debugging if verification fails
            show_acl_result = duthost.shell("show acl rule", module_ignore_errors=True)
            if show_acl_result["rc"] == 0:
                rule_count = show_acl_result["stdout"].count(ACL_TABLE_NAME)
                logger.error(f"'show acl rule' shows {rule_count} rules out of {scale_rule_count}")
                logger.info("Sample of 'show acl rule' output:")
                logger.info(show_acl_result["stdout"][:500])  # Show sample for debugging

            # Still report the actual count found
            pytest.fail(f"ACL rules verification failed: {e}")

        logger.info(f"=== {scale_rule_count}-RULE SCALE TEST COMPLETED ===")
        logger.info("SCALE TEST SUMMARY:")
        logger.info(f"- Programmed {scale_rule_count} ACL rules with SAME priority ({ACL_RULE_PRIORITY})")
        logger.info("- System behavior observed for priority conflict handling")
        logger.info("- Packet testing and counter verification performed for all programmed rules")
        logger.info("- Check logs above for rule installation and performance results")
        logger.info("- This scale test provides insights into hardware ACL capacity limits")

    finally:
        # ===================================================================
        # CLEANUP: Remove all scale rules and table
        # ===================================================================
        logger.info("CLEANUP: Removing scale test configuration")
        try:
            remove_bulk_acl_rules(duthost)
            remove_acl_table(duthost)
            logger.info("Scale test cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
