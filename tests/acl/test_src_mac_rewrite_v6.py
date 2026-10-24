"""
Tests ACL to modify inner source MAC in VXLAN-encapsulated IPv6 packets in SONiC.

This test suite validates the INNER_SRC_MAC_REWRITE_ACTION functionality
for ACL rules matching the inner IPv6 source address and VXLAN VNI.
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
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

ecmp_utils = Ecmp_Utils()

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')  # only ASIC supporting INNER_SRC_MAC_REWRITE_ACTION
]

ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
TMP_DIR = '/tmp'
CONFIG_DB_PATH = "/etc/sonic/config_db.json"

PTF_VTEP_IP = "100.0.1.10"
VXLAN_UDP_PORT = 4789
VXLAN_VNI = 10000
UNPROVISIONED_VNI = 30000   # never backed by a VNET; used for the VNI-mismatch negative test
VNET_PRIMARY_NAME = "Vnet-0"
VNET_PRIMARY_ROUTE_IP = "2001:db8:150::3"
VNET_PRIMARY_ROUTE_PREFIX = f"{VNET_PRIMARY_ROUTE_IP}/128"
VNET_INGRESS_IP = "2001:db8:201::1/64"
# Must differ from the real router_mac - Cisco-8000 ignores it otherwise.
VXLAN_ROUTER_MAC = "00:12:34:56:78:9a"

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_RULE_PRIORITY = "1000"  # shared by every rule in this module

SCALE_RULE_COUNT = 3000
SCALE_IPV6_BASE = "2001:db8:210::"  # distinct /64 from the functional tests' ranges
SCALE_IPV6_PREFIX = 64
SCALE_ORIGINAL_SRC_MAC = "00:aa:bb:cc:dd:ff"  # VNET routing rebuilds the inner Ethernet header,
                                                # so this value is never actually checked
CONSECUTIVE_FAILURE_LIMIT = 10  # abort the scale packet loop early after this many failures in a row


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
    """Fetch the VXLAN tunnel's source IP via CLI"""
    result = duthost.show_and_parse('show vxlan tunnel')
    for entry in result:
        if entry.get('vxlan tunnel name') == tunnel_name:
            return entry.get('source ip', '').strip()
    return None


def _check_vxlan_switch_config(duthost):
    result = duthost.shell('redis-cli -n 0 KEYS "SWITCH_TABLE:switch"', module_ignore_errors=True)
    return "SWITCH_TABLE:switch" in result.get("stdout", "")


def _select_vnet_ingress_port(mg_facts, cfg_facts):
    """Pick a server-facing VLAN-member port to repurpose as the VNET ingress. Returns
    (port_name, vlan_id, ptf_index), or (None, None, None) if none is available."""
    port_indices = mg_facts["minigraph_ptf_indices"]
    for vlan_name, members in cfg_facts.get("VLAN_MEMBER", {}).items():
        for member in members.keys():
            if member in port_indices:
                vlan_id = "".join(ch for ch in vlan_name if ch.isdigit())
                return member, vlan_id, port_indices[member]
    return None, None, None


def setup_vnet_ingress_datapath(duthost, ingress_port, vlan_id):
    """Detach the ingress port from its VLAN and bind it into the VNET as a routed port, so
    traffic entering it gets VNET-routed and VXLAN-encapsulated."""
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
    base_mac = "00:aa:bb:cc:dd"
    last_octet = f"{(index % 256):02x}"
    return f"{base_mac}:{last_octet}"


def generate_ipv6_address(index, base_ip=SCALE_IPV6_BASE, prefix=SCALE_IPV6_PREFIX):
    """
    Generate a unique IPv6 address from a base network using an index, for scale testing.
    """
    network = ipaddress.IPv6Network(f"{base_ip}/{prefix}", strict=False)
    max_hosts = 2**(128 - prefix) - 2  # Subtract network and all-ones addresses
    if index >= max_hosts:
        raise ValueError(f"Index {index} exceeds maximum hosts {max_hosts} for network {network}")
    return str(network.network_address + (index + 1))


def generate_scale_mac_address(index):
    """
    Generate a unique unicast MAC address from an index, covering up to 65535 distinct values
    (generate_mac_address only varies the last octet and wraps at 256, too few for scale testing).
    """
    if index >= 0x10000:
        raise ValueError(f"Index {index} exceeds the 65535 addresses encodable in the last two MAC octets")
    return f"aa:bb:cc:dd:{(index >> 8) & 0xff:02x}:{index & 0xff:02x}"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(request, rand_selected_dut, tbinfo, ptfadapter):
    if 'dualtor' in tbinfo['topo']['name']:
        pytest.skip("test_src_mac_rewrite does not support dualtor topology - "
                    "VXLAN tunnel config does not propagate to APP_DB on dualtor")

    data = {}

    data['duthost'] = rand_selected_dut
    data['ptfadapter'] = ptfadapter

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    # The outer VXLAN underlay remains IPv4, so select only Loopback0's IPv4 address.
    loopback0_ips = mg_facts["minigraph_lo_interfaces"]
    loopback_src_ip = None
    for intf in loopback0_ips:
        if intf["name"] == "Loopback0" and "." in intf["addr"]:
            loopback_src_ip = intf["addr"]
            break

    if not loopback_src_ip:
        pytest.fail("Could not find an IPv4 Loopback0 address for the VXLAN underlay")

    data['loopback_src_ip'] = loopback_src_ip

    cfg_facts = rand_selected_dut.get_running_config_facts()

    topo = tbinfo['topo']['properties']['topology']
    ptf_ports_available_in_topo = topo.get('ptf_map_disabled', {}).keys() if 'ptf_map_disabled' in topo else []
    if not ptf_ports_available_in_topo:
        ptf_ports_available_in_topo = list(mg_facts["minigraph_ptf_indices"].values())

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

    ingress_port_name, ingress_vlan_id, ingress_ptf_port = _select_vnet_ingress_port(mg_facts, cfg_facts)
    if not ingress_port_name:
        pytest.fail("Could not find a VLAN-member port to repurpose as the VNET ingress")

    data['ptf_port_1'] = ingress_ptf_port
    data['ptf_port_2'] = receive_ptf_ports
    data['vnet_ingress_port'] = ingress_port_name
    data['vnet_ingress_vlan'] = ingress_vlan_id
    data['bind_ports'] = list(pc_members.keys())

    data['test_scenarios'] = {
        'single_ipv6_test': {
            'original_mac': generate_mac_address(1),
            'first_modified_mac': generate_mac_address(2),
            'second_modified_mac': generate_mac_address(3)
        },
        'range_ipv6_test': {
            'original_mac': generate_mac_address(4),
            'first_modified_mac': generate_mac_address(5),
            'second_modified_mac': generate_mac_address(6)
        },
        'multi_vni_ipv6_test': {
            'original_mac': generate_mac_address(7),
            'first_modified_mac': generate_mac_address(8),
            'second_modified_mac': generate_mac_address(9),
            'third_modified_mac': generate_mac_address(10)
        }
    }

    data['vxlan_tunnel_name'] = "tunnel_v4"

    backup_config(rand_selected_dut)

    # Register cleanup as a finalizer (not a separate tearDown fixture) so it still runs even
    # if setUp fails partway through, instead of leaving the DUT with unclean CONFIG_DB.
    request.addfinalizer(lambda: cleanup_test_configuration(rand_selected_dut, data['vxlan_tunnel_name']))

    create_vxlan_vnet_config(
        duthost=rand_selected_dut,
        tunnel_name=data['vxlan_tunnel_name'],
        src_ip=data['loopback_src_ip'],
    )

    vnet_list = rand_selected_dut.show_and_parse('show vnet brief')
    pytest_assert(any(entry.get('vnet name') == VNET_PRIMARY_NAME for entry in vnet_list),
                  f"{VNET_PRIMARY_NAME} not found in 'show vnet brief' output")

    if not wait_until(60, 5, 5, _check_vnet_route, rand_selected_dut):
        vnet_route_state = rand_selected_dut.shell(
            "redis-cli -n 6 HGETALL '{}'".format(
                _vnet_route_state_db_key(VNET_PRIMARY_NAME, VNET_PRIMARY_ROUTE_PREFIX)
            ),
            module_ignore_errors=True
        )["stdout"]
        logger.error("STATE_DB VNET route entry:\n%s", vnet_route_state)
        pytest.fail(f"VNET route for {VNET_PRIMARY_ROUTE_PREFIX} is not active in STATE_DB")

    # Without this, ingress traffic is plain-routed and the ACL never sees it.
    setup_vnet_ingress_datapath(rand_selected_dut, data['vnet_ingress_port'], data['vnet_ingress_vlan'])

    return data


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL, prev_count=0):
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
    Get the ACL counter packet value for every rule in `table_name`, keyed by rule name. Used by
    the scale test to diff before/after counts in bulk (one 'aclshow -a' call for all rules)
    instead of checking each rule's counter individually, which would be too slow at scale.
    """
    result = duthost.show_and_parse('aclshow -a')
    if not result:
        logger.warning(f"Failed to retrieve ACL counters for table {table_name}")
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
            counters[rule_name] = 0
    return counters


def setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE):
    acl_table_type_data = {
        "ACL_TABLE_TYPE": {
            acl_type_name: {
                "BIND_POINTS": [
                    "PORT",
                    "PORTCHANNEL"
                ],
                "MATCHES": [
                    "INNER_SRC_IPV6",
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


def setup_acl_rule(duthost, inner_src_ipv6, vni, new_src_mac, rule_name="rule_1", priority=ACL_RULE_PRIORITY):
    """Create (or update) an ACL rule via 'config load -y' and wait until it is active."""
    acl_rule = {
        "ACL_RULE": {
            f"{ACL_TABLE_NAME}|{rule_name}": {
                "PRIORITY": priority,
                "TUNNEL_VNI": vni,
                "INNER_SRC_IPV6": inner_src_ipv6,
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


def modify_acl_rule(duthost, inner_src_ipv6, vni, new_src_mac):
    logger.info("Modifying ACL rule with new MAC: %s", new_src_mac)
    # Re-applying the rule via config load properly triggers change notifications.
    setup_acl_rule(duthost, inner_src_ipv6, vni, new_src_mac)
    logger.info("ACL rule successfully modified to use MAC: %s", new_src_mac)


def remove_acl_rules(duthost, rule_names=("rule_1",)):
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))

    for rule_name in rule_names:
        pytest_assert(wait_until(30, 5, 2, _check_acl_rule_absent, duthost, ACL_TABLE_NAME, rule_name),
                      f"ACL rule {rule_name} still in STATE_DB after removal")


def count_active_acl_rules(duthost, table_name=ACL_TABLE_NAME):
    """
    Return the number of rules reported as Active for `table_name`. Uses structured
    'show acl rule' parsing (table/status fields) rather than raw text/line matching, since a
    rule can have a STATE_DB entry while still being Inactive (e.g. ASIC resource exhaustion at
    scale) - and raw substring matching is more fragile than matching parsed fields exactly.
    """
    rules = duthost.show_and_parse("show acl rule", module_ignore_errors=True)
    return len([r for r in rules
                if r.get('table') == table_name and r.get('status', '').lower() == 'active'])


def _check_scale_rules_active(duthost, table_name, expected_count):
    active_count = count_active_acl_rules(duthost, table_name)
    logger.info(f"ACL rules Active: {active_count}/{expected_count}")
    return active_count == expected_count


def _check_no_active_acl_rules(duthost, database, pattern):
    """Uses --scan (not KEYS) since it is non-blocking and scales better for a large keyspace."""
    result = duthost.shell(f"redis-cli -n {database} --scan --pattern '{pattern}' | head -n 1")
    return not result["stdout"].strip()


def setup_bulk_acl_rules(duthost, rule_count, vni=VXLAN_VNI):
    """
    Bulk-create `rule_count` ACL rules in a single 'config load -y' operation (one big JSON)
    instead of one-at-a-time rule creation. All rules share ACL_RULE_PRIORITY, matching this
    module's existing single-priority convention. Returns {rule_name: (inner_src_ipv6, new_src_mac)}.
    """
    rule_info = {}
    acl_rules = {"ACL_RULE": {}}

    logger.info(f"Generating {rule_count} rule configurations...")
    generation_start = time.time()
    for i in range(rule_count):
        rule_name = f"scale_rule_{i + 1:04d}"
        inner_src_ipv6 = generate_ipv6_address(i)
        new_src_mac = generate_scale_mac_address(i)
        rule_info[rule_name] = (inner_src_ipv6, new_src_mac)
        acl_rules["ACL_RULE"][f"{ACL_TABLE_NAME}|{rule_name}"] = {
            "PRIORITY": ACL_RULE_PRIORITY,
            "TUNNEL_VNI": str(vni),
            "INNER_SRC_IPV6": f"{inner_src_ipv6}/128",
            "INNER_SRC_MAC_REWRITE_ACTION": new_src_mac
        }
    logger.info(f"Generated {rule_count} rule configurations in {time.time() - generation_start:.2f}s")

    logger.info(f"Applying {rule_count} bulk ACL rules via a single 'config load -y'...")
    apply_config_chunk(duthost, acl_rules, "acl_scale_rules")

    active_timeout = 60 + rule_count // 10
    logger.info(f"Waiting up to {active_timeout}s for all {rule_count} ACL rules to become Active...")
    pytest_assert(wait_until(active_timeout, 10, 5, _check_scale_rules_active, duthost, ACL_TABLE_NAME, rule_count),
                  f"Only {count_active_acl_rules(duthost, ACL_TABLE_NAME)} of {rule_count} ACL rules "
                  f"became Active within {active_timeout}s")

    return rule_info


def remove_bulk_acl_rules(duthost):
    """
    Wipe all rules from ACL_TABLE_NAME via the same acl-loader full-update del file used by
    remove_acl_rules, then wait for absence in BOTH CONFIG_DB and STATE_DB (checking each of
    potentially thousands of rule names individually would be too slow).
    """
    config_rule_pattern = f"ACL_RULE|{ACL_TABLE_NAME}|*"
    count_cmd = f"redis-cli -n 4 --scan --pattern '{config_rule_pattern}' | wc -l"
    rule_count = int(duthost.shell(count_cmd)["stdout"].strip() or 0)
    logger.info(f"Found {rule_count} rules to remove from CONFIG_DB")

    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))

    removal_timeout = 60 + rule_count // 10
    pytest_assert(
        wait_until(removal_timeout, 1, 0, _check_no_active_acl_rules, duthost, 4, config_rule_pattern),
        f"ACL rules for {ACL_TABLE_NAME} still present in CONFIG_DB after bulk removal")

    state_rule_pattern = f"ACL_RULE_TABLE*{ACL_TABLE_NAME}*"
    pytest_assert(
        wait_until(removal_timeout, 2, 0, _check_no_active_acl_rules, duthost, 6, state_rule_pattern),
        f"ACL rules for {ACL_TABLE_NAME} still present in STATE_DB after bulk removal")

    logger.info(f"Successfully removed {rule_count} ACL rules")


def verify_scale_acl_rules_installation(duthost, expected_count):
    """
    Verify that exactly `expected_count` ACL rules are installed and Active, checking CONFIG_DB,
    STATE_DB, and 'show acl rule' Active status. Called once right after bulk setup and again
    after the packet-test loop, to also catch rules that went Inactive mid-test.
    """
    logger.info(f"Verifying {expected_count} ACL rules are installed")

    config_rules = duthost.shell(f"redis-cli -n 4 KEYS 'ACL_RULE|{ACL_TABLE_NAME}|*'")["stdout_lines"]
    config_rule_count = len([key for key in config_rules if key.strip()])
    logger.info(f"Number of rules in CONFIG_DB: {config_rule_count}")
    pytest_assert(config_rule_count == expected_count,
                  f"CONFIG_DB has {config_rule_count} rules, expected {expected_count}")

    state_rules = duthost.shell(f"redis-cli -n 6 KEYS 'ACL_RULE_TABLE|{ACL_TABLE_NAME}|*'")["stdout_lines"]
    state_rule_count = len([key for key in state_rules if key.strip()])
    logger.info(f"Number of rules in STATE_DB: {state_rule_count}")

    active_count = count_active_acl_rules(duthost, ACL_TABLE_NAME)
    pytest_assert(active_count == expected_count,
                  f"Expected {expected_count} Active ACL rules, found {active_count} "
                  f"(STATE_DB has {state_rule_count} rule entries total) - this indicates hardware "
                  f"resource limits or priority conflicts")

    def _counters_ready(duthost):
        res = duthost.shell("aclshow -a")['stdout_lines']
        return len(res) > 2 and not any('N/A' in line for line in res)

    if not wait_until(60, 5, 5, _counters_ready, duthost):
        logger.warning("ACL rule counters are not ready after rule installation (not fatal)")
    else:
        logger.info("ACL rule counters are ready")

    logger.info(f"Verified {expected_count} ACL rules are installed and Active")


def create_vxlan_vnet_config(duthost, tunnel_name, src_ip):
    vnet_base = VXLAN_VNI
    ptf_vtep = PTF_VTEP_IP

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True
    ecmp_utils.Constants['DEBUG'] = False

    vxlan_tunnel_entry = {"src_ip": src_ip}
    # cisco-8000 needs explicit pipe TTL mode or orchagent's DECAP_TTL_MODE is inconsistent.
    if duthost.facts.get("asic_type") == "cisco-8000":
        vxlan_tunnel_entry["ttl_mode"] = "pipe"
    tunnel_config = {
        "VXLAN_TUNNEL": {
            tunnel_name: vxlan_tunnel_entry
        }
    }

    logger.info("Creating VXLAN tunnel:\n%s", json.dumps(tunnel_config, indent=4))
    apply_config_chunk(duthost, tunnel_config, "vxlan_tunnel")

    pytest_assert(wait_until(30, 2, 2, _check_vxlan_tunnel_config, duthost, tunnel_name),
                  f"VXLAN tunnel {tunnel_name} not found in CONFIG_DB after apply")

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

    vnet_name = list(vnet_vni_map.keys())[0]

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
        logger.info("Restoring original configuration from backup...")
        result = duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}", module_ignore_errors=True)

        if result.get("rc", 0) != 0:
            logger.warning("Backup file not found or move failed, trying alternative cleanup...")
            try:
                logger.info("Attempting manual ACL cleanup as fallback...")
                duthost.shell(f"config acl remove table {ACL_TABLE_NAME}", module_ignore_errors=True)
            except Exception as e:
                logger.warning(f"Manual ACL cleanup failed: {e}")
        else:
            logger.info("Configuration backup restored successfully")

        logger.info("Reloading configuration to apply restored settings...")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        logger.info("Configuration reload completed")

    except Exception as e:
        logger.error(f"Failed during configuration cleanup: {e}")

    finally:
        try:
            logger.info("Cleaning up temporary files...")
            temp_files = [
                f"/tmp/{ACL_REMOVE_RULES_FILE}",
                os.path.join(TMP_DIR, f"{ACL_TABLE_TYPE.lower()}_acl_type.json"),
                "/tmp/vxlan_tunnel_chunk.json",
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


def _log_vxlan_datapath_state(duthost, inner_src_ipv6, inner_dst_ipv6, rule_name):
    """Dump VNET/underlay/ACL state to distinguish a missing-encap datapath problem from a
    packet-content mismatch when no encapsulated packet is received."""
    diag_cmds = [
        "show vnet route all",
        "show vxlan tunnel",
        "show ip route {}".format(PTF_VTEP_IP),
        "show arp {}".format(PTF_VTEP_IP),
        "show ipv6 route {}".format(inner_dst_ipv6),
        "aclshow -a",
    ]
    logger.error("=== VXLAN datapath diagnostics (no encapsulated packet received for "
                 "inner_src=%s inner_dst=%s rule=%s) ===", inner_src_ipv6, inner_dst_ipv6, rule_name)
    for cmd in diag_cmds:
        try:
            out = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
        except Exception as e:
            out = "<failed to run '{}': {}>".format(cmd, e)
        logger.error("--- %s ---\n%s", cmd, out)


# Mask.set_do_not_care_packet() re-serializes and re-parses the whole packet via scapy on every
# call, which is slow when repeated thousands of times. Since every packet built by
# _send_and_verify_mac_rewrite has the same layout, cache the resulting mask bit array (keyed by
# packet length) and reuse it instead of rebuilding it every call.
_MASK_TEMPLATE_CACHE = {}


def _build_expected_packet_mask(expected_pkt):
    masked = Mask(expected_pkt)
    masked.set_ignore_extra_bytes()

    cached = _MASK_TEMPLATE_CACHE.get(len(expected_pkt))
    if cached is not None:
        masked.mask = list(cached)
        return masked

    masked.set_do_not_care_packet(scapy.Ether, "dst")
    masked.set_do_not_care_packet(scapy.UDP, "sport")
    masked.set_do_not_care_packet(scapy.UDP, "dport")
    masked.set_do_not_care_packet(scapy.UDP, "chksum")
    masked.set_do_not_care_packet(scapy.IP, "ttl")
    masked.set_do_not_care_packet(scapy.IP, "chksum")
    masked.set_do_not_care_packet(scapy.IP, "id")
    masked.set_do_not_care_packet(scapy.IP, "len")
    masked.set_do_not_care_packet(scapy.IP, "tos")
    _MASK_TEMPLATE_CACHE[len(expected_pkt)] = list(masked.mask)
    return masked


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, ptf_ports, duthost,
                                 src_ipv6, dst_ipv6, orig_src_mac, rewrite_mac,
                                 table_name, rule_name, expect_rewrite=True,
                                 vni=VXLAN_VNI, test_description="", scale_test=False,
                                 dut_vtep_ip=None):
    """
    Send one IPv6 test packet from the PTF host and verify whether the ACL rewrote the inner
    source MAC of the DUT egressed VXLAN packet.

    A full expected VXLAN packet is built and matched.
    The expected inner source MAC depends on the case: the rewrite MAC
    when the rule fires, otherwise the DUT's router_mac.

    The ACL counter must increment when expect_rewrite is True, and stay same otherwise.
    """
    router_mac = duthost.facts["router_mac"]
    if dut_vtep_ip is None:
        dut_vtep_ip = _get_vxlan_tunnel_src_ip(duthost, "tunnel_v4")
    pytest_assert(dut_vtep_ip, "VXLAN tunnel src_ip is empty in 'show vxlan tunnel' output")
    # The ASIC uses the configured tunnel MAC (VXLAN_ROUTER_MAC) as the inner eth_dst.
    vxlan_router_mac = VXLAN_ROUTER_MAC
    logger.info("vxlan_router_mac=%s, router_mac=%s", vxlan_router_mac, router_mac)

    input_pkt = testutils.simple_tcpv6_packet(
        pktlen=100, eth_dst=router_mac, eth_src=orig_src_mac,
        ipv6_dst=dst_ipv6, ipv6_src=src_ipv6, ipv6_hlim=64,
        tcp_sport=1234, tcp_dport=5000, ipv6_ecn=0)
    expected_inner_src_mac = rewrite_mac if expect_rewrite else router_mac
    inner_exp = testutils.simple_tcpv6_packet(
        pktlen=100, eth_src=expected_inner_src_mac, eth_dst=vxlan_router_mac,
        ipv6_src=src_ipv6, ipv6_dst=dst_ipv6, ipv6_hlim=63,
        tcp_sport=1234, tcp_dport=5000, ipv6_ecn=0)
    expected_pkt = testutils.simple_vxlan_packet(
        eth_src=router_mac, eth_dst="ff:ff:ff:ff:ff:ff",
        ip_src=dut_vtep_ip, ip_dst=PTF_VTEP_IP, ip_id=0, ip_flags=0x2,
        udp_sport=0, udp_dport=VXLAN_UDP_PORT, with_udp_chksum=False,
        vxlan_vni=vni, inner_frame=inner_exp)

    masked = _build_expected_packet_mask(expected_pkt)

    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0) if not scale_test else None
    logger.info("=== MAC Rewrite Test (expect_rewrite=%s, rule=%s, %s) ===",
                expect_rewrite, rule_name, test_description)
    logger.info("Sending test packet for rule %s", rule_name)

    # testutils.send (not send_packet) is required: the ptfadapter overrides send/dp_poll to tag
    # the payload with a per-module pattern on both the injected and expected packets.
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port_1, input_pkt, 1)

    # timeout=1: the rule is already confirmed Active before any packet is sent, so a match
    # should arrive almost immediately
    try:
        testutils.verify_packet_any_port(ptfadapter, masked, ptf_ports, timeout=1)
    except Exception:
        _log_vxlan_datapath_state(duthost, src_ipv6, dst_ipv6, rule_name)
        raise

    if not scale_test:
        if expect_rewrite:
            # The rule fired: wait for orchagent to flush the incremented counter.
            count_after = get_acl_counter(duthost, table_name, rule_name, prev_count=count_before)
            pytest_assert(count_after >= count_before + 1,
                          f"ACL counter did not increment for {src_ipv6}. "
                          f"before={count_before}, after={count_after}.")
        else:
            # The rule must NOT fire: read immediately (no reason to wait) and require a flat counter.
            count_after = get_acl_counter(duthost, table_name, rule_name, timeout=0)
            pytest_assert(count_after == count_before,
                          f"ACL counter incremented unexpectedly for partial match "
                          f"({test_description}): before={count_before}, after={count_after}")
        logger.info("ACL counter for IPv6 address %s: before=%s, after=%s",
                    src_ipv6, count_before, count_after)


def _test_inner_src_mac_rewrite(setUp, scenario_name):
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter'] 
    scenario = setUp['test_scenarios'][scenario_name]

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    original_inner_src_mac = scenario['original_mac']
    first_modified_mac = scenario['first_modified_mac']
    second_modified_mac = scenario['second_modified_mac']

    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME

    inner_dst_ipv6 = VNET_PRIMARY_ROUTE_IP
    vni_id = str(VXLAN_VNI)
    inner_src_ipv6 = "2001:db8:201::101"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        if scenario_name == "single_ipv6_test":
            acl_rule_prefix = f"{inner_src_ipv6}/128"
            logger.info(f"Single IPv6 test: Using ACL rule prefix {acl_rule_prefix}")
        else:  # range_ipv6_test
            acl_rule_prefix = "2001:db8:201::/64"
            logger.info(f"IPv6 range test: Using ACL rule prefix {acl_rule_prefix}")

        setup_acl_rule(duthost, acl_rule_prefix, vni_id, first_modified_mac)

        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ipv6, inner_dst_ipv6, original_inner_src_mac,
            first_modified_mac, table_name, RULE_NAME, dut_vtep_ip=dut_vtep_ip
        )

        # Range test additionally checks other addresses within the same /64.
        if scenario_name == "range_ipv6_test":
            test_ipv6_addresses = [
                "2001:db8:201::102",
                "2001:db8:201::103",
                "2001:db8:201::104",
            ]
            for test_ipv6 in test_ipv6_addresses:
                logger.info(f"IPv6 range test: Verifying rewrite with address {test_ipv6}")
                _send_and_verify_mac_rewrite(
                    ptfadapter, ptf_port_1, ptf_port_2, duthost, test_ipv6, inner_dst_ipv6, original_inner_src_mac,
                    first_modified_mac, table_name, RULE_NAME, dut_vtep_ip=dut_vtep_ip)

        # Re-applying an existing rule updates it in place
        logger.info("Step 3: Modifying ACL rule to use new MAC: %s", second_modified_mac)
        modify_acl_rule(duthost, acl_rule_prefix, vni_id, second_modified_mac)

        logger.info("Step 4: Verifying rewrite with second modified MAC: %s", second_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ipv6, inner_dst_ipv6, original_inner_src_mac,
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


def test_single_ipv6_acl_rule(setUp):
    """
    Test inner source MAC rewriting with an exact IPv6 (/128) ACL match.
    """
    _test_inner_src_mac_rewrite(setUp, "single_ipv6_test")


def test_range_ipv6_acl_rule(setUp):
    """
    Test inner source MAC rewriting with an IPv6 subnet (/64) ACL match.
    """
    _test_inner_src_mac_rewrite(setUp, "range_ipv6_test")


def test_partial_match(setUp):
    """
    Test partial match cases for ACL rules:
      1. VNI matches but source IPv6 does not - rule should not trigger.
      2. Source IPv6 matches but VNI does not - rule should not trigger.
    Validates that both INNER_SRC_IPV6 and TUNNEL_VNI must match for an ACL
    rule to fire; a partial match should not increment counters or rewrite the MAC.
    """
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_ipv6_test']
    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']
    rule_name_1 = "rule_vni_match_no_ipv6"
    rule_name_2 = "rule_ipv6_match_no_vni"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info("=== Case 1: VNI matches but IPv6 does not ===")
        setup_acl_rule(duthost, "2001:db8:202:1::100/128", str(VXLAN_VNI), rewrite_mac_1, rule_name_1)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "2001:db8:202:1::200", VNET_PRIMARY_ROUTE_IP, original_inner_src_mac,
            rewrite_mac_1, ACL_TABLE_NAME, rule_name_1,
            expect_rewrite=False,
            test_description="VNI matches but IPv6 does not",
            dut_vtep_ip=dut_vtep_ip
        )
        logger.info("=== Case 1 completed successfully ===")

        # UNPROVISIONED_VNI
        logger.info("=== Case 2: IPv6 matches but VNI does not ===")
        setup_acl_rule(duthost, "2001:db8:202:2::100/128", str(UNPROVISIONED_VNI), rewrite_mac_2, rule_name_2)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "2001:db8:202:2::100", VNET_PRIMARY_ROUTE_IP, original_inner_src_mac,
            rewrite_mac_2, ACL_TABLE_NAME, rule_name_2,
            expect_rewrite=False,
            test_description="IPv6 matches but VNI does not",
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
    Test two ACL rules with different source IPv6 addresses and the same VNI.
    Validates that each rule matches only its configured source IPv6 and that their
    counters increment independently.
    """
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_ipv6_test']

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']

    test_src_ipv6_1 = "2001:db8:203:1::100"
    test_src_ipv6_2 = "2001:db8:203:1::200"
    test_dst_ipv6 = VNET_PRIMARY_ROUTE_IP
    test_vni = str(VXLAN_VNI)
    rule_name_1 = "rule_multi_1"
    rule_name_2 = "rule_multi_2"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info("Creating two ACL rules with different source IPv6 addresses and the same VNI")
        logger.info(f"Rule 1: src_ipv6={test_src_ipv6_1}, VNI={test_vni}, MAC={rewrite_mac_1}")
        logger.info(f"Rule 2: src_ipv6={test_src_ipv6_2}, VNI={test_vni}, MAC={rewrite_mac_2}")

        setup_acl_rule(duthost, f"{test_src_ipv6_1}/128", test_vni, rewrite_mac_1, rule_name_1)
        setup_acl_rule(duthost, f"{test_src_ipv6_2}/128", test_vni, rewrite_mac_2, rule_name_2)

        logger.info(f"=== Testing Rule 1: {rule_name_1} with source IPv6 {test_src_ipv6_1} ===")

        counter_1_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Initial counters - Rule 1: {counter_1_before}, Rule 2: {counter_2_before}")

        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            test_src_ipv6_1, test_dst_ipv6, original_inner_src_mac,
            rewrite_mac_1,
            ACL_TABLE_NAME, rule_name_1, dut_vtep_ip=dut_vtep_ip
        )

        counter_1_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Counters after rule 1 test - Rule 1: {counter_1_after}, Rule 2: {counter_2_after}")

        # Rule 1's own increment is asserted inside _send_and_verify_mac_rewrite; here we only
        # need the cross-rule isolation check that rule 2 did NOT match.
        pytest_assert(counter_2_after == counter_2_before,
                      f"Rule 2 counter should not have incremented: {counter_2_before} -> {counter_2_after}")

        logger.info(f"=== Testing Rule 2: {rule_name_2} with source IPv6 {test_src_ipv6_2} ===")

        counter_1_baseline = counter_1_after

        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            test_src_ipv6_2, test_dst_ipv6, original_inner_src_mac,
            rewrite_mac_2,
            ACL_TABLE_NAME, rule_name_2, dut_vtep_ip=dut_vtep_ip
        )

        counter_1_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Final counters - Rule 1: {counter_1_final}, Rule 2: {counter_2_final}")

        # Rule 2's own increment is asserted inside _send_and_verify_mac_rewrite; here we only
        # need the cross-rule isolation check that rule 1 did NOT match.
        pytest_assert(counter_1_final == counter_1_baseline,
                      f"Rule 1 counter should not have incremented: {counter_1_baseline} -> {counter_1_final}")

        logger.info("=== Test Summary ===")
        logger.info(
            f"Rule 1 ({test_src_ipv6_1}): {counter_1_before} -> {counter_1_final} "
            f"(increment: {counter_1_final - counter_1_before})"
        )
        logger.info(
            f"Rule 2 ({test_src_ipv6_2}): {counter_2_before} -> {counter_2_final} "
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


def test_scale_ipv6_acl_rule(setUp):
    """
    Scale test: bulk-install SCALE_RULE_COUNT ACL rules each matching a distinct inner IPv6 source
    address and VNI, then send one packet per rule and verify its inner MAC rewrite. ACL counters
    are checked in bulk before/after the whole packet send loop rather than per rule, and rule
    installation is re-verified both before and after the packet loop.
    """
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    dut_vtep_ip = setUp['loopback_src_ip']

    rule_count = SCALE_RULE_COUNT

    logger.info(f"=== STARTING {rule_count}-RULE IPv6 SCALE TEST ===")
    logger.info("WARNING: this is a high-scale test that may hit hardware ACL resource limits")

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info(f"Bulk-programming {rule_count} ACL rules via a single 'config load -y'...")
        rule_info = setup_bulk_acl_rules(duthost, rule_count)

        verify_scale_acl_rules_installation(duthost, rule_count)

        counter_before = get_acl_counters(duthost, ACL_TABLE_NAME)

        packet_failures = []
        consecutive_failures = 0
        for i, (rule_name, (inner_src_ipv6, new_src_mac)) in enumerate(rule_info.items()):
            logger.info(f"Testing rule {i + 1}/{rule_count}: {rule_name} (src={inner_src_ipv6})")
            try:
                _send_and_verify_mac_rewrite(
                    ptfadapter, ptf_port_1, ptf_port_2, duthost,
                    inner_src_ipv6, VNET_PRIMARY_ROUTE_IP, SCALE_ORIGINAL_SRC_MAC, new_src_mac,
                    ACL_TABLE_NAME, rule_name, scale_test=True,
                    test_description=f"scale test rule {rule_name}", dut_vtep_ip=dut_vtep_ip
                )
                consecutive_failures = 0
                logger.info(f"✓ Rule {rule_name} packet test PASSED")
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"✗ Rule {rule_name} packet test FAILED: {e}")
                packet_failures.append(rule_name)
                # A run of consecutive failures points to a systemic problem (e.g. rules
                # unexpectedly cleared mid-test), not isolated flakiness - abort early instead of
                # grinding through every remaining rule, each paying its own timeout.
                if consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT:
                    logger.error(
                        f"Aborting packet testing early after {consecutive_failures} consecutive "
                        f"failures (tested {i + 1}/{rule_count} rules)"
                    )
                    break

        # Poll for counters to settle instead of a fixed sleep - orchagent's counter flush can
        # plausibly take longer than a fixed guess under load at thousands of rules.
        def _check_counter_increments(duthost):
            counters = get_acl_counters(duthost, ACL_TABLE_NAME)
            incremented = sum(1 for name, before in counter_before.items() if counters.get(name, 0) > before)
            return incremented >= (rule_count - len(packet_failures))

        wait_until(20 + rule_count // 50, 2, 0, _check_counter_increments, duthost)
        counter_after = get_acl_counters(duthost, ACL_TABLE_NAME)

        counter_failures = []
        for rule_name in rule_info:
            before_count = counter_before.get(rule_name, 0)
            after_count = counter_after.get(rule_name, 0)
            if after_count <= before_count:
                counter_failures.append(f"{rule_name}: {before_count} -> {after_count}")

        # Re-checks all rules are still Active after the packet loop, catching any that went
        # Inactive mid-test (e.g. evicted under hardware resource pressure).
        logger.info("Performing final re-verification of all ACL rules after packet testing...")
        try:
            verify_scale_acl_rules_installation(duthost, rule_count)
            logger.info(f"All {rule_count} ACL rules re-verified successfully after packet testing")
        except Exception as e:
            logger.error(f"Final rule re-verification failed: {e}")
            pytest.fail(f"ACL rules re-verification after packet testing failed: {e}")

        success_count = rule_count - len(packet_failures)
        success_rate = (success_count / rule_count) * 100

        logger.info("=== SCALE TEST RESULTS ===")
        logger.info(f"Packet tests passed: {success_count}/{rule_count} ({success_rate:.1f}%)")
        logger.info(f"Counter increments confirmed: {rule_count - len(counter_failures)}/{rule_count}")

        if packet_failures:
            logger.error(f"First 20 of {len(packet_failures)} packet failures:\n" +
                        "\n".join(packet_failures[:20]))
        if counter_failures:
            logger.error(f"First 20 of {len(counter_failures)} counter failures:\n" +
                        "\n".join(counter_failures[:20]))

        pytest_assert(not packet_failures,
                      f"{len(packet_failures)}/{rule_count} scale ACLS rules failed inner MAC rewrite "
                      f"verification")
        pytest_assert(not counter_failures,
                      f"{len(counter_failures)}/{rule_count} scale ACL rules did not increment their "
                      f"counter")

        logger.info(f"=== {rule_count}-RULE IPv6 SCALE TEST COMPLETED SUCCESSFULLY ===")

    finally:
        logger.info("CLEANUP: Removing scale test ACL rules and table")
        try:
            remove_bulk_acl_rules(duthost)
            remove_acl_table(duthost)
            logger.info("Scale test cleanup completed")
        except Exception as e:
            logger.error(f"Scale test cleanup failed: {e}")
