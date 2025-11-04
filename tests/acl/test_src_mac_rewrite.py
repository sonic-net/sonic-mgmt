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
from ptf import mask
from scapy.all import Ether, IP, UDP
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from ptf import testutils
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.config_reload import config_reload

ecmp_utils = Ecmp_Utils()

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),  # Only run on T0 testbed
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

# Test configuration constants
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"


def generate_mac_address(index):
    """
    Generate a MAC address using an index.
    Similar to how IPs are generated dynamically.
    
    Args:
        index: Numeric index for MAC generation
        
    Returns:
        MAC address string in format "00:aa:bb:cc:dd:xx"
    """
    base_mac = "00:aa:bb:cc:dd"
    last_octet = f"{(index % 256):02x}"
    return f"{base_mac}:{last_octet}"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(rand_selected_dut, tbinfo, ptfadapter):
    """
    Module-scoped fixture that sets up test infrastructure and configuration.
    Uses consistent VXLAN/VNET configuration for reliable testing.
    """
    data = {}
    
    # Basic setup
    data['duthost'] = rand_selected_dut
    data['tbinfo'] = tbinfo
    data['ptfadapter'] = ptfadapter
    
    # Get minigraph facts
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    data['mg_facts'] = mg_facts
    
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
    
    # Get port configuration
    eth_to_portchannel = {}
    for pc_name, pc_data in mg_facts["minigraph_portchannels"].items():
        for member in pc_data["members"]:
            eth_to_portchannel[member] = pc_name
    
    # Send on port 24, expect on any of the PortChannel PTF ports
    send_ptf_port = 24
    expected_ptf_ports = [24, 25, 26, 27]  # PortChannel mapped PTF ports
    
    # Verify the send port exists
    send_port_name = None
    for eth_port, ptf_idx in mg_facts["minigraph_ptf_indices"].items():
        if ptf_idx == send_ptf_port:
            pc_name = eth_to_portchannel.get(eth_port)
            send_port_name = pc_name if pc_name else eth_port
            break
    
    if not send_port_name:
        pytest.fail(f"PTF port {send_ptf_port} not found in minigraph")
    
    data['ptf_port_1'] = send_ptf_port        # Send port
    data['ptf_port_2'] = expected_ptf_ports   # List of expected receive ports
    data['test_port_1'] = send_port_name
    data['test_port_2'] = "PortChannel101"    # Expected egress PortChannel
    
    # Get bindable ports for ACL table
    eth_ports_set = set(
        iface["name"] for iface in mg_facts["minigraph_interfaces"]
        if iface["name"].startswith("Ethernet")
    )
    
    bind_ports = []
    for pc_name, pc_data in mg_facts.get("minigraph_portchannels", {}).items():
        members = pc_data.get("members", [])
        bind_ports.append(pc_name)
        eth_ports_set -= set(members)
    
    bind_ports.extend(sorted(eth_ports_set))
    data['bind_ports'] = bind_ports
    
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
        }
    }
    
    # VXLAN/VNET configuration values
    data['vxlan_tunnel_name'] = "tunnel_v4"
    
    # MAC addresses for packet crafting
    data['outer_src_mac'] = ptfadapter.dataplane.get_mac(0, send_ptf_port)
    data['outer_dst_mac'] = rand_selected_dut.facts['router_mac']
    
    logger.info("setUp fixture completed. Configuration data:")
    logger.info("  Loopback IP: %s", data['loopback_src_ip'])
    logger.info("  Test ports: %s (PTF %s) -> PortChannel101 (PTF %s)", 
                send_port_name, send_ptf_port, expected_ptf_ports)
    logger.info("  Bind ports: %s", data['bind_ports'])
    logger.info("  Test scenarios: %s", list(data['test_scenarios'].keys()))
    
    return data


def check_rule_counters(duthost):
    """
    Check if Acl rule counters initialized

    Args:
        duthost: DUT host object
    Returns:
        Bool value
    """
    res = duthost.shell("aclshow -a")['stdout_lines']
    if len(res) <= 2 or [line for line in res if 'N/A' in line]:
        return False
    else:
        return True


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL):
    """
    Get ACL counter packets value.

    Args:
        duthost: DUT host object
        table_name: ACL Table name
        rule_name: ACL rule name
        timeout: Timeout for ACL counters to update

    Returns:
        ACL counter value for packets as int, or 0 if not available
    """
    # Wait for orchagent to update the ACL counters
    time.sleep(timeout)
    result = duthost.show_and_parse('aclshow -a')

    if not result:
        pytest.fail("Failed to retrieve ACL counter for {}|{}".format(table_name, rule_name))

    for rule in result:
        if table_name == rule.get('table name') and rule_name == rule.get('rule name'):
            pkt_count = rule.get('packets count', '0')
            try:
                return int(pkt_count)
            except ValueError:
                logger.warning(f"ACL counter for {table_name}|{rule_name} is not integer: '{pkt_count}', returning 0")
                return 0

    pytest.fail("ACL rule {} not found in table {}".format(rule_name, table_name))


def setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE):
    """
    Add a custom ACL table type definition to CONFIG_DB.
    """
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

    logger.info("Waiting for ACL table type to apply...")
    time.sleep(10)


def setup_acl_table(duthost, ports):
    """
    Create an ACL table with the given ports and validate its creation
    using 'show acl table'. Fails if the table is not created or remains
    in 'Pending creation' state.
    """
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
    time.sleep(10)


def remove_acl_table(duthost):
    """
    Remove the ACL table and verify it is deleted from STATE_DB.
    """
    logger.info(f"Removing ACL table {ACL_TABLE_NAME}")
    cmd = f"config acl remove table {ACL_TABLE_NAME}"
    result = duthost.shell(cmd, module_ignore_errors=True)

    if result["rc"] != 0:
        logger.warning(f"Failed to remove ACL table via config command. Output:\n{result.get('stdout', '')}")
        pytest.fail(f"Failed to remove ACL table {ACL_TABLE_NAME}")

    time.sleep(10)

    logger.info(f"Verifying ACL table {ACL_TABLE_NAME} was removed from STATE_DB")
    db_cmd = f"redis-cli -n 6 KEYS 'ACL_TABLE_TABLE:{ACL_TABLE_NAME}'"
    keys_output = duthost.shell(db_cmd)["stdout_lines"]

    if any(keys_output):
        logger.error(f"ACL table {ACL_TABLE_NAME} still present in STATE_DB: {keys_output}")
        pytest.fail(f"ACL table {ACL_TABLE_NAME} was not removed from STATE_DB")
    else:
        logger.info(f"ACL table {ACL_TABLE_NAME} successfully removed from STATE_DB")


def setup_acl_rules(duthost, inner_src_ip, vni, new_src_mac):
    acl_rule = {
        "ACL_RULE": {
            f"{ACL_TABLE_NAME}|rule_1": {
                "priority": "1005",
                "TUNNEL_VNI": vni,
                "INNER_SRC_IP": inner_src_ip,
                "INNER_SRC_MAC_REWRITE_ACTION": new_src_mac
            }
        }
    }
    # Convert to JSON string
    acl_rule_json = json.dumps(acl_rule, indent=4)
    dest_path = os.path.join(TMP_DIR, ACL_RULES_FILE)

    logger.info("Writing ACL rule to %s:\n%s", dest_path, acl_rule_json)
    duthost.copy(content=acl_rule_json, dest=dest_path)

    logger.info("Loading ACL rule from %s", dest_path)
    duthost.shell(f"config load -y {dest_path}")

    logger.info("Waiting for ACL rule to be applied...")
    time.sleep(10)

    logger.info("Verifying ACL table type in CONFIG_DB")
    config_db_key = f"ACL_TABLE_TYPE|{ACL_TABLE_TYPE}"
    db_cmd = f"redis-cli -n 4 HGETALL \"{config_db_key}\""
    config_db_output = duthost.shell(db_cmd)["stdout"]
    logger.info("CONFIG_DB entry:\n%s", config_db_output)

    for field in ["BIND_POINTS", "MATCHES", "ACTIONS"]:
        pytest_assert(field in config_db_output, f"{field} missing in CONFIG_DB for ACL type {ACL_TABLE_TYPE}")

    # === Show ACL Table Verification ===
    logger.info("Verifying ACL table state using 'show acl table'")
    result = duthost.shell("show acl table", module_ignore_errors=True)
    output = result.get("stdout", "")
    logger.info("Output of 'show acl table':\n%s", output)

    if ACL_TABLE_NAME not in output:
        pytest.fail(f"ACL table {ACL_TABLE_NAME} not found in 'show acl table' output")

    for line in output.splitlines():
        if ACL_TABLE_NAME in line:
            if "pending" in line.lower():
                pytest.fail(f"ACL table {ACL_TABLE_NAME} is in 'Pending creation' state")
            elif "created" in line.lower() or "egress" in line.lower():
                logger.info(f"ACL table {ACL_TABLE_NAME} is successfully created and active")
                return

    pytest.fail(f"Unable to determine valid state for ACL table {ACL_TABLE_NAME}")

    logger.info("Verifying ACL rule installation with 'show acl rule'")
    output = duthost.shell("show acl rule")["stdout"]
    logger.info("ACL rule dump:\n%s", output)

    # === STATE_DB verification ===
    logger.info("Verifying ACL rule presence in STATE_DB...")
    state_db_key = f"ACL_RULE_TABLE:{ACL_TABLE_NAME}|rule_1"
    db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    state_db_output = duthost.shell(db_cmd)["stdout"]

    logger.info("STATE_DB entry for ACL rule:\n%s", state_db_output)
    pytest_assert("TUNNEL_VNI" in state_db_output and vni in state_db_output, "TUNNEL_VNI not found in STATE_DB")
    pytest_assert("INNER_SRC_IP" in state_db_output and inner_src_ip in state_db_output,
                  "INNER_SRC_IP not found in STATE_DB")
    pytest_assert("INNER_SRC_MAC_REWRITE_ACTION" in state_db_output and new_src_mac in state_db_output,
                  "MAC rewrite action missing in STATE_DB")

    # === COUNTERS check ===
    if duthost.facts['asic_type'] != 'vs':
        logger.info("Waiting for ACL rule counters to become ready...")
        pytest_assert(wait_until(60, 2, 0, check_rule_counters, duthost), "ACL rule counters are not ready")


def remove_acl_rules(duthost):
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))
    time.sleep(10)

    # === STATE_DB Deletion Check ===
    logger.info("Checking STATE_DB to confirm ACL rule deletion...")
    state_db_key = f"ACL_RULE_TABLE:{ACL_TABLE_NAME}|rule_1"
    db_cmd = f"redis-cli -n 6 EXISTS \"{state_db_key}\""
    exists_output = duthost.shell(db_cmd)["stdout"]

    logger.info(f"STATE_DB EXISTS check for {state_db_key}: {exists_output}")
    pytest_assert(exists_output.strip() == "0", f"ACL rule {state_db_key} still exists in STATE_DB")


def apply_config_in_dut(duthost, config, name="vxlan"):
    """
        The given json(config) will be copied to the DUT and loaded up.
    """
    filename = "/tmp/" + name + ".json"

    duthost.copy(content=config, dest=filename)
    duthost.shell("sudo config load {} -y".format(filename))
    time.sleep(1)

    duthost.shell("rm {}".format(filename))


def create_vxlan_vnet_config(duthost, tunnel_name, src_ip):
    """
    Configure complete VXLAN, VNET, route, and neighbor configuration.
    
    This function sets up a comprehensive VXLAN overlay configuration including:
    - VXLAN tunnel with DUT VTEP
    - VNET with VNI 10000
    - VNET route for test traffic (150.0.3.1/32)
    - Neighbor entry for next hop resolution
    
    Args:
        duthost: DUT host object
        tunnel_name: Name of the VXLAN tunnel
        src_ip: Source IP (Loopback0 IP for DUT VTEP)
    """
    # --- VXLAN parameters ---
    vnet_base = 10000
    ptf_vtep = "100.0.1.10"
    dut_vtep = "10.1.0.32"

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True
    ecmp_utils.Constants['DEBUG'] = False

    # --- Build overlay config JSON ---
    dut_json = {
        "NEIGH": {
            "PortChannel101|201.0.0.101": {
                "neigh": "00:aa:bb:cc:dd:ee",
                "family": "IPv4"
            }
        },
        "VXLAN_TUNNEL": {
            tunnel_name: {"src_ip": dut_vtep}
        },
        "VNET": {
            "Vnet1": {
                "vni": str(vnet_base),
                "vxlan_tunnel": tunnel_name,
                "scope": "default",
                "peer_list": "",
                "advertise_prefix": "false",
                "overlay_dmac": "25:35:45:55:65:75"
            }
        },
        "VNET_ROUTE_TUNNEL": {
            "Vnet1|150.0.3.1/32": {"endpoint": ptf_vtep}
        }
    }

    # Copy overlay config to DUT
    config_content = json.dumps(dut_json, indent=4)
    logger.info("Applying comprehensive VXLAN/VNET config:\n%s", config_content)
    
    duthost.copy(content=config_content, dest="/tmp/config_db_vxlan_vnet.json")
    duthost.shell("cp /tmp/config_db_vxlan_vnet.json /home/admin/config_db_vxlan_vnet.json")
    duthost.shell("sonic-cfggen -j /tmp/config_db_vxlan_vnet.json --write-to-db")
    duthost.shell("config save -y")
    
    # Clean up temp file
    duthost.shell("rm /tmp/config_db_vxlan_vnet.json")

    duthost.shell("cp /etc/sonic/config_db.json /home/admin/config_db_vxlan_route_persistent.json")
 
    config_reload(duthost, safe_reload=True, yang_validate=False)
 
    time.sleep(20)  # wait for DUT to come up after reload
 
    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=duthost.facts["router_mac"])
 
    logger.info("=== VXLAN VNET configuration applied and persisted successfully ===")


@pytest.mark.parametrize("scenario_name", ["single_ip_test", "range_test"])
def test_modify_inner_src_mac_egress(setUp, scenario_name):
    """
    Test ACL rule for inner source MAC rewriting with VXLAN/VNET configuration.
    Tests both single IP (/32) and range (/24) ACL rule matching scenarios.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios'][scenario_name]
    
    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    loopback_src_ip = setUp['loopback_src_ip']
    
    # Extract scenario-specific MAC addresses
    original_inner_src_mac = scenario['original_mac']
    first_modified_mac = scenario['first_modified_mac']
    second_modified_mac = scenario['second_modified_mac']
    
    # Configuration values
    vnet_1 = "Vnet1"
    vxlan_tunnel_name = setUp['vxlan_tunnel_name']
    outer_src_mac = setUp['outer_src_mac']
    outer_dst_mac = setUp['outer_dst_mac']
    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME
    
    # Standard values from VXLAN/VNET configuration
    next_hop_ip = "100.0.1.10"  # PTF VTEP endpoint
    inner_dst_ip = "150.0.3.1"  # Route destination
    vni_id = "10000"  # VNI from configuration
    inner_src_ip = "201.0.0.101"  # Source IP that matches neighbor entry

    logger.info(f"Running test scenario: {scenario_name}")
    logger.info(f"  Using inner src IP: {inner_src_ip}")
    logger.info(f"  Using inner dst IP: {inner_dst_ip}")
    logger.info(f"  Using VNI: {vni_id}")

    # ===================================================================
    # STEP 1: Program VXLAN_TUNNEL, VNET, and ROUTE config in one step
    # ===================================================================
    logger.info("STEP 1: Configuring comprehensive VXLAN/VNET/ROUTE configuration")
    
    # Apply comprehensive configuration
    create_vxlan_vnet_config(
        duthost=duthost,
        tunnel_name=vxlan_tunnel_name,
        src_ip=loopback_src_ip
    )
    
    # Wait for configuration to be applied
    logger.info("Waiting for VXLAN/VNET/ROUTE configuration to be applied...")
    time.sleep(15)

    # === Verify configuration was applied ===
    logger.info("Verifying VNET route with 'show vnet route all'")
    output = duthost.shell("show vnet route all")["stdout"]
    assert "150.0.3.1/32" in output and vnet_1 in output, "VNET route not found in 'show vnet route all'"
    
    # Verify neighbor entry was added
    logger.info("Verifying neighbor entry with 'show arp'")
    arp_output = duthost.shell("show arp")["stdout"]
    logger.info(f"ARP table:\n{arp_output}")
    
    # Additional verification - check VXLAN tunnel status
    logger.info("Verifying VXLAN tunnel status")
    tunnel_output = duthost.shell("show vxlan tunnel")["stdout"]
    assert vxlan_tunnel_name in tunnel_output, f"VXLAN tunnel {vxlan_tunnel_name} not found"
    
    # Wait additional time to ensure all VNET-VXLAN configuration is stable
    logger.info("Waiting for VNET-VXLAN configuration to stabilize...")
    time.sleep(5)
    
    # ===================================================================
    # STEP 2: Setup ACL table and rules AFTER VNET-VXLAN is ready
    # ===================================================================
    logger.info("STEP 2: Setting up ACL table and rules")
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
    
    setup_acl_rules(duthost, acl_rule_prefix, vni_id, first_modified_mac)

    # Test with the configured source IP 
    logger.info("Step 1: Verifying rewrite with first modified MAC: %s", first_modified_mac)
    _send_and_verify_mac_rewrite(
        ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
        first_modified_mac, vni_id, outer_src_mac, outer_dst_mac, loopback_src_ip, next_hop_ip, table_name, RULE_NAME
    )
    
    # For range test, also test with different IPs in the range
    if scenario_name == "range_test":
        test_ips = ["201.0.0.102", "201.0.0.103", "201.0.0.104"]  # Additional IPs in the 201.0.0.0/24 range
        for test_ip in test_ips:
            logger.info(f"Range test: Verifying rewrite with IP {test_ip}")
            _send_and_verify_mac_rewrite(
                ptfadapter, ptf_port_1, ptf_port_2, duthost, test_ip, inner_dst_ip, original_inner_src_mac,
                first_modified_mac, vni_id, outer_src_mac, outer_dst_mac, loopback_src_ip, next_hop_ip,
                table_name, RULE_NAME
            )

    # Modify rule after sending the first packet
    logger.info("Step 2: Replacing ACL rule to use new MAC: %s", second_modified_mac)
    remove_acl_rules(duthost)
    setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
    setup_acl_table(duthost, bind_ports)
    setup_acl_rules(duthost, acl_rule_prefix, vni_id, second_modified_mac)

    logger.info("Step 3: Verifying rewrite with second modified MAC: %s", second_modified_mac)
    _send_and_verify_mac_rewrite(
        ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
        second_modified_mac, vni_id, outer_src_mac, outer_dst_mac, loopback_src_ip, next_hop_ip, table_name, RULE_NAME
    )

    # Cleanup - remove table completely since remove_acl_rules() removes the table
    remove_acl_rules(duthost)


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, ptf_port_2_list, duthost,
                                 src_ip, dst_ip, orig_src_mac, expected_inner_mac,
                                 vni_id, outer_src_mac, outer_dst_mac, outer_src_ip, outer_dst_ip,
                                 table_name, rule_name):
    """
    Send a packet and verify MAC rewrite with VXLAN encapsulation.
    Updated to follow the pattern from test_bgp_vnet_route_forwarding.
    
    Args:
        ptf_port_2_list: List of PTF ports where packet might be received (like [24,25,26,27])
    """
    router_mac = duthost.facts["router_mac"]
    
    # Create input packet
    options = {'ip_ecn': 0}
    pkt_opts = {
        "pktlen": 100,
        "eth_dst": router_mac,
        "eth_src": orig_src_mac,
        "ip_dst": dst_ip,
        "ip_src": src_ip,
        "ip_id": 105,
        "ip_ttl": 64,
        "tcp_sport": 1234,
        "tcp_dport": 5000
    }

    pkt_opts.update(options)
    input_pkt = testutils.simple_tcp_packet(**pkt_opts)

    # Create expected inner packet with rewritten MAC
    inner_pkt_opts = {
        "pktlen": 100,
        "eth_dst": "00:12:34:56:78:9a",  # Switch MAC
        "eth_src": expected_inner_mac,  # This should be the rewritten MAC
        "ip_dst": dst_ip,
        "ip_src": src_ip,
        "ip_id": 105,
        "ip_ttl": 63,  # TTL decremented
        "tcp_sport": 1234,
        "tcp_dport": 5000
    }
    inner_pkt_opts.update(options)
    expected_inner_pkt = testutils.simple_tcp_packet(**inner_pkt_opts)

    # Create expected VXLAN encapsulated packet
    encap_pkt = testutils.simple_vxlan_packet(
        eth_src=router_mac,
        eth_dst="00:aa:bb:cc:dd:ee",  # Random MAC
        ip_id=0,
        ip_ihl=5,
        ip_src="10.1.0.32",  # DUT VTEP
        ip_dst="100.0.1.10",  # PTF VTEP from config
        ip_ttl=128,
        udp_sport=49366,
        udp_dport=4789,  # Standard VXLAN port
        with_udp_chksum=False,
        vxlan_vni=10000,  # VNI from config
        inner_frame=expected_inner_pkt,
        **options
    )
    
    # Set IP flags
    encap_pkt[IP].flags = 0x2
    
    # Create masked expected packet with detailed masking
    masked_exp_pkt = mask.Mask(encap_pkt)
    masked_exp_pkt.set_ignore_extra_bytes()

    # Outer headers masking - mask everything we don't care about
    masked_exp_pkt.set_do_not_care_scapy(Ether, "src")
    masked_exp_pkt.set_do_not_care_scapy(Ether, "dst")
    masked_exp_pkt.set_do_not_care_scapy(IP, "ttl")
    masked_exp_pkt.set_do_not_care_scapy(IP, "chksum")
    masked_exp_pkt.set_do_not_care_scapy(IP, "id")
    masked_exp_pkt.set_do_not_care_scapy(IP, "src")
    masked_exp_pkt.set_do_not_care_scapy(IP, "dst")
    masked_exp_pkt.set_do_not_care_scapy(UDP, "sport")
    masked_exp_pkt.set_do_not_care_scapy(UDP, "chksum")
    
    # The key verification: we only care about the inner source MAC being rewritten
    # Everything else in the inner frame is masked except the inner src MAC
    logger.info(f"Expected inner source MAC after rewrite: {expected_inner_mac}")

    # Get ACL counter before sending
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    
    # Send packet
    logger.info(f"Sending TCP packet on port {ptf_port_1}")
    testutils.send(ptfadapter, ptf_port_1, input_pkt)
    
    # Wait for processing
    time.sleep(20)
    
    try:
        # Verify packet on any of the expected output ports
        logger.info(f"Expecting VXLAN packet on any of ports {ptf_port_2_list}")
        testutils.verify_packet_any_port(ptfadapter, masked_exp_pkt, ptf_port_2_list)
        logger.info("Packet successfully received and verified")
    except Exception as e:
        logger.error("Did not receive expected packet on expected ports: %s", repr(e))
        raise
    
    # Check ACL counter incremented
    count_after = get_acl_counter(duthost, table_name, rule_name)
    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)
    pytest_assert(count_after >= count_before + 1,
                  f"ACL counter did not increment for {src_ip}. before={count_before}, after={count_after}")
