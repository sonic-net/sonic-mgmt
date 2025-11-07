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
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')  # Only run on Cisco-8000 ASICs that support INNER_SRC_MAC_REWRITE_ACTION
]

# Test configuration constants
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'

# VXLAN/VNET configuration constants
PTF_VTEP_IP = "100.0.1.10"  # PTF VTEP endpoint IP
DUT_VTEP_IP = "10.1.0.32"   # DUT VTEP IP

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

    # Get CONFIG_DB facts for more robust port selection
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
    
    # Extract available PTF ports from PortChannel members
    # CONFIG_DB structure: {'PortChannel101': {'Ethernet192': {}}, 'PortChannel102': {'Ethernet200': {}}, ...}
    egress_ptf_if = []
    for pc_name, members_dict in pc_members.items():
        for member in members_dict.keys():
            if member in port_indexes:
                ptf_index = port_indexes[member]
                if ptf_index in ptf_ports_available_in_topo:
                    egress_ptf_if.append(ptf_index)

    if not egress_ptf_if:
        pytest.fail("No PortChannel member PTF ports found")

    # Use first available port as send port, all ports as receive ports
    send_ptf_port = egress_ptf_if[0]
    expected_ptf_ports = egress_ptf_if  # Use all ports starting from index 0
    
    # Find the interface name and PortChannel for the send port
    send_port_name = None
    selected_pc = None
    for pc_name, members_dict in pc_members.items():
        for member in members_dict.keys():
            if member in port_indexes and port_indexes[member] == send_ptf_port:
                send_port_name = member
                selected_pc = pc_name
                break
        if send_port_name:
            break
    
    if not send_port_name or not selected_pc:
        pytest.fail("Could not determine send port interface name or PortChannel")

    data['ptf_port_1'] = send_ptf_port        # Send port
    data['ptf_port_2'] = expected_ptf_ports  # List of expected receive ports
    data['test_port_1'] = send_port_name
    data['test_port_2'] = selected_pc  # Selected PortChannel for testing

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
    data['ptf_vtep_ip'] = PTF_VTEP_IP
    data['dut_vtep_ip'] = DUT_VTEP_IP

    # MAC addresses for packet crafting
    data['outer_src_mac'] = ptfadapter.dataplane.get_mac(0, send_ptf_port)
    data['outer_dst_mac'] = rand_selected_dut.facts['router_mac']

    logger.info("setUp fixture completed. Configuration data:")
    logger.info("  Loopback IP: %s", data['loopback_src_ip'])
    logger.info("  Selected PortChannel: %s with PTF ports: %s", selected_pc, egress_ptf_if)
    logger.info("  Test ports: %s (PTF %s) -> %s (PTF %s)",
                send_port_name, send_ptf_port, selected_pc, expected_ptf_ports)
    logger.info("  Bind ports: %s", data['bind_ports'])
    logger.info("  Test scenarios: %s", list(data['test_scenarios'].keys()))

    # Create configuration backup before making any changes
    backup_config(rand_selected_dut)

    # Configure VXLAN/VNET infrastructure once for all test scenarios
    logger.info("Setting up VXLAN/VNET configuration in setUp fixture...")
    create_vxlan_vnet_config(
        duthost=rand_selected_dut,
        tunnel_name=data['vxlan_tunnel_name'],
        src_ip=data['loopback_src_ip'],
        portchannel_name=selected_pc
    )

    # Wait for configuration to be applied
    logger.info("Waiting for VXLAN/VNET/ROUTE configuration to be applied...")
    time.sleep(15)

    # Verify configuration was applied
    logger.info("Verifying VNET route with 'show vnet route all'")
    output = rand_selected_dut.shell("show vnet route all")["stdout"]
    if "150.0.3.1/32" not in output or "Vnet1" not in output:
        pytest.fail("VNET route not found in 'show vnet route all'")

    logger.info("VXLAN/VNET configuration completed successfully")
    
    return data


@pytest.fixture(name="tearDown", scope="module", autouse=True)
def fixture_tearDown(setUp):
    """
    Module-scoped teardown fixture that runs after all tests in the module complete.
    Handles cleanup of VXLAN/VNET configuration.
    """
    yield  # This allows tests to run first
    
    logger.info("=== Module tearDown: Starting VXLAN/VNET cleanup ===")
    try:
        duthost = setUp['duthost']
        vxlan_tunnel_name = setUp['vxlan_tunnel_name']
        cleanup_test_configuration(duthost, vxlan_tunnel_name)
        logger.info("Module tearDown completed successfully")
    except Exception as e:
        logger.error(f"Module tearDown failed: {e}")
        # Don't raise the exception since tests may have passed


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


def create_vxlan_vnet_config(duthost, tunnel_name, src_ip, portchannel_name="PortChannel101"):
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
        portchannel_name: PortChannel interface for neighbor configuration
    """
    # --- VXLAN parameters ---
    vnet_base = 10000
    ptf_vtep = PTF_VTEP_IP
    dut_vtep = DUT_VTEP_IP

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True
    ecmp_utils.Constants['DEBUG'] = False

    # --- Build overlay config JSON ---
    dut_json = {
        "NEIGH": {
            f"{portchannel_name}|201.0.0.101": {
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

    # Clean up temp file
    duthost.shell("rm /tmp/config_db_vxlan_vnet.json")

    time.sleep(20)  # wait for DUT to come up after reload

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=duthost.facts["router_mac"])

    logger.info("=== VXLAN VNET configuration applied and persisted successfully ===")


CONFIG_DB_PATH = "/etc/sonic/config_db.json"


def backup_config(duthost):
    """
    Create a backup of the current configuration before making test changes.
    This allows for clean restoration regardless of test outcome.
    """
    logger.info("Creating configuration backup...")
    try:
        duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")
        logger.info("Configuration backup created successfully")
    except Exception as e:
        logger.error(f"Failed to create configuration backup: {e}")
        raise


def cleanup_test_configuration(duthost, vxlan_tunnel_name=None):
    """
    Return DUT to original state using backup and restore approach.
    This is much more reliable than trying to manually undo individual changes.
    
    Args:
        duthost: DUT host object
        vxlan_tunnel_name: Not used in backup/restore approach but kept for compatibility
    """
    logger.info("=== Starting configuration cleanup using backup restore ===")
    
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
                "/tmp/acl_update.json", 
                "/tmp/vnet_route_update.json", 
                "/tmp/bgp_and_interface_update.json",
                "/tmp/vnet_vxlan_update.json", 
                "/tmp/swss_config_update.json",
                "/tmp/config_db_vxlan_vnet.json",
                f"/tmp/{ACL_RULES_FILE}",
                f"/tmp/{ACL_REMOVE_RULES_FILE}"
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
        ip_src=DUT_VTEP_IP,  # DUT VTEP
        ip_dst=outer_dst_ip,  # PTF VTEP from config
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


def _test_inner_src_mac_rewrite(setUp, scenario_name):
    """
    Internal test function for ACL rule inner source MAC rewriting with VXLAN/VNET configuration.
    Tests both single IP (/32) and range (/24) ACL rule matching scenarios.
    
    Uses try-finally to ensure cleanup happens regardless of test outcome.
    
    Args:
        setUp: Test fixture data
        scenario_name: Either "single_ip_test" or "range_test"
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios'][scenario_name]

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
    bind_ports = setUp['bind_ports']
    loopback_src_ip = setUp['loopback_src_ip']
    selected_portchannel = setUp['test_port_2']  # Dynamically selected PortChannel

    # Extract scenario-specific MAC addresses
    original_inner_src_mac = scenario['original_mac']
    first_modified_mac = scenario['first_modified_mac']
    second_modified_mac = scenario['second_modified_mac']

    # Configuration values
    vnet_1 = "Vnet1"
    vxlan_tunnel_name = setUp['vxlan_tunnel_name']
    outer_src_mac = setUp['outer_src_mac']
    outer_dst_mac = setUp['outer_dst_mac']
    ptf_vtep_ip = setUp['ptf_vtep_ip']
    dut_vtep_ip = setUp['dut_vtep_ip']
    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME

    # Standard values from VXLAN/VNET configuration
    next_hop_ip = ptf_vtep_ip  # PTF VTEP endpoint
    inner_dst_ip = "150.0.3.1"  # Route destination
    vni_id = "10000"  # VNI from configuration
    inner_src_ip = "201.0.0.101"  # Source IP that matches neighbor entry

    logger.info(f"Running test scenario: {scenario_name}")
    logger.info(f"  Using inner src IP: {inner_src_ip}")
    logger.info(f"  Using inner dst IP: {inner_dst_ip}")
    logger.info(f"  Using VNI: {vni_id}")

    try:
        # ===================================================================
        # STEP 1: Setup ACL table and rules (VXLAN/VNET already configured in setUp)
        # ===================================================================
        logger.info("STEP 1: Setting up ACL table and rules")
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
        
        logger.info("=== All test steps completed successfully ===")

    finally:
        # Clean up ACL configuration (VXLAN/VNET cleanup handled at module level)
        logger.info("=== Cleaning up ACL configuration ===")
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