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
from datetime import datetime
from scapy.all import Ether, IP, UDP
from tests.common.helpers.assertions import pytest_assert
from ptf import testutils
from ptf.testutils import dp_poll, send_packet
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
CONFIG_DB_PATH = "/etc/sonic/config_db.json"

# VXLAN/VNET configuration constants
PTF_VTEP_IP = "100.0.1.10"  # PTF VTEP endpoint IP
DUT_VTEP_IP = "10.1.0.32"   # DUT VTEP IP
VXLAN_UDP_PORT = 4789       # Standard VXLAN UDP port
VXLAN_VNI = 10000           # Primary VXLAN Network Identifier
VXLAN_VNI_2 = 20000         # Secondary VNI for multi-VNI testing
VXLAN_VNI_3 = 30000         # Tertiary VNI for multi-VNI testing
RANDOM_MAC = "00:aa:bb:cc:dd:ee"  # Random MAC for outer Ethernet dst

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"


def generate_mac_address(index):
    base_mac = "00:aa:bb:cc:dd"
    last_octet = f"{(index % 256):02x}"
    return f"{base_mac}:{last_octet}"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(rand_selected_dut, tbinfo, ptfadapter):
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
    expected_ptf_ports = egress_ptf_if

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

    data['ptf_port_1'] = send_ptf_port
    data['ptf_port_2'] = expected_ptf_ports
    data['test_port_1'] = send_port_name
    data['test_port_2'] = selected_pc

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
        },
        'multi_vni_test': {
            'original_mac': generate_mac_address(7),
            'first_modified_mac': generate_mac_address(8),
            'second_modified_mac': generate_mac_address(9),
            'third_modified_mac': generate_mac_address(10)
        }
    }

    # VXLAN/VNET configuration values
    data['vxlan_tunnel_name'] = "tunnel_v4"
    data['ptf_vtep_ip'] = PTF_VTEP_IP
    data['dut_vtep_ip'] = DUT_VTEP_IP

    # MAC addresses for packet crafting
    data['outer_src_mac'] = ptfadapter.dataplane.get_mac(0, send_ptf_port)
    data['outer_dst_mac'] = rand_selected_dut.facts['router_mac']

    # Create configuration backup before making any changes
    backup_config(rand_selected_dut)

    # Configure VXLAN/VNET infrastructure once for all test scenarios
    create_vxlan_vnet_config(
        duthost=rand_selected_dut,
        tunnel_name=data['vxlan_tunnel_name'],
        src_ip=data['loopback_src_ip'],
        portchannel_name=selected_pc,
        router_mac=rand_selected_dut.facts['router_mac']
    )

    # Wait for configuration to be applied
    time.sleep(15)

    # Debug: Check what VNETs actually exist
    logger.info("Checking VNET configuration after setup...")
    vnet_list = rand_selected_dut.shell("show vnet", module_ignore_errors=True)["stdout"]
    logger.info("VNET list output:\n%s", vnet_list)

    # Debug: Check CONFIG_DB for VNET configuration
    vnet_config = rand_selected_dut.shell("redis-cli -n 4 KEYS 'VNET*'", module_ignore_errors=True)["stdout"]
    logger.info("CONFIG_DB VNET keys:\n%s", vnet_config)

    # Debug: Check STATE_DB for VNET routes
    vnet_routes = rand_selected_dut.shell("redis-cli -n 6 KEYS 'VNET_ROUTE*'", module_ignore_errors=True)["stdout"]
    logger.info("STATE_DB VNET route keys:\n%s", vnet_routes)

    # Verify configuration was applied
    output = rand_selected_dut.shell("show vnet route all")["stdout"]
    logger.info("VNET routes output:\n%s", output)

    if "150.0.3.1/32" not in output:
        pytest.fail("Primary VNET route (150.0.3.1/32) not found in 'show vnet route all'")

    return data


@pytest.fixture(name="tearDown", scope="module", autouse=True)
def fixture_tearDown(setUp):
    yield  # This allows tests to run first

    try:
        duthost = setUp['duthost']
        vxlan_tunnel_name = setUp['vxlan_tunnel_name']
        cleanup_test_configuration(duthost, vxlan_tunnel_name)
        logger.info("Module tearDown completed successfully")
    except Exception as e:
        logger.error(f"Module tearDown failed: {e}")
        # Don't raise the exception since tests may have passed


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL):
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

    time.sleep(10)


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
    time.sleep(10)

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
                break
    else:
        pytest.fail(f"Unable to determine valid state for ACL table {ACL_TABLE_NAME}")

    logger.info(f"ACL table {ACL_TABLE_NAME} validation completed successfully")


def remove_acl_table(duthost):
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
    """
    Set up initial ACL rules. Uses 'config load -y' for initial setup
    since it may need to create table types and tables first.
    """

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
    load_result = duthost.shell(f"config load -y {dest_path}", module_ignore_errors=True)
    logger.info("Config load result: rc=%s, stdout=%s", load_result.get("rc", "unknown"), load_result.get("stdout", ""))

    if load_result.get("rc", 0) != 0:
        logger.error("Config load failed: %s", load_result.get("stderr", ""))
        pytest.fail("Failed to load ACL rule configuration")

    logger.info("Waiting for ACL rule to be applied...")
    time.sleep(15)  # Increased wait time

    # Check CONFIG_DB for the rule
    logger.info("Checking if rule was added to CONFIG_DB...")
    rule_config_cmd = f'redis-cli -n 4 HGETALL "ACL_RULE|{ACL_TABLE_NAME}|rule_1"'
    rule_config_result = duthost.shell(rule_config_cmd)["stdout"]
    logger.info("ACL rule in CONFIG_DB:\n%s", rule_config_result)

    # === Show ACL Rule Verification ===
    logger.info("Verifying ACL rule state using 'show acl rule'")
    rule_result = duthost.shell("show acl rule", module_ignore_errors=True)
    rule_output = rule_result.get("stdout", "")
    logger.info("Output of 'show acl rule':\n%s", rule_output)

    # Check that the rule shows up and is Active
    if ACL_TABLE_NAME not in rule_output or "rule_1" not in rule_output:
        pytest.fail(f"ACL rule for table {ACL_TABLE_NAME} and rule rule_1 not found in 'show acl rule' output")

    if "Active" not in rule_output:
        pytest.fail(f"ACL rule for table {ACL_TABLE_NAME} is not showing as Active in 'show acl rule' output")

    logger.info(f"ACL rule for table {ACL_TABLE_NAME} is successfully created and shows as Active")

    # === STATE_DB Verification ===
    logger.info("Verifying ACL rule propagation to STATE_DB...")
    state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1"
    state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    state_db_output = duthost.shell(state_db_cmd)["stdout"]

    logger.info("STATE_DB entry for ACL rule:\n%s", state_db_output)

    # Check if the rule is active in STATE_DB (this indicates successful propagation)
    if "status" in state_db_output and "Active" in state_db_output:
        logger.info("ACL rule is active in STATE_DB, indicating successful propagation")
        # Also verify the CONFIG_DB has the correct MAC to confirm the setup
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|rule_1"
        config_verification = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" INNER_SRC_MAC_REWRITE_ACTION')["stdout"]
        pytest_assert(config_verification.strip() == new_src_mac,
                      f"CONFIG_DB does not have expected MAC {new_src_mac}, got: {config_verification.strip()}")
        logger.info(f"STATE_DB validation successful - rule is active with MAC {new_src_mac}")

    logger.info("ACL rule STATE_DB verification completed")


def modify_acl_rule(duthost, inner_src_ip, vni, new_src_mac):
    logger.info("Modifying ACL rule with new MAC: %s", new_src_mac)

    # First check what's currently in CONFIG_DB
    logger.info("Checking current CONFIG_DB ACL rules...")
    current_rules = duthost.shell('redis-cli -n 4 KEYS "ACL_RULE*"')["stdout"]
    logger.info("Current ACL_RULE keys in CONFIG_DB:\n%s", current_rules)

    # Directly update the ACL rule in CONFIG_DB using Redis
    rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|rule_1"

    logger.info("Updating CONFIG_DB ACL rule with key: %s", rule_key)

    # First check if the rule exists
    exists = duthost.shell(f'redis-cli -n 4 EXISTS "{rule_key}"')["stdout"]
    logger.info("Rule exists in CONFIG_DB: %s", exists)

    if exists.strip() == "0":
        logger.warning("Rule doesn't exist in CONFIG_DB, checking different key format...")
        # Try alternative key format
        alt_rule_key = f"ACL_RULE:{ACL_TABLE_NAME}|rule_1"
        exists_alt = duthost.shell(f'redis-cli -n 4 EXISTS "{alt_rule_key}"')["stdout"]
        logger.info("Alternative rule key exists: %s", exists_alt)
        if exists_alt.strip() == "1":
            rule_key = alt_rule_key

    # Show current rule content
    current_rule = duthost.shell(f'redis-cli -n 4 HGETALL "{rule_key}"')["stdout"]
    logger.info("Current rule content before modification:\n%s", current_rule)

    # Update the MAC rewrite action field directly
    cmd = f'redis-cli -n 4 HSET "{rule_key}" INNER_SRC_MAC_REWRITE_ACTION "{new_src_mac}"'
    result = duthost.shell(cmd)
    logger.info("HSET result: %s", result["stdout"])

    # Also update other fields to ensure consistency
    duthost.shell(f'redis-cli -n 4 HSET "{rule_key}" priority "1005"')
    duthost.shell(f'redis-cli -n 4 HSET "{rule_key}" TUNNEL_VNI "{vni}"')
    duthost.shell(f'redis-cli -n 4 HSET "{rule_key}" INNER_SRC_IP "{inner_src_ip}"')

    # Verify the update in CONFIG_DB
    updated_rule = duthost.shell(f'redis-cli -n 4 HGETALL "{rule_key}"')["stdout"]
    logger.info("Updated rule content in CONFIG_DB:\n%s", updated_rule)

    logger.info("Waiting for CONFIG_DB changes to propagate to STATE_DB...")
    time.sleep(15)

    # Verify the modification in STATE_DB
    logger.info("Verifying ACL rule modification in STATE_DB...")
    state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1"

    db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    state_db_output = duthost.shell(db_cmd)["stdout"]

    logger.info("STATE_DB entry for modified ACL rule:\n%s", state_db_output)

    # Check if the rule is active in STATE_DB (this indicates successful propagation)
    if "status" in state_db_output and "Active" in state_db_output:
        logger.info("ACL rule is active in STATE_DB, indicating successful propagation")
        # Also verify the CONFIG_DB has the correct MAC to confirm the update
        config_verification = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" INNER_SRC_MAC_REWRITE_ACTION')["stdout"]
        pytest_assert(config_verification.strip() == new_src_mac,
                      f"CONFIG_DB does not have expected MAC {new_src_mac}, got: {config_verification.strip()}")

    logger.info("ACL rule successfully modified to use MAC: %s", new_src_mac)


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


def create_vxlan_vnet_config(duthost, tunnel_name, src_ip, portchannel_name="PortChannel101", router_mac=None):
    # --- VXLAN parameters ---
    vnet_base = VXLAN_VNI
    ptf_vtep = PTF_VTEP_IP
    dut_vtep = DUT_VTEP_IP

    ecmp_utils.Constants['KEEP_TEMP_FILES'] = True
    ecmp_utils.Constants['DEBUG'] = False

    # First create the VXLAN tunnel manually (since we need specific src_ip)
    tunnel_config = {
        "VXLAN_TUNNEL": {
            tunnel_name: {"src_ip": dut_vtep}
        }
    }

    tunnel_content = json.dumps(tunnel_config, indent=4)
    logger.info("Creating VXLAN tunnel:\n%s", tunnel_content)

    duthost.copy(content=tunnel_content, dest="/tmp/vxlan_tunnel.json")
    duthost.shell("sonic-cfggen -j /tmp/vxlan_tunnel.json --write-to-db")
    duthost.shell("rm /tmp/vxlan_tunnel.json")

    time.sleep(5)  # Wait for tunnel creation

    # Use ecmp_utils.create_vnets() for primary VNET (handles complex setup)
    logger.info("Creating primary VNET using ecmp_utils.create_vnets()")
    vnet_vni_map = ecmp_utils.create_vnets(
        duthost,
        tunnel_name=tunnel_name,
        vnet_count=1,
        scope="default",
        vni_base=vnet_base,
        vnet_name_prefix="Vnet",
        advertise_prefix="false"
    )

    logger.info(f"Created primary VNET: {vnet_vni_map}")

    # Get the VNET name (should be "Vnet-0" based on ecmp_utils naming)
    vnet_name = list(vnet_vni_map.keys())[0]

    # Configure VNET route using ecmp_utils
    logger.info("Configuring primary VNET route using ecmp_utils")
    ecmp_utils.create_and_apply_config(
        duthost=duthost,
        vnet=vnet_name,
        dest="150.0.3.1",
        mask=32,
        nhs=[ptf_vtep],
        op="SET"
    )

    time.sleep(10)  # wait for configuration to be applied

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=VXLAN_UDP_PORT, dutmac=router_mac)

    time.sleep(5)  # Give time for config to apply


def apply_config_chunk(duthost, payload, config_name):
    """Apply configuration chunk similar to the scale test approach"""
    content = json.dumps(payload, indent=2)
    file_dest = f"/tmp/{config_name}_chunk.json"
    duthost.copy(content=content, dest=file_dest)
    duthost.shell(f"sonic-cfggen -j {file_dest} --write-to-db")
    duthost.shell(f"rm -f {file_dest}")


def create_additional_vnets(duthost, tunnel_name):
    """Create additional VNETs for multi-VNI testing using direct CONFIG_DB approach like PR #21220"""
    ptf_vtep = PTF_VTEP_IP

    logger.info("Creating additional VNETs using direct CONFIG_DB approach")

    # VNET configuration for VNI 20000 (Vnet2)
    vnet2_config = {
        "VNET": {
            "Vnet2-0": {
                "vni": str(VXLAN_VNI_2),
                "vxlan_tunnel": tunnel_name
            }
        }
    }
    
    logger.info(f"Creating Vnet2 with VNI {VXLAN_VNI_2}")
    apply_config_chunk(duthost, vnet2_config, "vnet_Vnet2")
    time.sleep(2)  # Small delay between VNET creation steps
    
    # VNET route for VNI 20000
    route2_config = {
        "VNET_ROUTE_TUNNEL": {
            "Vnet2-0|151.0.3.1/32": {
                "endpoint": ptf_vtep,
                "vni": str(VXLAN_VNI_2)
            }
        }
    }
    
    logger.info("Creating Vnet2 route for 151.0.3.1/32")
    apply_config_chunk(duthost, route2_config, "routes_Vnet2")
    time.sleep(2)

    # VNET configuration for VNI 30000 (Vnet3)
    vnet3_config = {
        "VNET": {
            "Vnet3-0": {
                "vni": str(VXLAN_VNI_3),
                "vxlan_tunnel": tunnel_name
            }
        }
    }
    
    logger.info(f"Creating Vnet3 with VNI {VXLAN_VNI_3}")
    apply_config_chunk(duthost, vnet3_config, "vnet_Vnet3")
    time.sleep(2)  # Small delay between VNET creation steps
    
    # VNET route for VNI 30000
    route3_config = {
        "VNET_ROUTE_TUNNEL": {
            "Vnet3-0|152.0.3.1/32": {
                "endpoint": ptf_vtep,
                "vni": str(VXLAN_VNI_3)
            }
        }
    }
    
    logger.info("Creating Vnet3 route for 152.0.3.1/32")
    apply_config_chunk(duthost, route3_config, "routes_Vnet3")
    time.sleep(2)

    # Final wait for all VNET configurations to be applied
    logger.info("Waiting for additional VNET configurations to be fully applied...")
    time.sleep(10)

    logger.info(f"Created additional VNETs: Vnet2-0 (VNI {VXLAN_VNI_2}), Vnet3-0 (VNI {VXLAN_VNI_3})")


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
                f"/tmp/{ACL_RULES_FILE}",  # acl_config.json
                f"/tmp/{ACL_REMOVE_RULES_FILE}",  # acl_rules_del.json
                "/tmp/dual_acl_rules.json",  # Created by test_multiple_acl_rules_same_priority
                "/tmp/acl_rule_no_priority.json",  # Created by test_acl_rule_no_priority
                "/tmp/inner_src_mac_rewrite_type_acl_type.json",  # Created by setup_acl_table_type
                "/tmp/vxlan_tunnel.json",  # Created by create_vxlan_vnet_config
                "/tmp/vnet_Vnet2_chunk.json",  # Created by create_additional_vnets
                "/tmp/routes_Vnet2_chunk.json",  # Created by create_additional_vnets
                "/tmp/vnet_Vnet3_chunk.json",  # Created by create_additional_vnets
                "/tmp/routes_Vnet3_chunk.json",  # Created by create_additional_vnets
                "/tmp/acl_rule_rule_vni_match_no_ip.json",  # Created by setup_multi_vni_acl_rule
                "/tmp/acl_rule_rule_ip_match_no_vni.json",  # Created by setup_multi_vni_acl_rule
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


def _send_and_verify_acl_counter_no_increment(ptfadapter, ptf_port_1, duthost,
                                              src_ip, dst_ip, orig_src_mac, table_name, rule_name):
    """
    Send a packet and verify that the ACL counter does NOT increment for partial matches.
    For partial match cases (VNI matches but IP doesn't, or IP matches but VNI doesn't),
    the ACL rule should not trigger and the counter should remain unchanged.
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

    logger.info("=== Partial Match Counter Test ===")
    logger.info(f"Test packet: src_ip={src_ip}, dst_ip={dst_ip}")
    logger.info(f"ACL table: {table_name}, rule: {rule_name}")
    logger.info("Expected: ACL counter should NOT increment (partial match)")

    # Get ACL counter before sending
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info(f"ACL counter before sending: {count_before}")

    # Send packet
    logger.info(f"Sending TCP packet on port {ptf_port_1}")
    send_packet(ptfadapter, ptf_port_1, input_pkt)

    # Wait for potential rule processing
    time.sleep(3)

    # Check ACL counter after sending
    count_after = get_acl_counter(duthost, table_name, rule_name)
    logger.info(f"ACL counter after sending: {count_after}")

    # Verify counter did NOT increment (partial match should not trigger rule)
    if count_after == count_before:
        logger.info(f"✓ PASS: ACL counter did not increment ({count_before} -> {count_after}) - partial match correctly ignored")
    else:
        logger.error(f"✗ FAIL: ACL counter incremented unexpectedly ({count_before} -> {count_after}) - partial match incorrectly triggered rule")
        raise AssertionError(f"Partial match test failed: ACL counter incremented from {count_before} to {count_after}. "
                           f"For partial matches, the counter should not increment.")


def _send_and_verify_no_mac_rewrite(ptfadapter, ptf_port_1, duthost,
                                    src_ip, dst_ip, orig_src_mac,
                                    table_name, rule_name, test_description=""):
    """
    Send a test packet and verify that NO inner source MAC rewrite occurs.
    This is used for partial match cases where the packet should pass through unchanged.
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

    logger.info("=== Pre-packet Debug Information (Partial Match Test) ===")
    logger.info(f"Test packet: src_ip={src_ip}, dst_ip={dst_ip}")
    logger.info(f"Partial match test ({test_description}): Expecting NO MAC rewrite")
    logger.info(f"Original MAC should be preserved: {orig_src_mac}")
    logger.info(f"ACL table: {table_name}, rule: {rule_name}")

    # Check current ACL rule state
    state_db_key = f"ACL_RULE_TABLE|{table_name}|{rule_name}"
    state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    current_state = duthost.shell(state_db_cmd)["stdout"]
    logger.info(f"Current ACL rule state:\n{current_state}")

    # Check routing for the destination IP
    route_check = duthost.shell(f"ip route get {dst_ip}", module_ignore_errors=True)
    logger.info(f"Routing for {dst_ip}: {route_check.get('stdout', 'N/A')}")

    # Get ACL counter before sending
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info(f"ACL counter before sending: {count_before}")

    # Send packet
    logger.info(f"Sending TCP packet on port {ptf_port_1}")
    send_packet(ptfadapter, ptf_port_1, input_pkt)

    # Poll for VXLAN packets - for partial match, we either expect:
    # 1. No packets (packet dropped or not routed)
    # 2. Original packet with unchanged MAC (packet passed through unchanged)
    poll_start = datetime.now()
    poll_timeout = 5  # Shorter timeout since we expect no rewritten packets
    rewritten_packet_found = False
    original_packet_found = False
    packets_received = 0

    while (datetime.now() - poll_start).total_seconds() < poll_timeout:
        res = dp_poll(ptfadapter, timeout=1)
        if not isinstance(res, ptfadapter.dataplane.PollSuccess):
            continue

        packets_received += 1
        ether = Ether(res.packet)
        if IP in ether and UDP in ether and ether[UDP].dport == VXLAN_UDP_PORT:
            vxlan_pkt = ether[UDP].payload
            inner_pkt = Ether(bytes(vxlan_pkt)[8:])  # Skip VXLAN header (8 bytes)
            inner_src_mac = inner_pkt.src
            
            logger.info(f"Received VXLAN packet with inner MAC: {inner_src_mac}")
            
            if inner_src_mac == orig_src_mac:
                original_packet_found = True
                logger.info("Original MAC preserved (acceptable for partial match)")
            else:
                rewritten_packet_found = True
                logger.error(f"Unexpected MAC rewrite detected: {orig_src_mac} -> {inner_src_mac}")
                break

    elapsed_time = (datetime.now() - poll_start).total_seconds()
    
    # For partial match cases, success means NO rewritten packets
    if rewritten_packet_found:
        logger.error(f"FAILED: Unexpected MAC rewrite occurred in partial match case after {elapsed_time:.2f}s")
        raise AssertionError(f"Partial match test failed: MAC rewrite should not occur for {test_description}, but rewrite was detected")
    elif original_packet_found:
        logger.info(f"PASSED: Original MAC preserved as expected for partial match case ({test_description}) after {elapsed_time:.2f}s")
    else:
        # No packets received at all - this is also acceptable for partial match cases
        logger.info(f"No VXLAN packets received after {elapsed_time:.2f}s)")

    # Check ACL counter - for partial matches, counter should NOT increment significantly
    count_after = get_acl_counter(duthost, table_name, rule_name)
    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)
    
    if count_after > count_before:
        logger.warning(f"ACL counter incremented for partial match case - this may indicate unexpected rule matching")
    else:
        logger.info("ACL counter did not increment - expected for partial match case")


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, duthost,
                                 src_ip, dst_ip, orig_src_mac, expected_inner_src_mac,
                                 table_name, rule_name):
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

    # === Enhanced Debugging Before Sending Packet ===
    logger.info("=== Pre-packet Debug Information ===")
    logger.info(f"Test packet: src_ip={src_ip}, dst_ip={dst_ip}")
    logger.info(f"Expected MAC rewrite: {orig_src_mac} -> {expected_inner_src_mac}")
    logger.info(f"ACL table: {table_name}, rule: {rule_name}")

    # Check current ACL rule state
    state_db_key = f"ACL_RULE_TABLE|{table_name}|{rule_name}"
    state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    current_state = duthost.shell(state_db_cmd)["stdout"]
    logger.info(f"Current ACL rule state:\n{current_state}")

    # Check routing for the destination IP
    route_check = duthost.shell(f"ip route get {dst_ip}", module_ignore_errors=True)
    logger.info(f"Routing for {dst_ip}: {route_check.get('stdout', 'N/A')}")

    # Get ACL counter before sending
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info(f"ACL counter before sending: {count_before}")

    # Send packet
    logger.info(f"Sending TCP packet on port {ptf_port_1}")
    send_packet(ptfadapter, ptf_port_1, input_pkt)

    # Poll for VXLAN packets with inner MAC rewrite
    poll_start = datetime.now()
    poll_timeout = 8  # seconds
    success = False

    while (datetime.now() - poll_start).total_seconds() < poll_timeout:
        res = dp_poll(ptfadapter, timeout=2)
        if not isinstance(res, ptfadapter.dataplane.PollSuccess):
            continue

        ether = Ether(res.packet)
        if IP in ether and UDP in ether and ether[UDP].dport == VXLAN_UDP_PORT:
            try:
                # Extract VNI from VXLAN header for debugging
                vxlan_header = bytes(ether[UDP].payload)[:8]
                if len(vxlan_header) >= 8:
                    # VNI is in bytes 4-7 (24 bits)
                    vni = int.from_bytes(vxlan_header[4:7], byteorder='big')
                    logger.info(f"Captured VXLAN packet with VNI: {vni}, expected destination: {dst_ip}")

                # Extract VXLAN payload (skip 8-byte VXLAN header)
                vxlan_payload = bytes(ether[UDP].payload)[8:]
                if len(vxlan_payload) < 14:  # Need at least Ethernet header
                    continue

                # Parse inner Ethernet frame
                inner_eth = Ether(vxlan_payload)
                if not inner_eth.haslayer(Ether):
                    continue

                # Check if inner source MAC matches expected rewritten MAC
                inner_src_mac = inner_eth.src.lower()
                expected_mac = expected_inner_src_mac.lower()

                logger.info(f"Packet details - VNI: {vni}, Inner SRC MAC: {inner_src_mac}, Expected: {expected_mac}")

                if inner_src_mac == expected_mac:
                    logger.info(f"Successfully verified VXLAN packet with inner MAC rewrite: {inner_src_mac}")
                    success = True
                    break

            except Exception as e:
                logger.warning(f"Error parsing VXLAN packet: {e}")
                continue

    elapsed_time = (datetime.now() - poll_start).total_seconds()
    if success:
        logger.info(f"Packet verification completed in {elapsed_time:.2f} seconds")
    else:
        raise AssertionError(f"No valid VXLAN packet with expected inner source MAC {expected_inner_src_mac} "
                             f"received after {elapsed_time:.2f} seconds")

    # Check ACL counter incremented
    count_after = get_acl_counter(duthost, table_name, rule_name)
    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)
    pytest_assert(count_after >= count_before + 1,
                  f"ACL counter did not increment for {src_ip}. before={count_before}, after={count_after}")


def _test_inner_src_mac_rewrite(setUp, scenario_name):
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios'][scenario_name]

    ptf_port_1 = setUp['ptf_port_1']
    bind_ports = setUp['bind_ports']

    # Extract scenario-specific MAC addresses
    original_inner_src_mac = scenario['original_mac']
    first_modified_mac = scenario['first_modified_mac']
    second_modified_mac = scenario['second_modified_mac']

    # Configuration values
    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME

    # Standard values from VXLAN/VNET configuration
    inner_dst_ip = "150.0.3.1"  # Route destination
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

        setup_acl_rules(duthost, acl_rule_prefix, vni_id, first_modified_mac)

        # Test with the configured source IP
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
            first_modified_mac, table_name, RULE_NAME
        )

        # For range test, also test with different IPs in the range
        if scenario_name == "range_test":
            test_ips = ["201.0.0.102", "201.0.0.103", "201.0.0.104"]  # Additional IPs in the 201.0.0.0/24 range
            for test_ip in test_ips:
                logger.info(f"Range test: Verifying rewrite with IP {test_ip}")
                _send_and_verify_mac_rewrite(
                    ptfadapter, ptf_port_1, duthost, test_ip, inner_dst_ip, original_inner_src_mac,
                    first_modified_mac, table_name, RULE_NAME)

        # Modify ACL rule to use new MAC address (much more efficient than remove/recreate)
        logger.info("Step 3: Modifying ACL rule to use new MAC: %s", second_modified_mac)
        modify_acl_rule(duthost, acl_rule_prefix, vni_id, second_modified_mac)

        logger.info("Step 4: Verifying rewrite with second modified MAC: %s", second_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
            second_modified_mac, table_name, RULE_NAME
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


def test_vni_match_no_ip_match(setUp):
    """
    Partial match case 1: VNI matches but IP doesn't match.
    Validates that when VNI matches but source IP doesn't match ACL rule,
    the ACL counter should NOT increment (partial match should not trigger rule).
    Test PASSES if counter stays the same, FAILS if counter increments.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    bind_ports = setUp['bind_ports']

    # Extract MAC addresses
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac = scenario['first_modified_mac']

    try:
        # Create additional VNETs for testing
        create_additional_vnets(
            duthost=duthost,
            tunnel_name=setUp['vxlan_tunnel_name']
        )

        time.sleep(10)

        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Create ACL rule for VNI 10000 with specific source IP
        test_rule_ip = "202.1.1.100/32"  # Specific IP that won't match test traffic
        setup_multi_vni_acl_rule(
            duthost,
            test_rule_ip,
            str(VXLAN_VNI),  # VNI 10000
            rewrite_mac,
            "rule_vni_match_no_ip",
            "1001"
        )

        # Send traffic with VNI 10000 (matches) but different source IP (no match)
        test_src_ip = "202.1.1.200"  # Different from rule IP 202.1.1.100
        test_dst_ip = "150.0.3.1"    # Routes through VNI 10000

        logger.info(f"Testing VNI match (10000) with non-matching source IP {test_src_ip}")

        # Verify ACL counter does NOT increment (partial ACL match should not trigger rule)
        _send_and_verify_acl_counter_no_increment(
            ptfadapter, ptf_port_1, duthost,
            test_src_ip, test_dst_ip, original_inner_src_mac,
            ACL_TABLE_NAME, "rule_vni_match_no_ip"
        )

        logger.info("=== VNI match, no IP match test completed successfully ===")

    finally:
        try:
            remove_specific_acl_rule(duthost, "rule_vni_match_no_ip")
            remove_acl_table(duthost)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def test_ip_match_no_vni_match(setUp):
    """
    Partial match case 2: IP matches but VNI doesn't match.
    Validates that when source IP matches ACL rule but VNI doesn't match,
    the ACL counter should NOT increment (partial match should not trigger rule).
    Test PASSES if counter stays the same, FAILS if counter increments.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    bind_ports = setUp['bind_ports']

    # Extract MAC addresses
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac = scenario['second_modified_mac']

    try:
        # Create additional VNETs for testing
        create_additional_vnets(
            duthost=duthost,
            tunnel_name=setUp['vxlan_tunnel_name']
        )

        time.sleep(10)

        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Create ACL rule for VNI 30000 with specific source IP
        test_src_ip = "202.2.2.100"
        setup_multi_vni_acl_rule(
            duthost,
            f"{test_src_ip}/32",
            str(VXLAN_VNI_3),  # VNI 30000 (won't match traffic going through VNI 10000)
            rewrite_mac,
            "rule_ip_match_no_vni",
            "1001"
        )

        # Send traffic with matching source IP but through different VNI
        test_dst_ip = "150.0.3.1"  # Routes through VNI 10000 (not VNI 30000)

        logger.info(f"Testing IP match ({test_src_ip}) with non-matching VNI (traffic goes via VNI 10000, rule for VNI 30000)")

        # Verify ACL counter does NOT increment (partial ACL match should not trigger rule)
        _send_and_verify_acl_counter_no_increment(
            ptfadapter, ptf_port_1, duthost,
            test_src_ip, test_dst_ip, original_inner_src_mac,
            ACL_TABLE_NAME, "rule_ip_match_no_vni"
        )

        logger.info("=== IP match, no VNI match test completed successfully ===")

    finally:
        try:
            remove_specific_acl_rule(duthost, "rule_ip_match_no_vni")
            remove_acl_table(duthost)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def test_acl_rule_no_priority(setUp):
    """
    Test ACL rule creation without explicit priority value.
    Validates that ACL rules can be created without priority and system assigns default.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    bind_ports = setUp['bind_ports']

    # Extract MAC addresses
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac = scenario['third_modified_mac']

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Create ACL rule WITHOUT priority (should use default)
        test_src_ip = "202.3.3.100"
        test_dst_ip = "150.0.3.1"

        logger.info("Creating ACL rule without explicit priority")

        # Create rule without priority parameter (uses function default)
        acl_rule = {
            "ACL_RULE": {
                f"{ACL_TABLE_NAME}|rule_no_priority": {
                    # Note: No "priority" field specified
                    "TUNNEL_VNI": str(VXLAN_VNI),
                    "INNER_SRC_IP": f"{test_src_ip}/32",
                    "INNER_SRC_MAC_REWRITE_ACTION": rewrite_mac
                }
            }
        }

        acl_rule_json = json.dumps(acl_rule, indent=4)
        dest_path = os.path.join(TMP_DIR, "acl_rule_no_priority.json")

        logger.info("Writing ACL rule without priority to %s:\n%s", dest_path, acl_rule_json)
        duthost.copy(content=acl_rule_json, dest=dest_path)

        logger.info("Loading ACL rule without priority from %s", dest_path)
        load_result = duthost.shell(f"config load -y {dest_path}", module_ignore_errors=True)

        if load_result.get("rc", 0) != 0:
            logger.error("Config load failed: %s", load_result.get("stderr", ""))
            pytest.fail("Failed to load ACL rule configuration without priority")

        time.sleep(5)  # Wait for rule application

        # Verify rule was created and check what priority was assigned
        state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_no_priority"
        state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
        state_db_output = duthost.shell(state_db_cmd)["stdout"]
        logger.info(f"Rule state in STATE_DB: {state_db_output}")

        # Test that the rule works (MAC rewrite should occur)
        logger.info(f"Testing ACL rule without priority: src={test_src_ip}, dst={test_dst_ip}")
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, duthost,
            test_src_ip, test_dst_ip, original_inner_src_mac,
            rewrite_mac,  # Expect MAC rewrite to occur
            ACL_TABLE_NAME, "rule_no_priority"
        )

        logger.info("=== ACL rule without priority test completed successfully ===")

    finally:
        try:
            remove_specific_acl_rule(duthost, "rule_no_priority")
            remove_acl_table(duthost)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def test_multiple_acl_rules_same_priority(setUp):
    """
    Test two ACL rules with different source IPs but same VNI and priority.
    Validates that both rules are active and their counters increment independently.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    bind_ports = setUp['bind_ports']

    # Extract MAC addresses
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']

    # Test parameters
    test_src_ip_1 = "203.1.1.100"
    test_src_ip_2 = "203.1.1.200"  # Different source IP
    test_dst_ip = "150.0.3.1"
    test_vni = str(VXLAN_VNI)  # Same VNI for both rules
    test_priority = "1005"     # Same priority for both rules
    rule_name_1 = "rule_multi_1"
    rule_name_2 = "rule_multi_2"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info("Creating two ACL rules with different source IPs but same VNI and priority")
        logger.info(f"Rule 1: src_ip={test_src_ip_1}, VNI={test_vni}, priority={test_priority}, MAC={rewrite_mac_1}")
        logger.info(f"Rule 2: src_ip={test_src_ip_2}, VNI={test_vni}, priority={test_priority}, MAC={rewrite_mac_2}")

        # Create both ACL rules in a single configuration
        dual_acl_rules = {
            "ACL_RULE": {
                f"{ACL_TABLE_NAME}|{rule_name_1}": {
                    "priority": test_priority,
                    "TUNNEL_VNI": test_vni,
                    "INNER_SRC_IP": f"{test_src_ip_1}/32",
                    "INNER_SRC_MAC_REWRITE_ACTION": rewrite_mac_1
                },
                f"{ACL_TABLE_NAME}|{rule_name_2}": {
                    "priority": test_priority,
                    "TUNNEL_VNI": test_vni,
                    "INNER_SRC_IP": f"{test_src_ip_2}/32",
                    "INNER_SRC_MAC_REWRITE_ACTION": rewrite_mac_2
                }
            }
        }

        acl_rules_json = json.dumps(dual_acl_rules, indent=4)
        dest_path = os.path.join(TMP_DIR, "dual_acl_rules.json")

        logger.info("Writing dual ACL rules to %s:\n%s", dest_path, acl_rules_json)
        duthost.copy(content=acl_rules_json, dest=dest_path)

        logger.info("Loading dual ACL rules from %s", dest_path)
        load_result = duthost.shell(f"config load -y {dest_path}", module_ignore_errors=True)

        if load_result.get("rc", 0) != 0:
            logger.error("Config load failed: %s", load_result.get("stderr", ""))
            pytest.fail("Failed to load dual ACL rule configuration")

        logger.info("Waiting for both ACL rules to be applied...")
        time.sleep(15)  # Wait for both rules to be applied

        # Verify both rules were created in STATE_DB
        for rule_name in [rule_name_1, rule_name_2]:
            state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|{rule_name}"
            state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
            state_db_output = duthost.shell(state_db_cmd)["stdout"]
            logger.info(f"STATE_DB entry for rule {rule_name}:\n%s", state_db_output)

            if "status" not in state_db_output or "Active" not in state_db_output:
                pytest.fail(f"ACL rule {rule_name} is not active in STATE_DB")

        logger.info("Both ACL rules are active in STATE_DB")

        # Test Rule 1: Send packet matching first source IP
        logger.info(f"=== Testing Rule 1: {rule_name_1} with source IP {test_src_ip_1} ===")
        
        # Get initial counter for rule 1
        counter_1_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_before = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Initial counters - Rule 1: {counter_1_before}, Rule 2: {counter_2_before}")

        # Send packet that should match rule 1
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, duthost,
            test_src_ip_1, test_dst_ip, original_inner_src_mac,
            rewrite_mac_1,  # Should use MAC from rule 1
            ACL_TABLE_NAME, rule_name_1
        )

        # Check counters after rule 1 test
        counter_1_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_after = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Counters after rule 1 test - Rule 1: {counter_1_after}, Rule 2: {counter_2_after}")

        # Verify rule 1 counter incremented but rule 2 counter stayed the same
        pytest_assert(counter_1_after >= counter_1_before + 1,
                      f"Rule 1 counter did not increment: {counter_1_before} -> {counter_1_after}")
        pytest_assert(counter_2_after == counter_2_before,
                      f"Rule 2 counter should not have incremented: {counter_2_before} -> {counter_2_after}")

        # Test Rule 2: Send packet matching second source IP
        logger.info(f"=== Testing Rule 2: {rule_name_2} with source IP {test_src_ip_2} ===")
        
        # Update counters baseline
        counter_1_baseline = counter_1_after
        counter_2_baseline = counter_2_after

        # Send packet that should match rule 2
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, duthost,
            test_src_ip_2, test_dst_ip, original_inner_src_mac,
            rewrite_mac_2,  # Should use MAC from rule 2
            ACL_TABLE_NAME, rule_name_2
        )

        # Check final counters
        counter_1_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_1, timeout=0)
        counter_2_final = get_acl_counter(duthost, ACL_TABLE_NAME, rule_name_2, timeout=0)
        logger.info(f"Final counters - Rule 1: {counter_1_final}, Rule 2: {counter_2_final}")

        # Verify rule 2 counter incremented but rule 1 counter stayed the same
        pytest_assert(counter_2_final >= counter_2_baseline + 1,
                      f"Rule 2 counter did not increment: {counter_2_baseline} -> {counter_2_final}")
        pytest_assert(counter_1_final == counter_1_baseline,
                      f"Rule 1 counter should not have incremented: {counter_1_baseline} -> {counter_1_final}")

        # Summary
        logger.info("=== Test Summary ===")
        logger.info(f"Rule 1 ({test_src_ip_1}): {counter_1_before} -> {counter_1_final} (increment: {counter_1_final - counter_1_before})")
        logger.info(f"Rule 2 ({test_src_ip_2}): {counter_2_before} -> {counter_2_final} (increment: {counter_2_final - counter_2_before})")

        logger.info("=== Multiple ACL rules test completed successfully ===")

    finally:
        try:
            remove_specific_acl_rule(duthost, rule_name_1)
            remove_specific_acl_rule(duthost, rule_name_2)
            remove_acl_table(duthost)
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")


def setup_multi_vni_acl_rule(duthost, inner_src_ip, vni, new_src_mac, rule_name, priority="1005"):
    """Setup ACL rule for specific VNI in multi-VNI test"""
    acl_rule = {
        "ACL_RULE": {
            f"{ACL_TABLE_NAME}|{rule_name}": {
                "priority": priority,
                "TUNNEL_VNI": vni,
                "INNER_SRC_IP": inner_src_ip,
                "INNER_SRC_MAC_REWRITE_ACTION": new_src_mac
            }
        }
    }

    acl_rule_json = json.dumps(acl_rule, indent=4)
    dest_path = os.path.join(TMP_DIR, f"acl_rule_{rule_name}.json")

    logger.info("Writing multi-VNI ACL rule to %s:\n%s", dest_path, acl_rule_json)
    duthost.copy(content=acl_rule_json, dest=dest_path)

    logger.info("Loading ACL rule from %s", dest_path)
    load_result = duthost.shell(f"config load -y {dest_path}", module_ignore_errors=True)
    logger.info("Config load result: rc=%s, stdout=%s", load_result.get("rc", "unknown"), load_result.get("stdout", ""))

    if load_result.get("rc", 0) != 0:
        logger.error("Config load failed: %s", load_result.get("stderr", ""))
        pytest.fail(f"Failed to load ACL rule configuration for {rule_name}")

    logger.info(f"Waiting for ACL rule {rule_name} to be applied...")
    time.sleep(15)  # Increased wait time to match working setup

    # Check CONFIG_DB for the rule
    logger.info(f"Checking if rule {rule_name} was added to CONFIG_DB...")
    rule_config_cmd = f'redis-cli -n 4 HGETALL "ACL_RULE|{ACL_TABLE_NAME}|{rule_name}"'
    rule_config_result = duthost.shell(rule_config_cmd)["stdout"]
    logger.info(f"ACL rule {rule_name} in CONFIG_DB:\n%s", rule_config_result)

    # === Show ACL Rule Verification ===
    logger.info(f"Verifying ACL rule {rule_name} state using 'show acl rule'")
    rule_result = duthost.shell("show acl rule", module_ignore_errors=True)
    rule_output = rule_result.get("stdout", "")
    logger.info("Output of 'show acl rule':\n%s", rule_output)

    # Check that the rule shows up and is Active
    if ACL_TABLE_NAME not in rule_output or rule_name not in rule_output:
        pytest.fail(f"ACL rule for table {ACL_TABLE_NAME} and rule {rule_name} not found in 'show acl rule' output")

    if "Active" not in rule_output:
        logger.warning(f"ACL rule for table {ACL_TABLE_NAME} is not showing as Active in 'show acl rule' output")

    # === STATE_DB Verification ===
    logger.info(f"Verifying ACL rule {rule_name} propagation to STATE_DB...")
    state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|{rule_name}"
    state_db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    state_db_output = duthost.shell(state_db_cmd)["stdout"]

    logger.info(f"STATE_DB entry for ACL rule {rule_name}:\n%s", state_db_output)

    # Check if the rule is active in STATE_DB (this indicates successful propagation)
    if "status" in state_db_output and "Active" in state_db_output:
        logger.info(f"ACL rule {rule_name} is active in STATE_DB for VNI {vni}")
        # Also verify the CONFIG_DB has the correct MAC to confirm the setup
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|{rule_name}"
        config_verification = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" INNER_SRC_MAC_REWRITE_ACTION')["stdout"]
        pytest_assert(config_verification.strip() == new_src_mac,
                      f"CONFIG_DB does not have expected MAC {new_src_mac} for rule {rule_name}, got: {config_verification.strip()}")
        logger.info(f"STATE_DB validation successful - rule {rule_name} is active with MAC {new_src_mac}")
    else:
        logger.warning(f"ACL rule {rule_name} may not be active in STATE_DB")


def remove_specific_acl_rule(duthost, rule_name):
    """Remove specific ACL rule for cleanup"""
    try:
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|{rule_name}"
        duthost.shell(f'redis-cli -n 4 DEL "{rule_key}"', module_ignore_errors=True)
        logger.info(f"Removed ACL rule: {rule_name}")
    except Exception as e:
        logger.warning(f"Failed to remove ACL rule {rule_name}: {e}")
