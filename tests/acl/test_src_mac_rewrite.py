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
from ptf.mask import Mask
from ptf.packet import Ether, IP, UDP
from tests.common.helpers.assertions import pytest_assert
from ptf import testutils
from ptf.testutils import send_packet
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

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

    def _check_vnet_route(duthost):
        result = duthost.shell(
            "redis-cli -n 6 HGET 'VNET_ROUTE_TUNNEL_TABLE|Vnet-0|150.0.3.1/32' 'state'",
            module_ignore_errors=True
        )["stdout"]
        return result.strip().lower() == "active"

    # Debug: Check what VNETs actually exist
    logger.info("Checking VNET configuration after setup...")
    vnet_list = rand_selected_dut.shell("show vnet brief", module_ignore_errors=True)["stdout"]
    logger.info("VNET list output:\n%s", vnet_list)
    pytest_assert("Vnet-0" in vnet_list, "Vnet-0 not found in 'show vnet brief' output")

    vnet_config = rand_selected_dut.shell("redis-cli -n 4 KEYS 'VNET*'", module_ignore_errors=True)["stdout"]
    logger.info("CONFIG_DB VNET keys:\n%s", vnet_config)
    pytest_assert("VNET|Vnet-0" in vnet_config, "VNET|Vnet-0 not found in CONFIG_DB")

    # Wait for VNET route to be active in STATE_DB (confirms orchagent programmed it)
    if not wait_until(60, 5, 5, _check_vnet_route, rand_selected_dut):
        vnet_route_state = rand_selected_dut.shell(
            "redis-cli -n 6 HGETALL 'VNET_ROUTE_TUNNEL_TABLE|Vnet-0|150.0.3.1/32'",
            module_ignore_errors=True
        )["stdout"]
        logger.error("STATE_DB VNET route entry:\n%s", vnet_route_state)
        pytest.fail("VNET route for 150.0.3.1/32 is not active in STATE_DB")

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


def get_acl_counter(duthost, table_name, rule_name, timeout=ACL_COUNTERS_UPDATE_INTERVAL, prev_count=0):
    def _check_acl_counter_updated(dut, tbl, rule, prev):
        result = dut.show_and_parse('aclshow -a')
        for entry in result:
            if entry.get('table name') == tbl and entry.get('rule name') == rule:
                try:
                    return int(entry.get('packets count', 0)) > prev
                except ValueError:
                    return False
        return False

    # Wait for orchagent to update the ACL counters
    if timeout > 0:
        wait_until(timeout, 2, 0, _check_acl_counter_updated, duthost, table_name, rule_name, prev_count)
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

    def _check_acl_table_type_in_config_db(duthost, type_name):
        result = duthost.shell(f'redis-cli -n 4 KEYS "ACL_TABLE_TYPE|{type_name}"')["stdout"]
        return type_name in result

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

    def _check_acl_table_present(duthost, table_name):
        result = duthost.shell(f'redis-cli -n 4 KEYS "ACL_TABLE|{table_name}"')["stdout"]
        return table_name in result

    pytest_assert(wait_until(30, 5, 2, _check_acl_table_present, duthost, ACL_TABLE_NAME),
                  f"ACL table {ACL_TABLE_NAME} not found in CONFIG_DB after creation")

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

    def _check_acl_table_absent(duthost, table_name):
        result = duthost.shell(f'redis-cli -n 6 KEYS "ACL_TABLE_TABLE:{table_name}"')["stdout"]
        return table_name not in result

    pytest_assert(wait_until(30, 5, 2, _check_acl_table_absent, duthost, ACL_TABLE_NAME),
                  f"ACL table {ACL_TABLE_NAME} still present in STATE_DB after removal")

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

    logger.info("Loading ACL rule config:\n%s", json.dumps(acl_rule, indent=4))
    apply_config_chunk(duthost, acl_rule, "acl_rule_setup")

    def _check_acl_rule_active(duthost, table_name, rule_name):
        result = duthost.shell(
            f'redis-cli -n 6 HGET "ACL_RULE_TABLE|{table_name}|{rule_name}" "status"'
        )["stdout"]
        return result.strip().lower() == "active"

    logger.info("Waiting for ACL rule to be applied...")
    pytest_assert(wait_until(30, 5, 2, _check_acl_rule_active, duthost, ACL_TABLE_NAME, "rule_1"),
                  "ACL rule not active in STATE_DB after loading")

    # Check CONFIG_DB for the rule
    logger.info("Checking if rule was added to CONFIG_DB...")
    rule_config_cmd = f'redis-cli -n 4 HGETALL "ACL_RULE|{ACL_TABLE_NAME}|rule_1"'
    rule_config_result = duthost.shell(rule_config_cmd)["stdout"]
    logger.info("ACL rule in CONFIG_DB:\n%s", rule_config_result)
    pytest_assert(rule_config_result.strip(), "ACL rule rule_1 not found in CONFIG_DB")

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

    # Verify the rule is active in STATE_DB (this indicates successful propagation)
    pytest_assert("status" in state_db_output and "Active" in state_db_output,
                  f"ACL rule rule_1 is not active in STATE_DB. Entry: {state_db_output}")
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

    # Use config load to update the rule, which properly triggers change notifications
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
    apply_config_chunk(duthost, acl_rule, "acl_rule_modify")

    # Verify the MAC was updated in CONFIG_DB (STATE_DB only stores status, not rule fields)
    def _check_config_db_mac_updated(duthost, table_name, expected_mac):
        rule_key = f"ACL_RULE|{table_name}|rule_1"
        result = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" "INNER_SRC_MAC_REWRITE_ACTION"')["stdout"]
        return expected_mac in result

    logger.info("Waiting for CONFIG_DB to reflect the updated MAC...")
    pytest_assert(wait_until(30, 5, 2, _check_config_db_mac_updated, duthost, ACL_TABLE_NAME, new_src_mac),
                  f"CONFIG_DB not updated with new MAC {new_src_mac}")

    # Verify the rule is still active in STATE_DB (confirms orchagent re-programmed it)
    logger.info("Verifying ACL rule is still active in STATE_DB after modification...")
    state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1"
    db_cmd = f"redis-cli -n 6 HGETALL \"{state_db_key}\""
    state_db_output = duthost.shell(db_cmd)["stdout"]
    logger.info("STATE_DB entry for modified ACL rule:\n%s", state_db_output)

    pytest_assert("status" in state_db_output and "Active" in state_db_output,
                  f"ACL rule rule_1 is not active in STATE_DB after modification. Entry: {state_db_output}")

    logger.info("ACL rule successfully modified to use MAC: %s", new_src_mac)


def remove_acl_rules(duthost):
    duthost.copy(src=os.path.join(FILES_DIR, ACL_REMOVE_RULES_FILE), dest=TMP_DIR)
    remove_rules_dut_path = os.path.join(TMP_DIR, ACL_REMOVE_RULES_FILE)
    duthost.command("acl-loader update full {} --table_name {}".format(remove_rules_dut_path, ACL_TABLE_NAME))

    def _check_acl_rule_absent(duthost, table_name, rule_name):
        result = duthost.shell(
            f'redis-cli -n 6 KEYS "ACL_RULE_TABLE|{table_name}|{rule_name}"'
        )["stdout"]
        return rule_name not in result

    pytest_assert(wait_until(30, 5, 2, _check_acl_rule_absent, duthost, ACL_TABLE_NAME, "rule_1"),
                  "ACL rule still in STATE_DB after removal")

    # === STATE_DB Deletion Check ===
    logger.info("Checking STATE_DB to confirm ACL rule deletion...")
    state_db_key = f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1"
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

    logger.info("Creating VXLAN tunnel:\n%s", json.dumps(tunnel_config, indent=4))
    apply_config_chunk(duthost, tunnel_config, "vxlan_tunnel")

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

    # Configure VNET route via CONFIG_DB so 'show vnet route all' can see it
    logger.info("Configuring primary VNET route via CONFIG_DB")
    route_config = {
        "VNET_ROUTE_TUNNEL": {
            f"{vnet_name}|150.0.3.1/32": {
                "endpoint": ptf_vtep
            }
        }
    }
    apply_config_chunk(duthost, route_config, "vnet_route")

    def _check_vxlan_tunnel_config(duthost, tunnel_name):
        result = duthost.shell(f'redis-cli -n 4 KEYS "VXLAN_TUNNEL|{tunnel_name}"')["stdout"]
        return tunnel_name in result

    pytest_assert(wait_until(60, 5, 5, _check_vxlan_tunnel_config, duthost, tunnel_name),
                  f"VXLAN tunnel {tunnel_name} not found in CONFIG_DB after setup")

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=VXLAN_UDP_PORT, dutmac=router_mac)

    # Allow time for VXLAN switch config to propagate through swss pipeline
    def _check_vxlan_switch_config(duthost):
        result = duthost.shell('redis-cli -n 0 KEYS "SWITCH_TABLE:switch"', module_ignore_errors=True)
        return "SWITCH_TABLE:switch" in result.get("stdout", "")

    pytest_assert(wait_until(10, 2, 2, _check_vxlan_switch_config, duthost),
                  "SWITCH_TABLE:switch not found in APP_DB after configure_vxlan_switch")


def apply_config_chunk(duthost, payload, config_name):
    """Apply configuration chunk using config load for proper notification"""
    content = json.dumps(payload, indent=2)
    file_dest = f"/tmp/{config_name}_chunk.json"
    duthost.copy(content=content, dest=file_dest)
    duthost.shell(f"config load -y {file_dest}")
    duthost.shell(f"rm -f {file_dest}")


def create_additional_vnets(duthost, tunnel_name):
    """Create additional VNETs for multi-VNI testing"""
    ptf_vtep = PTF_VTEP_IP

    logger.info("Creating additional VNETs and routes")

    combined_config = {
        "VNET": {
            "Vnet2-0": {
                "vni": str(VXLAN_VNI_2),
                "vxlan_tunnel": tunnel_name
            },
            "Vnet3-0": {
                "vni": str(VXLAN_VNI_3),
                "vxlan_tunnel": tunnel_name
            }
        },
        "VNET_ROUTE_TUNNEL": {
            "Vnet2-0|151.0.3.1/32": {
                "endpoint": ptf_vtep,
                "vni": str(VXLAN_VNI_2)
            },
            "Vnet3-0|152.0.3.1/32": {
                "endpoint": ptf_vtep,
                "vni": str(VXLAN_VNI_3)
            }
        }
    }

    apply_config_chunk(duthost, combined_config, "additional_vnets")

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
                "/tmp/vxlan_tunnel_chunk.json",  # Created by create_vxlan_vnet_config
                "/tmp/additional_vnets_chunk.json",  # Created by create_additional_vnets
                "/tmp/additional_vnet_routes_chunk.json",  # Created by create_additional_vnets

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


def _create_and_send_test_packet(ptfadapter, ptf_port_1, duthost, src_ip, dst_ip,
                                  orig_src_mac, table_name, rule_name, test_label=""):
    """
    Common helper to create a test packet, log pre-send debug info, and send it.
    Returns the ACL counter value before sending.
    """
    router_mac = duthost.facts["router_mac"]

    input_pkt = testutils.simple_tcp_packet(
        pktlen=100, eth_dst=router_mac, eth_src=orig_src_mac,
        ip_dst=dst_ip, ip_src=src_ip, ip_id=105, ip_ttl=64,
        tcp_sport=1234, tcp_dport=5000, ip_ecn=0
    )

    logger.info(f"=== {test_label} ===")
    logger.info(f"Test packet: src_ip={src_ip}, dst_ip={dst_ip}")
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

    return count_before


def _send_and_verify_acl_counter_no_increment(ptfadapter, ptf_port_1, duthost,
                                              src_ip, dst_ip, orig_src_mac, table_name, rule_name):
    """
    Send a packet and verify that the ACL counter does NOT increment for partial matches.
    """
    count_before = _create_and_send_test_packet(
        ptfadapter, ptf_port_1, duthost, src_ip, dst_ip, orig_src_mac,
        table_name, rule_name, test_label="Partial Match Counter Test"
    )

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


def _send_and_verify_no_mac_rewrite(ptfadapter, ptf_port_1, ptf_ports, duthost,
                                    src_ip, dst_ip, orig_src_mac,
                                    table_name, rule_name, rewrite_mac,
                                    test_description="", vni=VXLAN_VNI):
    """
    Send a test packet and verify that the ACL did NOT rewrite the inner source MAC.
    After L3 routing + VXLAN encap on Cisco-8000, the inner eth_src defaults to
    vxlan_router_mac and the ACL INNER_SRC_MAC_REWRITE_ACTION would change it.
    We verify the inner src MAC is NOT the ACL rewrite_mac.
    """
    router_mac = duthost.facts["router_mac"]
    # vxlan_router_mac is the MAC the ASIC uses as inner eth_src/dst before any ACL rewrite
    vxlan_router_mac = duthost.shell(
        "redis-cli -n 0 HGET 'SWITCH_TABLE:switch' 'vxlan_router_mac'"
    )["stdout"].strip()
    logger.info("vxlan_router_mac=%s, router_mac=%s", vxlan_router_mac, router_mac)

    inner_exp_pkt = testutils.simple_tcp_packet(
        pktlen=100,
        eth_src=vxlan_router_mac,
        eth_dst=vxlan_router_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_id=105,
        ip_ttl=63,
        tcp_sport=1234,
        tcp_dport=5000,
        ip_ecn=0
    )
    expected_pkt = testutils.simple_vxlan_packet(
        eth_src=router_mac,
        eth_dst="ff:ff:ff:ff:ff:ff",
        ip_src=DUT_VTEP_IP,
        ip_dst=PTF_VTEP_IP,
        ip_id=0,
        ip_flags=0x2,
        udp_sport=0,
        udp_dport=VXLAN_UDP_PORT,
        with_udp_chksum=False,
        vxlan_vni=vni,
        inner_frame=inner_exp_pkt
    )
    masked_pkt = Mask(expected_pkt)
    masked_pkt.set_do_not_care_scapy(Ether, 'dst')
    masked_pkt.set_do_not_care(176, 8)                # outer IP TTL
    masked_pkt.set_do_not_care_scapy(IP, 'chksum')
    masked_pkt.set_do_not_care_scapy(UDP, 'sport')
    masked_pkt.set_do_not_care_scapy(UDP, 'chksum')
    masked_pkt.set_do_not_care(448, 48)               # inner eth src
    masked_pkt.set_do_not_care(800, 16)               # inner TCP checksum
    masked_pkt.set_do_not_care(832, 368)              # inner TCP payload
    masked_pkt.set_ignore_extra_bytes()

    # Flush stale background packets, then send and immediately start listening
    ptfadapter.dataplane.flush()
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info(
        "=== Partial Match Test (%s): Expecting NO MAC rewrite to %s ===",
        test_description, rewrite_mac
    )
    send_packet(ptfadapter, ptf_port_1, testutils.simple_tcp_packet(
        pktlen=100, eth_dst=router_mac, eth_src=orig_src_mac,
        ip_dst=dst_ip, ip_src=src_ip, ip_id=105, ip_ttl=64,
        tcp_sport=1234, tcp_dport=5000, ip_ecn=0
    ))

    logger.info(
        "Verifying VXLAN packet without MAC rewrite "
        "(inner src MAC should NOT be rewrite MAC %s) on ports %s",
        rewrite_mac, ptf_ports
    )
    testutils.verify_packet_any_port(ptfadapter, masked_pkt, ptf_ports, timeout=5)
    logger.info("PASSED: VXLAN packet received without ACL rewrite for partial match case (%s)", test_description)

    # Check ACL counter - for partial matches, counter should NOT increment
    count_after = get_acl_counter(duthost, table_name, rule_name)
    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)

    if count_after > count_before:
        logger.warning("ACL counter incremented for partial match case - this may indicate unexpected rule matching")
    else:
        logger.info("ACL counter did not increment - expected for partial match case")


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, ptf_ports, duthost,
                                 src_ip, dst_ip, orig_src_mac, expected_inner_src_mac,
                                 table_name, rule_name, vni=VXLAN_VNI):
    router_mac = duthost.facts["router_mac"]
    # vxlan_router_mac is the MAC the ASIC uses as inner eth_dst (and default inner eth_src
    # before ACL rewrite) — distinct from router_mac on Cisco-8000
    vxlan_router_mac = duthost.shell(
        "redis-cli -n 0 HGET 'SWITCH_TABLE:switch' 'vxlan_router_mac'"
    )["stdout"].strip()
    logger.info("vxlan_router_mac=%s, router_mac=%s", vxlan_router_mac, router_mac)

    inner_exp_pkt = testutils.simple_tcp_packet(
        pktlen=100,
        eth_src=expected_inner_src_mac,
        eth_dst=vxlan_router_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_id=105,
        ip_ttl=63,
        tcp_sport=1234,
        tcp_dport=5000,
        ip_ecn=0
    )
    expected_pkt = testutils.simple_vxlan_packet(
        eth_src=router_mac,
        eth_dst="ff:ff:ff:ff:ff:ff",
        ip_src=DUT_VTEP_IP,
        ip_dst=PTF_VTEP_IP,
        ip_id=0,
        ip_flags=0x2,
        udp_sport=0,
        udp_dport=VXLAN_UDP_PORT,
        with_udp_chksum=False,
        vxlan_vni=vni,
        inner_frame=inner_exp_pkt
    )
    masked_pkt = Mask(expected_pkt)
    masked_pkt.set_do_not_care_scapy(Ether, 'dst')
    masked_pkt.set_do_not_care(176, 8)                # outer IP TTL
    masked_pkt.set_do_not_care_scapy(IP, 'chksum')
    masked_pkt.set_do_not_care_scapy(UDP, 'sport')
    masked_pkt.set_do_not_care_scapy(UDP, 'chksum')
    # Do NOT mask inner eth src (bytes 56-61) — verifying the rewrite MAC is the core assertion
    masked_pkt.set_do_not_care(800, 16)               # inner TCP checksum
    masked_pkt.set_do_not_care(832, 368)              # inner TCP payload
    masked_pkt.set_ignore_extra_bytes()

    # Flush stale background packets, then send and immediately start listening
    ptfadapter.dataplane.flush()
    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info(
        "=== MAC Rewrite Test (expected: %s -> %s) ===",
        orig_src_mac, expected_inner_src_mac
    )
    send_packet(ptfadapter, ptf_port_1, testutils.simple_tcp_packet(
        pktlen=100, eth_dst=router_mac, eth_src=orig_src_mac,
        ip_dst=dst_ip, ip_src=src_ip, ip_id=105, ip_ttl=64,
        tcp_sport=1234, tcp_dport=5000, ip_ecn=0
    ))

    logger.info("Verifying VXLAN packet with inner src MAC=%s on ports %s", expected_inner_src_mac, ptf_ports)
    testutils.verify_packet_any_port(ptfadapter, masked_pkt, ptf_ports, timeout=8)
    logger.info("Successfully verified VXLAN packet with inner MAC rewrite: %s", expected_inner_src_mac)

    count_after = get_acl_counter(duthost, table_name, rule_name, prev_count=count_before)
    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)
    pytest_assert(count_after >= count_before + 1,
                  f"ACL counter did not increment for {src_ip}. before={count_before}, after={count_after}")


def _test_inner_src_mac_rewrite(setUp, scenario_name):
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios'][scenario_name]

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
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
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
            first_modified_mac, table_name, RULE_NAME
        )

        # For range test, also test with different IPs in the range
        if scenario_name == "range_test":
            test_ips = ["201.0.0.102", "201.0.0.103", "201.0.0.104"]  # Additional IPs in the 201.0.0.0/24 range
            for test_ip in test_ips:
                logger.info(f"Range test: Verifying rewrite with IP {test_ip}")
                _send_and_verify_mac_rewrite(
                    ptfadapter, ptf_port_1, ptf_port_2, duthost, test_ip, inner_dst_ip, original_inner_src_mac,
                    first_modified_mac, table_name, RULE_NAME)

        # Modify ACL rule to use new MAC address (much more efficient than remove/recreate)
        logger.info("Step 3: Modifying ACL rule to use new MAC: %s", second_modified_mac)
        modify_acl_rule(duthost, acl_rule_prefix, vni_id, second_modified_mac)

        logger.info("Step 4: Verifying rewrite with second modified MAC: %s", second_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, inner_src_ip, inner_dst_ip, original_inner_src_mac,
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
    original_inner_src_mac = scenario['original_mac']
    rewrite_mac_1 = scenario['first_modified_mac']
    rewrite_mac_2 = scenario['second_modified_mac']
    rule_name_1 = "rule_vni_match_no_ip"
    rule_name_2 = "rule_ip_match_no_vni"

    try:
        create_additional_vnets(duthost=duthost, tunnel_name=setUp['vxlan_tunnel_name'])
        time.sleep(10)

        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        # Case 1: VNI matches but source IP does not match
        logger.info("=== Case 1: VNI matches but IP does not ===")
        setup_multi_vni_acl_rule(duthost, "202.1.1.100/32", str(VXLAN_VNI), rewrite_mac_1, rule_name_1, "1001")
        _send_and_verify_acl_counter_no_increment(
            ptfadapter, ptf_port_1, duthost,
            "202.1.1.200", "150.0.3.1", original_inner_src_mac,
            ACL_TABLE_NAME, rule_name_1
        )
        _send_and_verify_no_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "202.1.1.200", "150.0.3.1", original_inner_src_mac,
            ACL_TABLE_NAME, rule_name_1,
            rewrite_mac=rewrite_mac_1,
            test_description="VNI matches but IP does not"
        )
        logger.info("=== Case 1 completed successfully ===")

        # Case 2: Source IP matches but VNI does not match
        logger.info("=== Case 2: IP matches but VNI does not ===")
        setup_multi_vni_acl_rule(duthost, "202.2.2.100/32", str(VXLAN_VNI_3), rewrite_mac_2, rule_name_2, "1001")
        _send_and_verify_acl_counter_no_increment(
            ptfadapter, ptf_port_1, duthost,
            "202.2.2.100", "150.0.3.1", original_inner_src_mac,
            ACL_TABLE_NAME, rule_name_2
        )
        _send_and_verify_no_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            "202.2.2.100", "150.0.3.1", original_inner_src_mac,
            ACL_TABLE_NAME, rule_name_2,
            rewrite_mac=rewrite_mac_2,
            test_description="IP matches but VNI does not"
        )
        logger.info("=== Case 2 completed successfully ===")

        logger.info("=== All partial match test cases completed successfully ===")

    finally:
        try:
            remove_specific_acl_rule(duthost, rule_name_1)
            remove_specific_acl_rule(duthost, rule_name_2)
            remove_acl_table(duthost)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

def test_multiple_acl_rules_same_priority(setUp):
    """
    Test two ACL rules with different source IPs, same VNI, and different priorities.
    Priorities within an ACL table must be unique; using the same priority leads to
    non-deterministic rule matching. Validates that both rules are active and their
    counters increment independently.
    """
    # Extract test data from setUp fixture
    duthost = setUp['duthost']
    ptfadapter = setUp['ptfadapter']
    scenario = setUp['test_scenarios']['multi_vni_test']

    ptf_port_1 = setUp['ptf_port_1']
    ptf_port_2 = setUp['ptf_port_2']
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
    priority_1 = "1005"        # Priorities must be unique within an ACL table
    priority_2 = "1006"
    rule_name_1 = "rule_multi_1"
    rule_name_2 = "rule_multi_2"

    try:
        setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
        setup_acl_table(duthost, bind_ports)

        logger.info("Creating two ACL rules with different source IPs, same VNI, and unique priorities")
        logger.info(f"Rule 1: src_ip={test_src_ip_1}, VNI={test_vni}, priority={priority_1}, MAC={rewrite_mac_1}")
        logger.info(f"Rule 2: src_ip={test_src_ip_2}, VNI={test_vni}, priority={priority_2}, MAC={rewrite_mac_2}")

        setup_multi_vni_acl_rule(duthost, f"{test_src_ip_1}/32", test_vni, rewrite_mac_1, rule_name_1, priority_1)
        setup_multi_vni_acl_rule(duthost, f"{test_src_ip_2}/32", test_vni, rewrite_mac_2, rule_name_2, priority_2)

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
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
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

    logger.info("Applying ACL rule config:\n%s", json.dumps(acl_rule, indent=4))
    apply_config_chunk(duthost, acl_rule, f"acl_rule_{rule_name}")

    logger.info(f"Waiting for ACL rule {rule_name} to be applied...")
    time.sleep(15)  # Increased wait time to match working setup

    # Check CONFIG_DB for the rule
    logger.info(f"Checking if rule {rule_name} was added to CONFIG_DB...")
    rule_config_cmd = f'redis-cli -n 4 HGETALL "ACL_RULE|{ACL_TABLE_NAME}|{rule_name}"'
    rule_config_result = duthost.shell(rule_config_cmd)["stdout"]
    logger.info(f"ACL rule {rule_name} in CONFIG_DB:\n%s", rule_config_result)
    pytest_assert(rule_config_result.strip(), f"ACL rule {rule_name} not found in CONFIG_DB")

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
        pytest.fail(f"ACL rule for table {ACL_TABLE_NAME} is not showing as Active in 'show acl rule' output")

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
        pytest.fail(f"ACL rule {rule_name} is not active in STATE_DB")


def remove_specific_acl_rule(duthost, rule_name):
    """Remove specific ACL rule for cleanup"""
    try:
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|{rule_name}"
        duthost.shell(f'redis-cli -n 4 DEL "{rule_key}"', module_ignore_errors=True)
        logger.info(f"Removed ACL rule: {rule_name}")
    except Exception as e:
        logger.warning(f"Failed to remove ACL rule {rule_name}: {e}")
