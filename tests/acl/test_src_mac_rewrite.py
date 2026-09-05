"""
Tests ACL to modify inner source MAC in VXLAN packets in SONiC.

This test suite validates the INNER_SRC_MAC_REWRITE_ACTION functionality
for ACL rules that can rewrite the inner source MAC address of VXLAN-encapsulated packets.
"""

import os
import logging
import pytest
import json
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
    base_mac = "00:aa:bb:cc:dd"
    last_octet = f"{(index % 256):02x}"
    return f"{base_mac}:{last_octet}"


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

    if not result:
        pytest.fail("Failed to retrieve ACL counter for {}|{}".format(table_name, rule_name))

    for rule in result:
        if table_name == rule.get('table name') and rule_name == rule.get('rule name'):
            pkt_count = rule.get('packets count', '0')
            if pkt_count == 'N/A':
                return 0
            try:
                return int(pkt_count)
            except ValueError:
                logger.warning(
                    f"ACL counter for {table_name}|{rule_name} has unexpected value: '{pkt_count}', returning 0"
                )
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
                                 vni=VXLAN_VNI, test_description=""):
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
    stay flat for a partial/no-match case.
    """
    router_mac = duthost.facts["router_mac"]
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

    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    logger.info("=== MAC Rewrite Test (expect_rewrite=%s, rule=%s, %s) ===",
                expect_rewrite, rule_name, test_description)
    logger.info("Sending pkt from PTF port %s (inner src MAC=%s); rewrite MAC=%s on PTF port(s) %s",
                ptf_port_1, orig_src_mac, rewrite_mac, ptf_ports)

    # Inject via testutils.send (not send_packet): the ptfadapter overrides send/dp_poll to rewrite
    # the L4 payload to a per-module pattern on BOTH the injected packet and the expected mask, so
    # they stay symmetric. send_packet skips that rewrite and would mismatch the payload here.
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port_1, input_pkt, 1)

    # `masked` already encodes the expected inner src MAC for this case (rewrite MAC when the rule
    # fires, router_mac when it must not), so the same positive verify confirms e2e whether the
    # rewrite happened. Only the ACL-counter expectation differs between the two cases.
    try:
        testutils.verify_packet_any_port(ptfadapter, masked, ptf_ports, timeout=10)
    except Exception:
        # Dump VNET/underlay/ACL state to distinguish a datapath problem (no encap at all)
        # from a packet-content mismatch, then fail.
        _log_vxlan_datapath_state(duthost, src_ip, dst_ip, rule_name)
        raise

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
            test_description="VNI matches but IP does not"
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
            test_description="IP matches but VNI does not"
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
            ACL_TABLE_NAME, rule_name_1
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
            ACL_TABLE_NAME, rule_name_2
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
