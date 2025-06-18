"""
Tests Acl to modify inner src mac to ENI mac in SONiC.
"""

import os
import time
import logging
import pytest
import json
import tempfile
from ptf import mask
from scapy.all import Ether
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from ptf import testutils

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),  # Only run on T0 testbed
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

DEFAULT_VNI = 1000
ACL_COUNTERS_UPDATE_INTERVAL = 10
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"
ACL_RULES_FILE = 'acl_config.json'
TMP_DIR = '/tmp'

ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TABLE_TYPE = "INNER_SRC_MAC_REWRITE_TYPE"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"


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


@pytest.fixture(scope='module')
def get_portchannel_for_eth_ports(rand_selected_dut, tbinfo):
    """
    Returns a list of tuples: (eth_port, portchannel_name, ptf_port)
    Selects the first two Ethernet ports and their associated PortChannels (if any).
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    eth_to_portchannel = {}

    for pc_name, pc_data in mg_facts["minigraph_portchannels"].items():
        for member in pc_data["members"]:
            eth_to_portchannel[member] = pc_name

    # Pick two distinct Ethernet ports with ptf indices
    eth_ports = list(mg_facts["minigraph_ptf_indices"].keys())
    assert len(eth_ports) >= 3, "Need at least three Ethernet ports"

    selected_ports = eth_ports[:3]  # Use the first three ports
    result = []

    logger.info("Selected ports and their mappings:")
    for eth_port in selected_ports:
        ptf_port = mg_facts["minigraph_ptf_indices"][eth_port]
        pc_name = eth_to_portchannel.get(eth_port)
        logger.info("  DUT port: %s | PortChannel: %s | PTF port: %s", eth_port, pc_name, ptf_port)
        result.append((eth_port, pc_name, ptf_port))

    return result


@pytest.fixture(scope='module')
def prepare_test_ports(get_portchannel_for_eth_ports):
    """
    Returns: (ptf_port_1, ptf_port_2, test_port_1, test_port_2)
    Each test_port is either a PortChannel or Ethernet port, depending on availability.
    """
    ports = get_portchannel_for_eth_ports
    assert len(ports) == 3, "Expected exactly three test ports"

    eth1, pc1, ptf1 = ports[1]
    eth2, pc2, ptf2 = ports[2]

    test_port_1 = pc1 if pc1 else eth1
    test_port_2 = pc2 if pc2 else eth2

    logger.info("Selected test ports:")
    logger.info("  ptf_port_1: %s, dut_port_1: %s (PC: %s)", ptf1, eth1, pc1)
    logger.info("  ptf_port_2: %s, dut_port_2: %s (PC: %s)", ptf2, eth2, pc2)
    logger.info("  Using test_port_1: %s, test_port_2: %s", test_port_1, test_port_2)

    return ptf1, ptf2, test_port_1, test_port_2


@pytest.fixture(scope='module')
def get_all_bindable_ports(rand_selected_dut, tbinfo):
    """
    Returns a list of all Ethernet ports and PortChannels that can be bound to the ACL table.
    Avoids duplicate binding by preferring PortChannels over member Ethernet ports.
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    eth_ports = set(
        iface["name"] for iface in mg_facts["minigraph_interfaces"]
        if iface["name"].startswith("Ethernet")
    )

    bind_ports = []

    for pc_name, pc_data in mg_facts.get("minigraph_portchannels", {}).items():
        members = pc_data.get("members", [])
        bind_ports.append(pc_name)
        eth_ports -= set(members)  # Remove members that are already in PortChannels

    bind_ports.extend(sorted(eth_ports))  # Add remaining standalone Ethernet ports
    return bind_ports


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
    time.sleep(10)  # Let the system stabilize


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

    time.sleep(10)  # Allow time for removal to take effect

    logger.info(f"Verifying ACL table {ACL_TABLE_NAME} was removed from STATE_DB")
    db_cmd = f"redis-cli -n 6 KEYS 'ACL_TABLE_TABLE:{ACL_TABLE_NAME}'"
    keys_output = duthost.shell(db_cmd)["stdout_lines"]

    if any(keys_output):
        logger.error(f"ACL table {ACL_TABLE_NAME} still present in STATE_DB: {keys_output}")
        pytest.fail(f"ACL table {ACL_TABLE_NAME} was not removed from STATE_DB")
    else:
        logger.info(f"ACL table {ACL_TABLE_NAME} successfully removed from STATE_DB")


def add_single_acl_rule(duthost, table_name, rule_name, inner_src_prefix, vni_id, modified_mac):
    """
    Adds a single ACL rule using JSON-based acl-loader approach.
    The rule rewrites the inner source MAC based on inner source IP and VNI.
    """
    # Build the ACL config in the required format
    acl_config = {
        "ACL_RULE": {
            f"{table_name}|{rule_name}": {
                "INNER_SRC_IP": inner_src_prefix,
                "TUNNEL_VNI": str(vni_id),
                "INNER_SRC_MAC_REWRITE_ACTION": modified_mac,
                "PRIORITY": "100"
            }
        }
    }

    # Write to temporary file
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmpfile:
        json.dump(acl_config, tmpfile, indent=4)
        tmpfile_path = tmpfile.name

    dest_path = f"/tmp/{rule_name}_acl.json"

    logger.info(f"Adding ACL rule {rule_name} with IP {inner_src_prefix} and VNI {vni_id} via acl-loader")

    try:
        # Copy the JSON to the DUT and load it
        duthost.copy(src=tmpfile_path, dest=dest_path)
        duthost.shell(f"acl-loader update full {dest_path}")
        time.sleep(1)
    finally:
        # Clean up both temp and DUT files
        os.remove(tmpfile_path)
        duthost.shell(f"rm -f {dest_path}")


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

    # Check each line for table status
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


def create_vxlan_tunnel(duthost, tunnel_name, src_ip):
    """
    Configure VXLAN_TUNNEL in CONFIG_DB using src_ip (typically Loopback0 IP).

    Args:
        duthost: DUT host object
        tunnel_name: Name of the VXLAN tunnel (e.g. 'vtep_v4')
        src_ip: Source IP (e.g. from Loopback0)
    """
    config = {
        "VXLAN_TUNNEL": {
            tunnel_name: {
                "src_ip": src_ip
            }
        }
    }

    config_json = json.dumps(config, indent=4)
    logger.info("Applying VXLAN_TUNNEL config: %s", config_json)
    apply_config_in_dut(duthost, config_json, f"vxlan_tunnel_{tunnel_name}")


def create_two_vnets(duthost, tunnel_name):
    """
    Program exactly two VNET entries with fixed VNIs: 799999 and 799998.

    Args:
        duthost: DUT host object
        tunnel_name: VXLAN tunnel name (must already exist)
    """
    config = {
        "VNET": {
            "Vnet1": {
                "vxlan_tunnel": tunnel_name,
                "vni": "799999",
                "peer_list": "",
                "advertise_prefix": "false"
            },
            "Vnet2": {
                "vxlan_tunnel": tunnel_name,
                "vni": "799998",
                "peer_list": "",
                "advertise_prefix": "false"
            }
        }
    }

    config_json = json.dumps(config, indent=4)
    logger.info("Applying VNET config:\n%s", config_json)
    apply_config_in_dut(duthost, config_json, f"vnets_{tunnel_name}")


@pytest.mark.parametrize("inner_src_ips, inner_src_prefix", [
    (["192.168.0.1"], "192.168.0.1/32"),               # Single IP test
    (["192.168.0.{}".format(i) for i in range(1, 5)], "192.168.0.0/24")  # Range test
])
def test_modify_inner_src_mac_egress(duthost, ptfadapter, prepare_test_ports, get_all_bindable_ports,
                                     inner_src_ips, inner_src_prefix, tbinfo):
    # Extract Loopback0 IP from minigraph
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    loopback0_ips = mg_facts["minigraph_lo_interfaces"]

    loopback_src_ip = None
    for intf in loopback0_ips:
        if intf["name"] == "Loopback0":
            loopback_src_ip = intf["addr"]
            break

    # Constants
    inner_dst_ip = "192.168.0.100"
    vni_id = "799999"
    vnet_1 = "Vnet1"
    vnet_2 = "Vnet2"
    vxlan_tunnel_name = "vtep_v4"

    original_inner_src_mac = "00:66:77:88:99:aa"
    first_modified_mac = "00:11:22:33:44:55"
    second_modified_mac = "00:aa:bb:cc:dd:ee"
    outer_src_mac = "00:11:22:33:44:66"
    outer_dst_mac = duthost.facts['router_mac']
    outer_dst_ip = "20.1.1.1"
    RULE_NAME = "rule_1"
    table_name = ACL_TABLE_NAME
    ptf_port_1, ptf_port_2, dut_port_1, dut_port_2 = prepare_test_ports

    # === Program VXLAN_TUNNEL and VNET config ===
    logger.info("Configuring VXLAN_TUNNEL and VNETs with Loopback IP")
    create_vxlan_tunnel(duthost, vxlan_tunnel_name, loopback_src_ip)
    create_two_vnets(duthost, vxlan_tunnel_name)
    time.sleep(10)

    # Setup ACL table and rule
    setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
    setup_acl_table(duthost, get_all_bindable_ports)
    setup_acl_rules(duthost, inner_src_prefix, vni_id, first_modified_mac)

    for idx, src_ip in enumerate(inner_src_ips):
        logger.info("Step 1: Verifying rewrite with first modified MAC: %s", first_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, src_ip, inner_dst_ip, original_inner_src_mac,
            first_modified_mac, vni_id, outer_src_mac, outer_dst_mac, loopback_src_ip, outer_dst_ip, table_name, RULE_NAME
        )

        # Modify rule after sending the first packet
        if idx == 0:
            logger.info("Step 2: Replacing ACL rule to use new MAC: %s", second_modified_mac)
            remove_acl_rules(duthost)
            setup_acl_rules(duthost, inner_src_prefix, vni_id, second_modified_mac)

    for src_ip in inner_src_ips:
        logger.info("Step 3: Verifying rewrite with second modified MAC: %s", second_modified_mac)
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost, src_ip, inner_dst_ip, original_inner_src_mac,
            second_modified_mac, vni_id, outer_src_mac, outer_dst_mac, loopback_src_ip, outer_dst_ip, table_name, RULE_NAME
        )

    # Cleanup
    remove_acl_rules(duthost)
    remove_acl_table(duthost)


def _send_and_verify_mac_rewrite(ptfadapter, ptf_port_1, ptf_port_2, duthost,
                                 src_ip, dst_ip, orig_src_mac, expected_inner_mac,
                                 vni_id, outer_src_mac, outer_dst_mac, outer_src_ip, outer_dst_ip,
                                 table_name, rule_name):
    expected_inner_pkt = testutils.simple_udp_packet(
        eth_dst=duthost.facts['router_mac'],
        eth_src=expected_inner_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_id=0,
        ip_ihl=5,
        udp_sport=1234,
        udp_dport=4321,
        ip_ttl=121
    )

    expected_pkt = testutils.simple_vxlan_packet(
        eth_dst=outer_dst_mac,
        eth_src=outer_src_mac,
        ip_src=outer_src_ip,
        ip_dst=outer_dst_ip,
        udp_sport=1234,
        udp_dport=4789,
        vxlan_vni=int(vni_id),
        inner_frame=expected_inner_pkt
    )

    masked_expected_pkt = mask.Mask(expected_pkt)
    masked_expected_pkt.set_do_not_care_scapy(Ether, 'src')
    masked_expected_pkt.set_do_not_care_scapy(Ether, 'dst')

    input_pkt = testutils.simple_udp_packet(
        eth_dst=duthost.facts['router_mac'],
        eth_src=orig_src_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_id=0,
        ip_ihl=5,
        udp_sport=1234,
        udp_dport=4321,
        ip_ttl=121
    )

    count_before = get_acl_counter(duthost, table_name, rule_name, timeout=0)
    testutils.send(ptfadapter, ptf_port_1, input_pkt)
    testutils.verify_packet(ptfadapter, masked_expected_pkt, ptf_port_2)
    count_after = get_acl_counter(duthost, table_name, rule_name)

    logger.info("ACL counter for IP %s: before=%s, after=%s", src_ip, count_before, count_after)
    pytest_assert(count_after >= count_before + 1,
                  f"ACL counter did not increment for {src_ip}. before={count_before}, after={count_after}")


def test_multiple_acl_rules_inner_src_mac_rewrite(duthost, ptfadapter, prepare_test_ports, get_all_bindable_ports):
    """
    Test multiple ACL rules with different inner_src_ip prefixes rewriting to different inner_src_mac values.
    """
    RULES = [
        {
            "inner_src_prefix": "192.168.10.0/24",
            "match_ip": "192.168.10.1",
            "modified_mac": "00:aa:bb:cc:dd:01"
        },
        {
            "inner_src_prefix": "192.168.20.0/24",
            "match_ip": "192.168.20.1",
            "modified_mac": "00:aa:bb:cc:dd:02"
        },
        {
            "inner_src_prefix": "192.168.30.0/24",
            "match_ip": "192.168.30.1",
            "modified_mac": "00:aa:bb:cc:dd:03"
        }
    ]

    inner_dst_ip = "192.168.0.100"
    original_inner_src_mac = "00:66:77:88:99:aa"
    vni_id = 5000
    outer_src_mac = "00:11:22:33:44:66"
    outer_dst_mac = duthost.facts['router_mac']
    outer_src_ip = "10.1.1.1"
    outer_dst_ip = "20.1.1.1"
    table_name = ACL_TABLE_NAME
    ptf_port_1, ptf_port_2, dut_port_1, dut_port_2 = prepare_test_ports

    # Setup ACL table
    setup_acl_table_type(duthost, acl_type_name=ACL_TABLE_TYPE)
    setup_acl_table(duthost, get_all_bindable_ports)

    # Add multiple rules
    for idx, rule in enumerate(RULES):
        rule_name = f"rule_{idx+1}"
        add_single_acl_rule(duthost, table_name, rule_name, rule["inner_src_prefix"], vni_id, rule["modified_mac"])

    # Send and verify for each rule
    for idx, rule in enumerate(RULES):
        rule_name = f"rule_{idx+1}"
        _send_and_verify_mac_rewrite(
            ptfadapter, ptf_port_1, ptf_port_2, duthost,
            rule["match_ip"], inner_dst_ip, original_inner_src_mac,
            rule["modified_mac"], vni_id,
            outer_src_mac, outer_dst_mac, outer_src_ip, outer_dst_ip,
            table_name, rule_name
        )

    # Cleanup
    remove_acl_rules(duthost)
    remove_acl_table(duthost)

