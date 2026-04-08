import ipaddress
import logging
import random
import pytest
import os
import time
import json

from ptf.mask import Mask
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses  # noqa: F401
import ptf.testutils as testutils
from tests.common.helpers.constants import PTF_TIMEOUT
from tests.common.helpers.assertions import pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import get_upstream_neigh_type, get_neighbor_ptf_port_list, \
    get_neighbor_port_list, is_ipv6_only_topology,  wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "m0", "mx", "m1"),
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

LOG_ERROR_INSUFFICIENT_RESOURCES = ".*SAI_STATUS_INSUFFICIENT_RESOURCES.*"

ACL_JSON_FILE_SRC = "acl/null_route/acl.json"
ACL_JSON_FILE_DEST = "/host/" + os.path.basename(ACL_JSON_FILE_SRC)

ACL_TABLE_NAME_V4 = "NULL_ROUTE_ACL_TABLE_V4"
ACL_TABLE_NAME_V6 = "NULL_ROUTE_ACL_TABLE_V6"

NULL_ROUTE_HELPER = "null_route_helper"

FORWARD = "FORWARD"
DROP = "DROP"
SHOW_ACL_RULE_CMD = "show acl rule {}"
ACTIVE_RULE_STATUS = "Active"
UNBLOCK_RULE_TYPE = "UNBLOCK"
BLOCK_RULE_TYPE = "BLOCK"

TEST_DATA = [
    # src_ip, action, expected_result
    ("1.2.3.4", "", FORWARD),  # Should be forwared in default
    ("fc03:1001::1", "", FORWARD),  # Should be forwared in default

    ("1.2.3.4", "block {} 1.2.3.4"
     .format(ACL_TABLE_NAME_V4), DROP),  # Verify block ipv4 without prefix len
    ("1.2.3.4", "unblock {} 1.2.3.4/32"
     .format(ACL_TABLE_NAME_V4), FORWARD),  # Verify unblock ipv4 with prefix len
    ("1.2.3.4", "block {} 1.2.3.4/32"
     .format(ACL_TABLE_NAME_V4), DROP),  # Verify block ipv4 with prefix len
    ("1.2.3.4", "block {} 1.2.3.4/32"
     .format(ACL_TABLE_NAME_V4), DROP),  # Verify double-block dosen't cause issue
    ("1.2.3.4", "unblock {} 1.2.3.4/32"
     .format(ACL_TABLE_NAME_V4), FORWARD),  # Verify unblock ipv4 with prefix len
    ("1.2.3.4", "unblock {} 1.2.3.4/32"
     .format(ACL_TABLE_NAME_V4), FORWARD),  # Verify double-unblock doesn't cause issue

    ("fc03:1000::1", "block {} fc03:1000::1"
     .format(ACL_TABLE_NAME_V6), DROP),  # Verify block ipv6 without prefix len
    ("fc03:1000::1", "unblock {} fc03:1000::1/128".
     format(ACL_TABLE_NAME_V6), FORWARD),  # Verify unblock ipv6 with prefix len
    ("fc03:1000::1", "block {} fc03:1000::1/128"
     .format(ACL_TABLE_NAME_V6), DROP),  # Verify block ipv6 with prefix len
    ("fc03:1000::1", "block {} fc03:1000::1/128"
     .format(ACL_TABLE_NAME_V6), DROP),  # Verify double-block dosen't cause issue
    ("fc03:1000::1", "unblock {} fc03:1000::1/128"
     .format(ACL_TABLE_NAME_V6), FORWARD),  # Verify unblock ipv4 with prefix len
    ("fc03:1000::1", "unblock {} fc03:1000::1/128"
     .format(ACL_TABLE_NAME_V6), FORWARD),  # Verify double-unblock doesn't cause issue
]


@pytest.fixture(scope="module", autouse=True)
def remove_data_everflow_acl_table(rand_selected_dut, duthosts):
    """
    Remove DATAACL and EVERFLOWV6 to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    table_names = {'DATAACL': 'False', 'EVERFLOWV6': 'False'}

    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table")['stdout_lines']
        for table_name in table_names.keys():
            for line in lines:
                if table_name in line:
                    table_names[table_name] = True
                    logger.info("Removing ACL table {}".format(table_name))
                    rand_selected_dut.shell(cmd="config acl remove table {}".format(table_name))

    if True not in table_names.values():
        yield
        return

    yield
    config_db_json = "/etc/sonic/config_db.json"
    output = rand_selected_dut.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
    entry_json = json.loads(output)
    for table_name in table_names.keys():
        if table_names[table_name]:
            entry = entry_json[table_name]
            cmd_create_table = "config acl add table {} {} -p {} -s {}"\
                .format(table_name, entry['type'], ",".join(entry['ports']), entry['stage'])
            logger.info("Restoring ACL table {}".format(table_name))
            rand_selected_dut.shell(cmd_create_table)


def remove_acl_table(duthost):
    """
    A helper function to remove ACL table for testing
    """
    cmds = [
        "config acl remove table {}".format(ACL_TABLE_NAME_V4),
        "config acl remove table {}".format(ACL_TABLE_NAME_V6)
    ]
    logger.info("Removing ACL table for testing")
    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module")
def create_acl_table(rand_selected_dut, tbinfo):
    """
    Create two ACL tables on DUT for testing.
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]
    if topo == "mx" or len(mg_facts["minigraph_portchannels"]) == 0:
        upstream_neigh_type = get_upstream_neigh_type(tbinfo)
        neighbor_ports = get_neighbor_port_list(rand_selected_dut, upstream_neigh_type)
        ports = ",".join(neighbor_ports)
    else:
        # Get the list of LAGs
        ports = ",".join(list(mg_facts["minigraph_portchannels"].keys()))
    cmds = [
        "config acl add table {} L3 -p {}".format(ACL_TABLE_NAME_V4, ports),
        "config acl add table {} L3V6 -p {}".format(ACL_TABLE_NAME_V6, ports)
    ]
    logger.info("Creating ACL table for testing")
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="null_route_helper")
    loganalyzer.match_regex = [LOG_ERROR_INSUFFICIENT_RESOURCES]

    # Skip test case if ACL table created failed due to insufficient resources
    try:
        with loganalyzer:
            rand_selected_dut.shell_cmds(cmds=cmds)
    except LogAnalyzerError:
        skip_msg = "ACL table creation failed due to insufficient resources, test case will be skipped"
        logger.error(skip_msg)
        remove_acl_table(rand_selected_dut)
        pytest.skip(skip_msg)

    yield

    remove_acl_table(rand_selected_dut)


@pytest.fixture(scope="module")
def apply_pre_defined_rules(rand_selected_dut, create_acl_table):
    """
    This is to apply some ACL rules as production does
    """
    rand_selected_dut.copy(src=ACL_JSON_FILE_SRC, dest=ACL_JSON_FILE_DEST)
    rand_selected_dut.shell("acl-loader update full " + ACL_JSON_FILE_DEST)
    # Wait 5 seconds for ACL rule creation
    time.sleep(5)
    yield
    # Clear ACL rules
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB keys "ACL_RULE|{}*" | xargs sonic-db-cli CONFIG_DB del'
                            .format(ACL_TABLE_NAME_V4))
    rand_selected_dut.shell('sonic-db-cli CONFIG_DB keys "ACL_RULE|{}*" | xargs sonic-db-cli CONFIG_DB del'
                            .format(ACL_TABLE_NAME_V6))


@pytest.fixture(scope="module")
def setup_ptf(rand_selected_dut, ptfhost, tbinfo):
    """
    Add ipv4 and ipv6 address to a port on ptf.
    """
    dst_ports = {}
    vlan_name = ""
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    vlans = {}
    config_facts = rand_selected_dut.config_facts(host=rand_selected_dut.hostname, source="running")['ansible_facts']
    for vlan_name, vlan_info in config_facts['VLAN_INTERFACE'].items():
        for vlan_ip_address in vlan_info.keys():
            try:
                if vlan_info[vlan_ip_address].get("secondary"):
                    continue
                ip_address = vlan_ip_address.split("/")[0]
                ip_ver = ipaddress.ip_network(ip_address, False).version
                if vlan_name not in vlans:
                    vlans[vlan_name] = {}
                ip_with_prefix = str(ipaddress.ip_address(ip_address) + 1) + '/' + vlan_ip_address.split("/")[1]
                vlans[vlan_name][ip_ver] = ip_with_prefix
            except Exception:
                continue
    for key, value in vlans.items():
        if len(value.keys()) in [1, 2]:
            vlan_name = key
            for ip_ver, value in value.items():
                dst_ports[ip_ver] = value
            break

    pytest_require(vlan_name != "", "Cannot get correct vlan")
    vlan_port = mg_facts['minigraph_vlans'][vlan_name]['members'][0]
    dst_ports['port'] = mg_facts['minigraph_ptf_indices'][vlan_port]

    logger.info("Setting up ptf for testing")
    if not is_ipv6_only_topology(tbinfo):
        ptfhost.shell("ifconfig eth{} {}".format(dst_ports['port'], dst_ports[4]))
    ptfhost.shell("ifconfig eth{} inet6 add {}".format(dst_ports['port'], dst_ports[6]))

    yield dst_ports
    if not is_ipv6_only_topology(tbinfo):
        ptfhost.shell("ifconfig eth{} 0.0.0.0".format(dst_ports['port']))
    ptfhost.shell("ifconfig eth{} inet6 del {}".format(dst_ports['port'], dst_ports[6]))


def generate_packet(src_ip, dst_ip, dst_mac):
    """
    Build ipv4 and ipv6 packets/expected_packets for testing.
    """
    if ipaddress.ip_network(src_ip.encode().decode(), False).version == 4:
        pkt = testutils.simple_ip_packet(eth_dst=dst_mac, ip_src=src_ip, ip_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        pkt = testutils.simple_tcpv6_packet(eth_dst=dst_mac, ipv6_src=src_ip, ipv6_dst=dst_ip)
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    return pkt, exp_pkt


def send_and_verify_packet(ptfadapter, pkt, exp_pkt, tx_port, rx_port, expected_action):     # noqa: F811
    """
    Send packet with ptfadapter and verify if packet is forwarded or dropped as expected.
    """
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=pkt, port_id=tx_port)
    if expected_action == FORWARD:
        testutils.verify_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=PTF_TIMEOUT)
    else:
        testutils.verify_no_packet(ptfadapter, pkt=exp_pkt, port_id=rx_port, timeout=5)


def parse_acl_rule(rule):
    rule_tested_parts = rule.split()
    tested_rule_type = rule_tested_parts[0].upper()
    tested_acl_table = rule_tested_parts[1]
    tested_ip = rule_tested_parts[-1]
    return tested_rule_type, tested_acl_table, tested_ip


def verify_test_data_rule_inserted_to_acl_table(duthost, rule_tested):
    is_rule_inserted_successfully = False
    tested_rule_type, tested_acl_table, tested_ip = parse_acl_rule(rule_tested)
    matching_acl_rules_for_tested_ip = (
        duthost.shell(f'{SHOW_ACL_RULE_CMD.format(tested_acl_table)} | grep -E {tested_ip}',
                      module_ignore_errors=True)['stdout_lines']
    )
    logger.info(f"Verifying that the tested rule: {rule_tested}, was applied in ACL table")
    if not matching_acl_rules_for_tested_ip and tested_rule_type == UNBLOCK_RULE_TYPE:
        logger.info(
            f"[{UNBLOCK_RULE_TYPE} rule was applied successfully] "
            f"Expected: No rule for {tested_ip} | "
            f"Actual: No rule found (traffic allowed by default)"
        )
        is_rule_inserted_successfully = True

    elif matching_acl_rules_for_tested_ip and tested_rule_type == BLOCK_RULE_TYPE:
        logger.info(
            f"[{BLOCK_RULE_TYPE} rule was applied successfully] "
            f"Expected: Rule for {tested_ip} to be found and active | "
            f"Actual: {matching_acl_rules_for_tested_ip}"
        )
        for rule in matching_acl_rules_for_tested_ip:
            rule_split = rule.split()
            if len(rule_split) < 2:
                logger.debug(f"Skipping incomplete ACL rule line: {rule}")
                continue
            matched_rule_from_table = rule_split[1]
            is_rule_active = rule_split[-1] == ACTIVE_RULE_STATUS
            is_rule_added_correctly = (
                tested_ip in matched_rule_from_table and
                tested_rule_type in matched_rule_from_table and
                is_rule_active
            )
            if is_rule_added_correctly:
                is_rule_inserted_successfully = True
    if not is_rule_inserted_successfully:
        logger.info(f"Tested rule: {rule_tested} wasn't applied in ACL table")
        acl_table = duthost.shell(SHOW_ACL_RULE_CMD.format(tested_acl_table), module_ignore_errors=True)['stdout']
        logger.info(f"ACL table: {acl_table}")
    return is_rule_inserted_successfully


def test_null_route_helper(rand_selected_dut, tbinfo, ptfadapter,
                           apply_pre_defined_rules, setup_ptf):  # noqa: F811
    """
    Test case to verify script null_route_helper.
    Some packets are generated as defined in TEST_DATA and sent to DUT,
    and verify if packet is forwarded or dropped as expected.
    """
    ptf_port_info = setup_ptf
    rx_port = ptf_port_info['port']
    router_mac = rand_selected_dut.facts["router_mac"]
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]
    if topo == "mx" or len(mg_facts["minigraph_portchannels"]) == 0:
        upstream_neigh_type = get_upstream_neigh_type(tbinfo)
        ptf_interfaces = get_neighbor_ptf_port_list(rand_selected_dut, upstream_neigh_type, tbinfo)
    else:
        portchannel_members = []
        for _, v in list(mg_facts["minigraph_portchannels"].items()):
            portchannel_members += v['members']

        ptf_interfaces = []
        for port in portchannel_members:
            ptf_interfaces.append(mg_facts['minigraph_ptf_indices'][port])

    # Run testing as defined in TEST_DATA
    for test_item in TEST_DATA:
        src_ip = test_item[0]
        action = test_item[1]
        expected_result = test_item[2]
        ip_ver = ipaddress.ip_network(src_ip.encode().decode(), False).version
        if ip_ver == 4 and is_ipv6_only_topology(tbinfo):
            continue
        logger.info("Testing with src_ip = {} action = {} expected_result = {}"
                    .format(src_ip, action, expected_result))
        pkt, exp_pkt = generate_packet(src_ip, ptf_port_info[ip_ver].split("/")[0], router_mac)
        if action != "":
            rand_selected_dut.shell(NULL_ROUTE_HELPER + " " + action)
            wait_until(5, 1, 0, verify_test_data_rule_inserted_to_acl_table, rand_selected_dut, action)

        send_and_verify_packet(ptfadapter, pkt, exp_pkt, random.choice(ptf_interfaces),
                               rx_port, expected_result)
