import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

from ptf.mask import Mask
import ptf.packet as scapy


import ptf.testutils as testutils

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

IP_SOURCE = "192.168.0.3"
IPV6_SOURCE = "fc02:1000::3"

DST_IP_FORWARDED_ORIGINAL = "103.23.2.1"
DST_IPV6_FORWARDED_ORIGINAL = "103:23:2:1::1"

DST_IP_FORWARDED_REPLACEMENT = "103.23.2.2"
DST_IPV6_FORWARDED_REPLACEMENT = "103:23:2:2::1"

DST_IP_FORWARDED_scale_PREFIX = "103.23.4."
DST_IPV6_FORWARDED_scale_PREFIX = "103:23:4:"


DST_IP_BLOCKED = "103.23.3.1"
DST_IPV6_BLOCKED = "103:23:3:1::1"

MAX_RULE_PRIORITY = 9999
MAX_DROP_RULE_PRIORITY = 9000


@pytest.fixture(scope="module")
def setup(rand_selected_dut, tbinfo, vlan_name):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    list_ports = mg_facts["minigraph_vlans"][vlan_name]["members"]

    # Get all vlan ports
    vlan_ports = list(mg_facts['minigraph_vlans'].values())[0]['members']
    block_src_port = vlan_ports[0]
    unblocked_src_port = vlan_ports[1]
    scale_ports = vlan_ports[:]
    block_src_port_indice = mg_facts['minigraph_ptf_indices'][block_src_port]
    unblocked_src_port_indice = mg_facts['minigraph_ptf_indices'][unblocked_src_port]
    scale_ports_indices = [mg_facts ['minigraph_ptf_indices'][port_name] for port_name in scale_ports]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])

    # Generate destination IP's for scale test
    scale_dest_ips = {}
    for i in range(1,75):
        ipv4_rule_name = "FORWARD_RULE_" + str(i)
        ipv6_rule_name = "V6_FORWARD_RULE_" + str(i)
        ipv4_address = DST_IP_FORWARDED_scale_PREFIX + str(i)
        ipv6_address = DST_IPV6_FORWARDED_scale_PREFIX + str(i) + "::1"
        scale_dest_ips[ipv4_rule_name] = ipv4_address
        scale_dest_ips[ipv6_rule_name] = ipv6_address

    setup_information = {
        "blocked_src_port_name" : block_src_port,
        "blocked_src_port_indice" : block_src_port_indice,
        "unblocked_src_port_indice" : unblocked_src_port_indice,
        "scale_port_names" : scale_ports,
        "scale_port_indices" : scale_ports_indices,
        "scale_dest_ips" : scale_dest_ips,
        "dst_port_indices" : dst_port_indices,
        "router_mac" : router_mac,
        "bind_ports" : list_ports,
    }

    return setup_information

@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for acl config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def verify_expected_packet_behavior(exp_pkt, ptfadapter, setup, expect_drop):
    """Verify that a packet was either dropped or forwarded"""
    if expect_drop:
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["dst_port_indices"])
    else:
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=setup["dst_port_indices"],
                                        timeout=20)

def generate_packets(setup, dst_ip = DST_IP_FORWARDED_ORIGINAL, dst_ipv6 = DST_IPV6_FORWARDED_ORIGINAL):
    """Generate packets that match the destination IP of given ips.
    If no IP is given, default to our original forwarding ips"""

    packets = {}

    packets["IPV4"] = testutils.simple_tcp_packet(eth_dst=setup["router_mac"],
                                ip_src=IP_SOURCE,
                                ip_dst=dst_ip)

    packets["IPV6"] = testutils.simple_tcpv6_packet(eth_dst=setup["router_mac"],
                                ipv6_src=IPV6_SOURCE,
                                ipv6_dst=dst_ipv6)

    return packets

def build_exp_pkt(input_pkt):
    """
    Generate the expected packet for given packet
    """
    exp_pkt = Mask(input_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    return exp_pkt

def expect_acl_table_match_multiple_bindings(duthost, table_name, expected_first_line_content, expected_bindings):
    """Check if acl table show as expected
    Acl table with multiple bindings will show as such

    Table_Name  Table_Type  Ethernet4   Table_Description   ingress
                            Ethernet8
                            Ethernet12
                            Ethernet16

    So we must have separate checks for first line and bindings
    """

    cmds = "show acl table {}".format(table_name)

    output = duthost.show_and_parse(cmds)
    pytest_assert(len(output)>0, "'{}' is not a table on this device".format(table_name))

    first_line = output[0]
    pytest_assert(set(first_line.values()) == set(expected_first_line_content))
    table_bindings = [first_line["Binding"]]
    for i in range(len(output)):
        table_bindings.append(output[i]["Binding"])
    pytest_assert(set(table_bindings) == set(expected_bindings), "ACL Table bindings don't fully match")

def expect_acl_rule_match(duthost, rulename, expected_content_list):
    """Check if acl rule shows as expected"""

    cmds = "show acl rule DYNAMIC_ACL_TABLE {}".format(rulename)

    output = duthost.show_and_parse(cmds)
    pytest_assert(len(output) == 1, "'{}' is not a rule on this device".format(rulename))

    pytest_assert(set(output[0].values()) == set(expected_content_list), "ACL Rule details do not match!")

def expect_acl_rule_removed(duthost, rulename):
    """Check if ACL rule has been successfully removed"""

    cmds = "show acl rule DYNAMIC_ACL_TABLE {}".format(rulename)
    output = duthost.show_and_parse(cmds)

    removed = len(output) == 0

    pytest_assert(removed, "'{}' showed a rule, this following rule should have been removed".format(cmds))

#TODO - add json patch files to template file or the like.  How to do this?  Answer - use duthost.templtae method with setting environment variables.

@pytest.fixture(scope="module")
def dynamic_acl_create_table_type(rand_selected_dut):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE_TYPE",
            "value": {
                "DYNAMIC_ACL_TABLE_TYPE" : {
                "MATCHES": ["DST_IP","DST_IPV6","ETHER_TYPE","IN_PORTS"],
                "ACTIONS": ["PACKET_ACTION","COUNTER"],
                "BIND_POINTS": ["PORT"]
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)

    yield

    dynamic_acl_remove_table_type(rand_selected_dut)

@pytest.fixture(scope="module")
def dynamic_acl_create_table(rand_selected_dut, dynamic_acl_create_table_type, setup):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
            "value": {
                "policy_desc": "DYNAMIC_ACL_TABLE",
                "type": "DYNAMIC_ACL_TABLE_TYPE",
                "stage": "INGRESS",
                "ports": setup["bind_ports"]
            }
        }
    ]

    expected_bindings = setup["bind_ports"]
    expected_first_line = ["DYNAMIC_ACL_TABLE", "DYNAMIC_ACL_TABLE_TYPE", setup["bind_ports"][0], "DYNAMIC_ACL_TABLE", "ingress", "Active"]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)

        expect_acl_table_match_multiple_bindings(rand_selected_dut, "DYNAMIC_ACL_TABLE", expected_first_line, expected_bindings)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)

    yield

    dynamic_acl_remove_table(rand_selected_dut)

def dynamic_acl_create_duplicate_table(duthost, setup):
    """Create a duplicate ACL table type that should succeed"""
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
            "value": {
                "policy_desc": "DYNAMIC_ACL_TABLE",
                "type": "DYNAMIC_ACL_TABLE_TYPE",
                "stage": "INGRESS",
                "ports": setup["bind_ports"]
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_forward_rules(duthost):
    """Create forward ACL rules"""

    IPV4_SUBNET = DST_IP_FORWARDED_ORIGINAL + "/32"
    IPV6_SUBNET = DST_IPV6_FORWARDED_ORIGINAL + "/128"

    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "DYNAMIC_ACL_TABLE|RULE_1": {
                    "DST_IP": IPV4_SUBNET,
                    "PRIORITY": "9999",
                    "PACKET_ACTION": "FORWARD"
                },
                "DYNAMIC_ACL_TABLE|RULE_2": {
                    "DST_IPV6": IPV6_SUBNET,
                    "PRIORITY": "9998",
                    "PACKET_ACTION": "FORWARD"
                }
            }
        }
    ]

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", IPV4_SUBNET]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  IPV6_SUBNET]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_create_drop_rule(duthost, setup):
    """Create a drop rule in the format required when an ACL table has rules in it already"""

    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3",
            "value": {
                "PRIORITY": "9997",
                "PACKET_ACTION": "DROP",
                "IN_PORTS": setup["blocked_src_port_name"]
            }
        }
    ]

    expected_rule_content = ["DYNAMIC_ACL_TABLE", "RULE_3", "9997" , "DROP", "IN_PORTS:", setup["blocked_src_port_name"]]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_drop_rule_initial(duthost, setup):
    """Create a drop rule in the format required when an ACL table does not have any rules in it yet"""

    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "DYNAMIC_ACL_TABLE|RULE_3": {
                    "PRIORITY": "9997",
                    "PACKET_ACTION": "DROP",
                    "IN_PORTS": setup["blocked_src_port_name"],
                }
            }
        }
    ]

    expected_rule_content = ["DYNAMIC_ACL_TABLE", "RULE_3", "9997" , "DROP", "IN_PORTS:", setup["blocked_src_port_name"]]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_verify_packets(setup, ptfadapter, packets, packets_dropped, src_port = None):
    """Verify that the given packets are either dropped/forwarded correctly

    Args:
        packets: the packets that we are sending
        packets_dropped: whether or not we are expecting to drop or forward these packets
        src_port_blocked: whether or not to send it on the source port that we block in our drop rules"""
    if packets_dropped:
        action_type = "dropped"
    else:
        action_type = "forwarded"


    if src_port is None:
        src_port = setup["blocked_src_port_indice"]

    for rule, pkt in list(packets.items()):
        logger.info("Testing that {} packets are correctly {}".format(rule, action_type))
        exp_pkt = build_exp_pkt(pkt)
        # Send and verify packet
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port)
        verify_expected_packet_behavior(exp_pkt, ptfadapter, setup, expect_drop=packets_dropped)

def dynamic_acl_remove_drop_rule(duthost):
    """Remove the drop rule that we just created"""
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3",
            "value":{}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_3")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_drop_rule_initial(duthost):
    """Remove the drop rule that we just created.  Since this drop rule is the only ACL_RULE in the entire table, we must remove the entire table"""
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE",
            "value":{}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_3")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_nonexistant_rule(duthost):
    """Verify that replacing a non-existent rule fails"""
    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_10",
            "value": {
                "DST_IP": "103.23.2.2/32",
                "PRIORITY": "9999",
                "PACKET_ACTION": "FORWARD"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_rules(duthost):
    """
    Replace our forward rules on the ACL table"""

    REPLACEMENT_IPV4_SUBNET = DST_IP_FORWARDED_REPLACEMENT + "/32"
    REPLACEMENT_IPV6_SUBNET = DST_IPV6_FORWARDED_REPLACEMENT + "/128"

    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1",
            "value": {
                "DST_IP": REPLACEMENT_IPV4_SUBNET,
                "PRIORITY": "9999",
                "PACKET_ACTION": "FORWARD"
            }
        },
        {
        "op": "replace",
        "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_2",
            "value": {
                "DST_IPV6": REPLACEMENT_IPV6_SUBNET,
                "PRIORITY": "9998",
                "PACKET_ACTION": "FORWARD"
            }
        }
    ]

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", REPLACEMENT_IPV4_SUBNET]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  REPLACEMENT_IPV6_SUBNET]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_apply_forward_scale_rules(duthost, setup):
    """Apply a large amount of forward rules to the duthost"""

    priority = MAX_RULE_PRIORITY
    value_dict = {}
    expected_rule_contents = {}

    for rule_name, dest_ip in setup["scale_dest_ips"].items():
        if "V6" in rule_name:
            subnet = dest_ip + "/128"
            dst_type = "DST_IPV6"
        else:
            subnet = dest_ip + "/32"
            dst_type = "DST_IP"
        full_rule_name = "DYNAMIC_ACL_TABLE|"+ rule_name
        rule_vals = {
            dst_type: subnet,
            "PRIORITY" : str(priority),
            "PACKET_ACTION" : "FORWARD"
        }
        value_dict[full_rule_name] = rule_vals
        expected_content = ["DYNAMIC_ACL_TABLE", rule_name, str(priority), "FORWARD", dst_type + ":", subnet]
        expected_rule_contents[rule_name] = expected_content
        priority-=1


    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": value_dict
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for rule_name, expected_content in expected_rule_contents.items():
            expect_acl_rule_match(duthost, rule_name, expected_content)

    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_apply_drop_scale_rules(duthost, setup):
    """Apply a large amount of drop rules to the duthost"""

    priority = MAX_DROP_RULE_PRIORITY
    json_patch = []
    expected_rule_contents = {}
    rule_number = 1

    for port_name in setup["scale_port_names"]:
        rule_name = "DROP_RULE_" + str(rule_number)
        full_rule_name = "/ACL_RULE/DYNAMIC_ACL_TABLE|"+rule_name
        rule_vals = {
            "PRIORITY" : str(priority),
            "PACKET_ACTION" : "DROP",
            "IN_PORTS": port_name
        }
        patch = {
            "op": "add",
            "path": full_rule_name,
            "value": rule_vals
        }
        json_patch.append(patch)
        expected_content = ["DYNAMIC_ACL_TABLE", rule_name, str(priority), "DROP", "IN_PORTS:", port_name]
        expected_rule_contents[rule_name] = expected_content
        priority -= 1
        rule_number += 1

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for rule_name, expected_content in expected_rule_contents.items():
            expect_acl_rule_match(duthost, rule_name, expected_content)

    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_remove_forward_rules(duthost):
    """Remove our two forward rules from the acl table"""
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1",
            "value":{}
        },
        {
            "op": "remove",
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_2",
            "value": { }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_1")
        expect_acl_rule_removed(duthost, "RULE_2")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table(duthost):
    """Remove an ACL Table Type from the duthost"""
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
            "value": { }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_nonexistant_table(duthost):
    """Remove a nonexistent ACL Table from the duthost, verify it fails"""
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE_BAD",
            "value": { }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table_type(duthost):
    """Remove an ACL Table definition from the duthost
    As we only have one ACL Table definition on """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE_TYPE",
            "value": { }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


#TODO - add comments for each test case.  Enhance test cases according to bings suggestions


def test_gcu_acl_drop_rule_creation(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_create_drop_rule_initial(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED), packets_dropped = True)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets = generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped = False,
                               src_port = setup["unblocked_src_port_indice"])


def test_gcu_acl_drop_rule_removal(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_create_drop_rule_initial(rand_selected_dut, setup)
    dynamic_acl_remove_drop_rule_initial(rand_selected_dut)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED), packets_dropped = False)

def test_gcu_acl_forward_rule_priority_respected(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_drop_rule(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup), packets_dropped = False)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED), packets_dropped = True)

def test_gcu_acl_forward_rule_replacement(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_drop_rule(rand_selected_dut, setup)
    dynamic_acl_replace_rules(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets = generate_packets(setup, DST_IP_FORWARDED_REPLACEMENT, DST_IPV6_FORWARDED_REPLACEMENT),
                               packets_dropped = False)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup), packets_dropped = True)

def test_gcu_acl_forward_rule_removal(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_drop_rule(rand_selected_dut, setup)
    dynamic_acl_remove_forward_rules(rand_selected_dut)
    dynamic_acl_verify_packets(setup, ptfadapter, packets = generate_packets(setup), packets_dropped = True)

def test_gcu_acl_scale_rules(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    dynamic_acl_apply_forward_scale_rules(rand_selected_dut, setup)
    dynamic_acl_apply_drop_scale_rules(rand_selected_dut, setup)

    #select one of our src ports blocked by these scale rules
    blocked_scale_port = setup["scale_port_indices"][0]

    #select ipv4 and ipv6 destination ips from our forwarding rules
    v4_dest = setup["scale_dest_ips"]["FORWARD_RULE_10"]
    v6_dest = setup["scale_dest_ips"]["V6_FORWARD_RULE_10"]

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               generate_packets(setup, v4_dest, v6_dest),
                               packets_dropped = False,
                               src_port = blocked_scale_port)
    dynamic_acl_verify_packets(setup, ptfadapter, generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED), packets_dropped = True, src_port = blocked_scale_port)


def test_gcu_acl_nonexistent_rule_replacement(rand_selected_dut):
    dynamic_acl_replace_nonexistant_rule(rand_selected_dut)

def test_gcu_acl_nonexistent_table_removal(rand_selected_dut):
    dynamic_acl_remove_nonexistant_table(rand_selected_dut)
