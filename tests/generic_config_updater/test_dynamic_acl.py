import logging
import pytest
import os
import json

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

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
TMP_DIR = '/tmp'

CREATE_CUSTOM_TABLE_TYPE_FILE = "create_custom_table_type.json"
CREATE_CUSTOM_TABLE_TEMPLATE = "create_custom_table.j2"
CREATE_FORWARD_RULES_TEMPLATE = "create_forward_rules.j2"
CREATE_INITIAL_DROP_RULE_TEMPLATE = "create_initial_drop_rule.j2"
CREATE_SECONDARY_DROP_RULE_TEMPLATE = "create_secondary_drop_rule.j2"
CREATE_THREE_DROP_RULES_TEMPLATE = "create_three_drop_rules.j2"
REPLACE_RULES_TEMPLATE = "replace_rules.j2"
REPLACE_NONEXISTENT_RULE_FILE = "replace_nonexistent_rule.json"
REMOVE_THIRD_DROP_RULE_FILE = "remove_third_drop_rule.json"
REMOVE_IPV4_FORWARD_RULE_FILE = "remove_ipv4_forward_rule.json"
REMOVE_IPV6_FORWARD_RULE_FILE = "remove_ipv6_forward_rule.json"
REMOVE_TABLE_FILE = "remove_table.json"
REMOVE_NONEXISTENT_TABLE_FILE = "remove_nonexistent_table.json"
REMOVE_TABLE_TYPE_FILE = "remove_table_type.json"

IP_SOURCE = "192.168.0.3"
IPV6_SOURCE = "fc02:1000::3"

DST_IP_FORWARDED_ORIGINAL = "103.23.2.1"
DST_IPV6_FORWARDED_ORIGINAL = "103:23:2:1::1"

DST_IP_FORWARDED_REPLACEMENT = "103.23.2.2"
DST_IPV6_FORWARDED_REPLACEMENT = "103:23:2:2::1"

DST_IP_FORWARDED_SCALE_PREFIX = "103.23.4."
DST_IPV6_FORWARDED_SCALE_PREFIX = "103:23:4:"

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
    scale_ports_indices = [mg_facts['minigraph_ptf_indices'][port_name] for port_name in scale_ports]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])

    # Generate destination IP's for scale test
    scale_dest_ips = {}
    for i in range(1, 75):
        ipv4_rule_name = "FORWARD_RULE_" + str(i)
        ipv6_rule_name = "V6_FORWARD_RULE_" + str(i)
        ipv4_address = DST_IP_FORWARDED_SCALE_PREFIX + str(i)
        ipv6_address = DST_IPV6_FORWARDED_SCALE_PREFIX + str(i) + "::1"
        scale_dest_ips[ipv4_rule_name] = ipv4_address
        scale_dest_ips[ipv6_rule_name] = ipv6_address

    setup_information = {
        "blocked_src_port_name": block_src_port,
        "blocked_src_port_indice": block_src_port_indice,
        "unblocked_src_port_indice": unblocked_src_port_indice,
        "scale_port_names": scale_ports,
        "scale_port_indices": scale_ports_indices,
        "scale_dest_ips": scale_dest_ips,
        "dst_port_indices": dst_port_indices,
        "router_mac": router_mac,
        "bind_ports": list_ports,
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
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=setup["dst_port_indices"], timeout=20)


def generate_packets(setup, dst_ip=DST_IP_FORWARDED_ORIGINAL, dst_ipv6=DST_IPV6_FORWARDED_ORIGINAL):
    """Generate packets that match the destination IP of given ips.
    If no IP is given, default to our original forwarding ips"""

    packets = {}

    packets["IPV4"] = testutils.simple_tcp_packet(eth_dst=setup["router_mac"],
                                                  ip_src=IP_SOURCE,
                                                  ip_dst=dst_ip,
                                                  ip_ttl=64)

    packets["IPV6"] = testutils.simple_tcpv6_packet(eth_dst=setup["router_mac"],
                                                    ipv6_src=IPV6_SOURCE,
                                                    ipv6_dst=dst_ipv6)

    return packets


def build_exp_pkt(input_pkt):
    """
    Generate the expected packet for given packet
    """
    pkt_copy = input_pkt.copy()
    if pkt_copy.haslayer('IP'):
        pkt_copy['IP'].ttl -= 1
    exp_pkt = Mask(pkt_copy)
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    return exp_pkt


def format_and_apply_template(duthost, template_name, extra_vars):
    dest_path = os.path.join(TMP_DIR, template_name)
    duthost.host.options['variable_manager'].extra_vars.update(extra_vars)
    duthost.file(path=dest_path, state='absent')
    duthost.template(src=os.path.join(TEMPLATES_DIR, template_name), dest=dest_path)

    # duthost.template uses single quotes, which breaks apply-patch. this replaces them with double quotes
    duthost.shell("sed -i \"s/'/\\\"/g\" " + dest_path)

    output = duthost.shell("config apply-patch {}".format(dest_path))

    duthost.file(path=dest_path, state='absent')

    return output


def load_and_apply_json_patch(duthost, file_name):
    with open(os.path.join(TEMPLATES_DIR, file_name)) as file:
        json_patch = json.load(file)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    return output


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
    pytest_assert(len(output) > 0, "'{}' is not a table on this device".format(table_name))

    first_line = output[0]
    pytest_assert(set(first_line.values()) == set(expected_first_line_content))
    table_bindings = [first_line["binding"]]
    for i in range(len(output)):
        table_bindings.append(output[i]["binding"])
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


@pytest.fixture(scope="module")
def dynamic_acl_create_table_type(rand_selected_dut):
    """Create a new ACL table type that can be used"""

    output = load_and_apply_json_patch(rand_selected_dut, CREATE_CUSTOM_TABLE_TYPE_FILE)

    expect_op_success(rand_selected_dut, output)

    yield

    dynamic_acl_remove_table_type(rand_selected_dut)


@pytest.fixture(scope="module")
def dynamic_acl_create_table(rand_selected_dut, dynamic_acl_create_table_type, setup):
    """Create a new ACL table type that can be used"""

    extra_vars = {
        'bind_ports': setup['bind_ports']
        }

    output = format_and_apply_template(rand_selected_dut, CREATE_CUSTOM_TABLE_TEMPLATE, extra_vars)

    expected_bindings = setup["bind_ports"]
    expected_first_line = ["DYNAMIC_ACL_TABLE",
                           "DYNAMIC_ACL_TABLE_TYPE",
                           setup["bind_ports"][0],
                           "DYNAMIC_ACL_TABLE",
                           "ingress",
                           "Active"]

    expect_op_success(rand_selected_dut, output)

    expect_acl_table_match_multiple_bindings(rand_selected_dut,
                                             "DYNAMIC_ACL_TABLE",
                                             expected_first_line,
                                             expected_bindings)

    yield

    dynamic_acl_remove_table(rand_selected_dut)


def dynamic_acl_create_forward_rules(duthost):
    """Create forward ACL rules"""

    IPV4_SUBNET = DST_IP_FORWARDED_ORIGINAL + "/32"
    IPV6_SUBNET = DST_IPV6_FORWARDED_ORIGINAL + "/128"

    extra_vars = {
        'ipv4_subnet': IPV4_SUBNET,
        'ipv6_subnet': IPV6_SUBNET
        }

    output = format_and_apply_template(duthost, CREATE_FORWARD_RULES_TEMPLATE, extra_vars)

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP: " + IPV4_SUBNET, "Active"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6: " + IPV6_SUBNET, "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
    expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)


def dynamic_acl_create_secondary_drop_rule(duthost, setup):
    """Create a drop rule in the format required when an ACL table has rules in it already"""

    extra_vars = {
        'blocked_port': setup["blocked_src_port_name"]
    }

    output = format_and_apply_template(duthost, CREATE_SECONDARY_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9997",
                             "DROP",
                             "IN_PORTS: " + setup["blocked_src_port_name"],
                             "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)


def dynamic_acl_create_drop_rule_initial(duthost, setup):
    """Create a drop rule in the format required when an ACL table does not have any rules in it yet"""

    extra_vars = {
        'blocked_port': setup["blocked_src_port_name"]
    }

    output = format_and_apply_template(duthost, CREATE_INITIAL_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9997",
                             "DROP",
                             "IN_PORTS: " + setup["blocked_src_port_name"],
                             "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)


def dynamic_acl_create_three_drop_rules(duthost, setup):
    """Create 3 drop rules in the format required when an ACL table does not have any rules in it yet"""

    extra_vars = {
        'blocked_port_1': setup["scale_port_names"][0],
        'blocked_port_2': setup["scale_port_names"][1],
        'blocked_port_3': setup["scale_port_names"][2]

    }

    output = format_and_apply_template(duthost, CREATE_THREE_DROP_RULES_TEMPLATE, extra_vars)

    expected_rule_3_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_3",
                               "9997",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_1'],
                               "Active"]
    expected_rule_4_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_4",
                               "9996",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_2'],
                               "Active"]
    expected_rule_5_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_5",
                               "9995",
                               "DROP",
                               "IN_PORTS: " + extra_vars['blocked_port_3'],
                               "Active"]

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_3", expected_rule_3_content)
    expect_acl_rule_match(duthost, "RULE_4", expected_rule_4_content)
    expect_acl_rule_match(duthost, "RULE_5", expected_rule_5_content)


def dynamic_acl_verify_packets(setup, ptfadapter, packets, packets_dropped, src_port=None):
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


def dynamic_acl_remove_third_drop_rule(duthost):
    """Remove the third drop rule of the three created for the drop rule removal test"""

    output = load_and_apply_json_patch(duthost, REMOVE_THIRD_DROP_RULE_FILE)

    expect_op_success(duthost, output)

    expect_acl_rule_removed(duthost, "RULE_5")


def dynamic_acl_replace_nonexistent_rule(duthost):
    """Verify that replacing a non-existent rule fails"""

    output = load_and_apply_json_patch(duthost, REPLACE_NONEXISTENT_RULE_FILE)

    expect_op_failure(output)


def dynamic_acl_replace_rules(duthost):
    """
    Replace our forward rules on the ACL table"""

    REPLACEMENT_IPV4_SUBNET = DST_IP_FORWARDED_REPLACEMENT + "/32"
    REPLACEMENT_IPV6_SUBNET = DST_IPV6_FORWARDED_REPLACEMENT + "/128"

    extra_vars = {
        'ipv4_subnet': REPLACEMENT_IPV4_SUBNET,
        'ipv6_subnet': REPLACEMENT_IPV6_SUBNET
        }

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_1",
                               "9999",
                               "FORWARD",
                               "DST_IP: " + REPLACEMENT_IPV4_SUBNET,
                               "Active"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE",
                               "RULE_2",
                               "9998",
                               "FORWARD",
                               "DST_IPV6: " + REPLACEMENT_IPV6_SUBNET,
                               "Active"]

    output = format_and_apply_template(duthost, REPLACE_RULES_TEMPLATE, extra_vars)

    expect_op_success(duthost, output)

    expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
    expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)


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
        full_rule_name = "DYNAMIC_ACL_TABLE|" + rule_name
        rule_vals = {
            dst_type: subnet,
            "PRIORITY": str(priority),
            "PACKET_ACTION": "FORWARD"
        }
        value_dict[full_rule_name] = rule_vals
        expected_content = ["DYNAMIC_ACL_TABLE",
                            rule_name,
                            str(priority),
                            "FORWARD",
                            dst_type + ": " + subnet,
                            "Active"]
        expected_rule_contents[rule_name] = expected_content
        priority -= 1

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
            "PRIORITY": str(priority),
            "PACKET_ACTION": "DROP",
            "IN_PORTS": port_name
        }
        patch = {
            "op": "add",
            "path": full_rule_name,
            "value": rule_vals
        }
        json_patch.append(patch)
        expected_content = ["DYNAMIC_ACL_TABLE", rule_name, str(priority), "DROP", "IN_PORTS: " + port_name, "Active"]
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


def dynamic_acl_remove_forward_rule(duthost, ip_type):
    """Remove selected forward rule from the acl table"""

    if ip_type == "IPV4":
        file = REMOVE_IPV4_FORWARD_RULE_FILE
        rule_name = "RULE_1"
    else:
        file = REMOVE_IPV6_FORWARD_RULE_FILE
        rule_name = "RULE_2"

    output = load_and_apply_json_patch(duthost, file)

    expect_op_success(duthost, output)

    expect_acl_rule_removed(duthost, rule_name)


def dynamic_acl_remove_table(duthost):
    """Remove an ACL Table Type from the duthost"""

    output = load_and_apply_json_patch(duthost, REMOVE_TABLE_FILE)

    expect_op_success(duthost, output)


def dynamic_acl_remove_nonexistent_table(duthost):
    """Remove a nonexistent ACL Table from the duthost, verify it fails"""

    output = load_and_apply_json_patch(duthost, REMOVE_NONEXISTENT_TABLE_FILE)

    expect_op_failure(output)


def dynamic_acl_remove_table_type(duthost):
    """Remove an ACL Table definition from the duthost"""

    output = load_and_apply_json_patch(duthost, REMOVE_TABLE_TYPE_FILE)

    expect_op_success(duthost, output)


def test_gcu_acl_drop_rule_creation(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that we can create a drop rule via GCU, and that once this drop rule is in place packets
    that match the drop rule are dropped and packets that do not match the drop rule are forwarded"""

    dynamic_acl_create_drop_rule_initial(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=False,
                               src_port=setup["unblocked_src_port_indice"])


def test_gcu_acl_drop_rule_removal(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that once a drop rule is removed, packets that were previously being dropped are now forwarded"""

    dynamic_acl_create_three_drop_rules(rand_selected_dut, setup)
    dynamic_acl_remove_third_drop_rule(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=False,
                               src_port=setup["scale_port_indices"][2])


def test_gcu_acl_forward_rule_priority_respected(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that forward rules and drop rules can be created at the same time, with the forward rules having
    higher priority than drop.  Then, perform a traffic test to confirm that packets that match both the forward
    and drop rules are correctly forwarded, as the forwarding rules have higher priority"""

    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_verify_packets(setup, ptfadapter, packets=generate_packets(setup), packets_dropped=False)
    dynamic_acl_verify_packets(setup, ptfadapter,
                               packets=generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True)


def test_gcu_acl_forward_rule_replacement(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Test that forward rules can be created, and then afterwards can have their match pattern updated to a new value.
    Confirm that packets sent that match this new value are correctly forwarded, and that packets that are sent that
    match the old, replaced value are correctly dropped."""

    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_replace_rules(rand_selected_dut)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               packets=generate_packets(setup,
                                                        DST_IP_FORWARDED_REPLACEMENT,
                                                        DST_IPV6_FORWARDED_REPLACEMENT),
                               packets_dropped=False)
    dynamic_acl_verify_packets(setup, ptfadapter, packets=generate_packets(setup), packets_dropped=True)


@pytest.mark.parametrize("ip_type", ["IPV4", "IPV6"])
def test_gcu_acl_forward_rule_removal(rand_selected_dut, ptfadapter, setup, ip_type, dynamic_acl_create_table):
    """Test that if a forward rule is created, and then removed, that packets associated with that rule are properly
    no longer forwarded, and packets associated with the remaining rule are forwarded"""
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_secondary_drop_rule(rand_selected_dut, setup)
    dynamic_acl_remove_forward_rule(rand_selected_dut, ip_type)
    forward_packets = generate_packets(setup)
    drop_packets = forward_packets.copy()
    if ip_type == "IPV4":
        other_type = "IPV6"
    else:
        other_type = "IPV4"
    # generate_packets returns ipv4 and ipv6 packets. remove vals from two dicts so that only correct packets remain
    drop_packets.pop(other_type)
    forward_packets.pop(ip_type)
    dynamic_acl_verify_packets(setup, ptfadapter, drop_packets, packets_dropped=True)
    dynamic_acl_verify_packets(setup, ptfadapter, forward_packets, packets_dropped=False)


def test_gcu_acl_scale_rules(rand_selected_dut, ptfadapter, setup, dynamic_acl_create_table):
    """Perform a scale test, creating 150 forward rules with top priority,
    and then creating a drop rule for every single VLAN port on our device.
    Select any one of our blocked ports, as well as the ips for two of our forward rules,
    and confirm that packet forwarding and dropping works as expected even with this large amount of rules"""

    dynamic_acl_apply_forward_scale_rules(rand_selected_dut, setup)
    dynamic_acl_apply_drop_scale_rules(rand_selected_dut, setup)

    # select one of our src ports blocked by these scale rules
    blocked_scale_port = setup["scale_port_indices"][0]

    # select ipv4 and ipv6 destination ips from our forwarding rules
    v4_dest = setup["scale_dest_ips"]["FORWARD_RULE_10"]
    v6_dest = setup["scale_dest_ips"]["V6_FORWARD_RULE_10"]

    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               generate_packets(setup, v4_dest, v6_dest),
                               packets_dropped=False,
                               src_port=blocked_scale_port)
    dynamic_acl_verify_packets(setup,
                               ptfadapter,
                               generate_packets(setup, DST_IP_BLOCKED, DST_IPV6_BLOCKED),
                               packets_dropped=True,
                               src_port=blocked_scale_port)


def test_gcu_acl_nonexistent_rule_replacement(rand_selected_dut):
    """Confirm that replacing a nonexistent rule results in operation failure"""
    dynamic_acl_replace_nonexistent_rule(rand_selected_dut)


def test_gcu_acl_nonexistent_table_removal(rand_selected_dut):
    """Confirm that removing a nonexistent table results in operation failure"""
    dynamic_acl_remove_nonexistent_table(rand_selected_dut)
