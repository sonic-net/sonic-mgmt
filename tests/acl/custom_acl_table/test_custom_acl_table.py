import logging
import json
import pytest
import time

from ptf.mask import Mask
import ptf.packet as scapy


import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.utilities import get_all_upstream_neigh_type, get_neighbor_ptf_port_list, is_ipv6_only_topology

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),  # Only run on T0 testbed
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

CUSTOM_ACL_TABLE_TYPE_SRC_FILE = "acl/custom_acl_table/custom_acl_table.json"
CUSTOM_ACL_TABLE_TYPE_DST_FILE = "/tmp/custom_acl_table.json"

ACL_RULE_SRC_FILE = "acl/custom_acl_table/acl_rules.json"
ACL_RULE_DST_FILE = "/tmp/acl_rules.json"

# IPv6-specific custom ACL table constants
CUSTOM_ACL_TABLE_TYPE_IPV6_SRC_FILE = "acl/custom_acl_table/custom_acl_table_ipv6.json"
CUSTOM_ACL_TABLE_TYPE_IPV6_DST_FILE = "/tmp/custom_acl_table_ipv6.json"

ACL_RULE_IPV6_SRC_FILE = "acl/custom_acl_table/acl_rules_ipv6.json"
ACL_RULE_IPV6_DST_FILE = "/tmp/acl_rules_ipv6.json"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_FAILED_RE = ".*Failed to create ACL rule.*"


@pytest.fixture(scope='module')
def setup_counterpoll_interval(rand_selected_dut, rand_unselected_dut, tbinfo):
    """
    Set the counterpoll interval for acl to 1 second (10 seconds by default)
    """
    # Set polling interval to 1 second
    rand_selected_dut.shell('counterpoll acl interval 1000')
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell('counterpoll acl interval 1000')
    time.sleep(10)
    yield
    # Restore default value 10 seconds
    rand_selected_dut.shell('counterpoll acl interval 10000')
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell('counterpoll acl interval 10000')


def clear_acl_counter(dut):
    """
    Clear the counter of ACL
    """
    dut.shell('aclshow -c')


def read_acl_counter(dut, rule_name):
    """
    Read the counter of given rule
    RULE NAME    TABLE NAME      PRIO    PACKETS COUNT    BYTES COUNT
    -----------  ------------  ------  ---------------  -------------
    RULE_1       L3_MIX_TABLE    9999                0              0
    """
    cmd = 'aclshow -a -r {}'.format(rule_name)
    time.sleep(2)
    counters = dut.show_and_parse(cmd)
    for counter in counters:
        if counter['rule name'] == rule_name:
            return int(counter['packets count'])

    return 0


# TODO: Move this fixture to a shared place of acl test
@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """
    Remove DATAACL to free TCAM resources
    """
    TABLE_NAME = "DATAACL"
    data_acl_table = None
    output = rand_selected_dut.shell("sonic-cfggen -d --var-json \"ACL_TABLE\"")['stdout']
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        output = rand_unselected_dut.shell("sonic-cfggen -d --var-json \"ACL_TABLE\"")['stdout']
    try:
        acl_tables = json.loads(output)
        if TABLE_NAME in acl_tables:
            data_acl_table = {TABLE_NAME: acl_tables[TABLE_NAME]}
    except ValueError:
        pass
    if data_acl_table is None:
        yield
        return
    # Remove DATAACL
    logger.info("Removing ACL table {}".format(TABLE_NAME))
    rand_selected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME))
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME))
    yield
    # Recover DATAACL
    data_acl = {}
    data_acl['ACL_TABLE'] = data_acl_table
    cmd = 'sonic-cfggen -a \'{}\' -w'.format(json.dumps(data_acl))
    logger.info("Restoring ACL table {}".format(TABLE_NAME))
    rand_selected_dut.shell(cmd)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell(cmd)


def setup_and_cleanup_custom_acl_table(rand_selected_dut, rand_unselected_dut, tbinfo,
                                       table_type_src_file, table_type_dst_file,
                                       table_name, table_type_name, is_ipv6=False):
    """Helper function to setup and cleanup custom ACL table"""
    # Define custom table type by loading json configuration
    rand_selected_dut.copy(src=table_type_src_file, dest=table_type_dst_file)
    rand_selected_dut.shell("sonic-cfggen -j {} -w".format(table_type_dst_file))
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.copy(src=table_type_src_file, dest=table_type_dst_file)
        rand_unselected_dut.shell("sonic-cfggen -j {} -w".format(table_type_dst_file))

    # Create ACL table and bind to Vlan1000 interface
    cmd_create_table = "config acl add table {} {} -s ingress -p Vlan1000".format(table_name, table_type_name)
    cmd_remove_table = "config acl remove table {}".format(table_name)

    marker_prefix = "custom_acl_ipv6" if is_ipv6 else "custom_acl"
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix=marker_prefix)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        loganalyzer = LogAnalyzer(ansible_host=rand_unselected_dut, marker_prefix=marker_prefix)
    loganalyzer.load_common_config()

    try:
        logger.info("Creating ACL table {} with type {}".format(table_name, table_type_name))
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        # Ignore any other errors to reduce noise
        loganalyzer.ignore_regex = [r".*"]
        with loganalyzer:
            rand_selected_dut.shell(cmd_create_table)
            if "dualtor-aa" in tbinfo["topo"]["name"]:
                rand_unselected_dut.shell(cmd_create_table)
    except LogAnalyzerError as err:
        # Cleanup Config DB if table creation failed
        logger.error("ACL table creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_remove_table)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            rand_unselected_dut.shell(cmd_remove_table)
        raise err

    yield

    logger.info("Removing ACL table and custom type")
    # Remove ACL table
    rand_selected_dut.shell(cmd_remove_table)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell(cmd_remove_table)
    # Remove custom type
    rand_selected_dut.shell("sonic-db-cli CONFIG_DB del \'ACL_TABLE_TYPE|{}\'".format(table_type_name))
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell("sonic-db-cli CONFIG_DB del \'ACL_TABLE_TYPE|{}\'".format(table_type_name))


@pytest.fixture(scope='module')
def setup_custom_acl_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Setup CUSTOM_TABLE with CUSTOM_TYPE for IPv4/IPv6 mix testing"""
    yield from setup_and_cleanup_custom_acl_table(
        rand_selected_dut, rand_unselected_dut, tbinfo,
        CUSTOM_ACL_TABLE_TYPE_SRC_FILE, CUSTOM_ACL_TABLE_TYPE_DST_FILE,
        "CUSTOM_TABLE", "CUSTOM_TYPE", is_ipv6=False
    )


@pytest.fixture(scope='module')
def setup_custom_acl_table_ipv6(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Setup CUSTOM_IPV6_TABLE with CUSTOM_TYPE_IPV6 for IPv6-specific field testing"""
    yield from setup_and_cleanup_custom_acl_table(
        rand_selected_dut, rand_unselected_dut, tbinfo,
        CUSTOM_ACL_TABLE_TYPE_IPV6_SRC_FILE, CUSTOM_ACL_TABLE_TYPE_IPV6_DST_FILE,
        "CUSTOM_IPV6_TABLE", "CUSTOM_TYPE_IPV6", is_ipv6=True
    )


def setup_and_cleanup_acl_rules(rand_selected_dut, rand_unselected_dut, tbinfo,
                                rule_file, dest_file, table_name, is_ipv6=False):
    """Helper function to setup and cleanup ACL rules for a given table"""
    # Copy and load acl rules
    rand_selected_dut.copy(src=rule_file, dest=dest_file)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.copy(src=rule_file, dest=dest_file)
    cmd_add_rules = "sonic-cfggen -j {} -w".format(dest_file)
    cmd_rm_rules = "acl-loader delete {}".format(table_name)

    marker_prefix = "custom_acl_ipv6" if is_ipv6 else "custom_acl"
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix=marker_prefix)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        loganalyzer = LogAnalyzer(ansible_host=rand_unselected_dut, marker_prefix=marker_prefix)
    loganalyzer.match_regex = [LOG_EXPECT_ACL_RULE_FAILED_RE]

    try:
        logger.info("Creating ACL rules in {}".format(table_name))
        with loganalyzer:
            rand_selected_dut.shell(cmd_add_rules)
            if "dualtor-aa" in tbinfo["topo"]["name"]:
                rand_unselected_dut.shell(cmd_add_rules)
    except LogAnalyzerError as err:
        # Cleanup Config DB if failed
        logger.error("ACL rule creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_rm_rules)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            rand_unselected_dut.shell(cmd_rm_rules)
        raise err

    yield

    # Remove testing rules
    logger.info("Removing testing ACL rules from {}".format(table_name))
    rand_selected_dut.shell(cmd_rm_rules)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell(cmd_rm_rules)


@pytest.fixture(scope='module')
def setup_acl_rules(rand_selected_dut, rand_unselected_dut, tbinfo, setup_custom_acl_table):
    """Load ACL rules for CUSTOM_TABLE"""
    yield from setup_and_cleanup_acl_rules(
        rand_selected_dut, rand_unselected_dut, tbinfo,
        ACL_RULE_SRC_FILE, ACL_RULE_DST_FILE, "CUSTOM_TABLE", is_ipv6=False
    )


@pytest.fixture(scope='module')
def setup_acl_rules_ipv6(rand_selected_dut, rand_unselected_dut, tbinfo, setup_custom_acl_table_ipv6):
    """Load ACL rules for CUSTOM_IPV6_TABLE"""
    yield from setup_and_cleanup_acl_rules(
        rand_selected_dut, rand_unselected_dut, tbinfo,
        ACL_RULE_IPV6_SRC_FILE, ACL_RULE_IPV6_DST_FILE, "CUSTOM_IPV6_TABLE", is_ipv6=True
    )


def build_testing_pkts(router_mac, tbinfo):
    """
    Generate packet for IO test
    """
    # The IPs and ports must be exactly the same with rules defined in acl_rules.json
    DST_IP = "103.23.2.1"
    DST_IPV6 = "103:23:2:1::1"
    SRC_PORT = 8080
    DST_PORT = 8080
    SRC_RANGE_PORT = 8085
    DST_RANGE_PORT = 8085

    test_packets = {}

    if not is_ipv6_only_topology(tbinfo):
        # Verify matching destination IP and protocol
        test_packets['RULE_2'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                             ip_src='192.168.0.3',
                                                             ip_dst=DST_IP)
        # Verify matching source port (IPV4)
        test_packets['RULE_5'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                             ip_src='192.168.0.3',
                                                             ip_dst='1.1.1.1',
                                                             tcp_sport=SRC_PORT)
        # Verify matching source port range (IPV4)
        test_packets['RULE_7'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                             ip_src='192.168.0.3',
                                                             ip_dst='1.1.1.1',
                                                             tcp_sport=SRC_RANGE_PORT)

    # Verify matching IPV6 destination and next header
    test_packets['RULE_4'] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                                           ipv6_src='fc02:1000::3',
                                                           ipv6_dst=DST_IPV6)

    # Verify matching destination port (IPV6)
    test_packets['RULE_6'] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                                           ipv6_src='fc02:1000::3',
                                                           ipv6_dst='103:23:2:1::2',
                                                           tcp_dport=DST_PORT)

    # Verify matching destination port range (IPV6)
    test_packets['RULE_8'] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                                           ipv6_src='fc02:1000::3',
                                                           ipv6_dst='103:23:2:1::2',
                                                           tcp_dport=DST_RANGE_PORT)

    return test_packets


def build_exp_pkt(input_pkt):
    """
    Generate the expected packet for given packet
    """
    exp_pkt = Mask(input_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    if input_pkt.haslayer('IP'):
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    else:
        exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")

    return exp_pkt


def test_custom_acl(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                    setup_acl_rules, toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
                    setup_counterpoll_interval, remove_dataacl_table):   # noqa: F811
    """
    The test case is to verify the functionality of custom ACL table
    Test steps
    1. Define a custom ACL table type by loading json configuration
    2. Create an ingress ACL table with the custom type
    3. Toggle all ports to active if the test is running on dual-tor
    4. Ingress packets from vlan port
    5. Verify the packets are egressed to uplinks
    6. Verify the counter of expected rule increases as expected
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    mg_facts_unselected_dut = None
    asic_type = rand_selected_dut.facts['asic_type']
    if "dualtor" in tbinfo["topo"]["name"]:
        mg_facts_unselected_dut = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    # Selected the first vlan port as source port
    src_port = list(mg_facts['minigraph_vlans'].values())[0]['members'][0]
    src_port_indice = mg_facts['minigraph_ptf_indices'][src_port]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    if len(mg_facts['minigraph_portchannels']):
        for _, v in mg_facts['minigraph_portchannels'].items():
            for member in v['members']:
                dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])
                if "dualtor-aa" in tbinfo["topo"]["name"] and mg_facts_unselected_dut is not None:
                    dst_port_indices.append(mg_facts_unselected_dut['minigraph_ptf_indices'][member])
    else:
        topo = tbinfo["topo"]["type"]
        upstream_neigh_types = get_all_upstream_neigh_type(topo)
        for upstream_neigh_type in upstream_neigh_types:
            dst_port_indices.extend(get_neighbor_ptf_port_list(rand_selected_dut, upstream_neigh_type, tbinfo))

    # Test regular ACL rules (IPv4 and IPv6 mix)
    test_pkts = build_testing_pkts(router_mac, tbinfo)
    for rule, pkt in list(test_pkts.items()):
        logger.info("Testing ACL rule {}".format(rule))
        exp_pkt = build_exp_pkt(pkt)
        # Send and verify packet
        clear_acl_counter(rand_selected_dut)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            clear_acl_counter(rand_unselected_dut)
        if asic_type == 'vs':
            logger.info("Skip ACL verification on VS platform")
            continue
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port_indice)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=dst_port_indices, timeout=5)
        acl_counter = read_acl_counter(rand_selected_dut, rule)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            acl_counter_unselected_dut = read_acl_counter(rand_unselected_dut, rule)
            acl_counter += acl_counter_unselected_dut
        # Verify acl counter
        pytest_assert(acl_counter == 1, "ACL counter for {} didn't increase as expected".format(rule))


def test_custom_acl_ipv6(rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter,
                         setup_acl_rules_ipv6, toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
                         setup_counterpoll_interval, remove_dataacl_table):   # noqa: F811
    """
    Test custom ACL table with CUSTOM_TYPE_IPV6 (IPv6-specific fields)

    Test steps:
    1. Define custom ACL table type CUSTOM_TYPE_IPV6 with IPv6 fields by loading json configuration
    2. Create ingress ACL table CUSTOM_IPV6_TABLE with the custom type
    3. Toggle all ports to active if the test is running on dual-tor
    4. Send IPv6 test packets from vlan port
    5. Verify the packets are forwarded to uplinks (or dropped for drop rules)
    6. Verify the counter of expected rule increases as expected
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    mg_facts_unselected_dut = None
    asic_type = rand_selected_dut.facts['asic_type']
    if "dualtor" in tbinfo["topo"]["name"]:
        mg_facts_unselected_dut = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    # Selected the first vlan port as source port
    src_port = list(mg_facts['minigraph_vlans'].values())[0]['members'][0]
    src_port_indice = mg_facts['minigraph_ptf_indices'][src_port]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    if len(mg_facts['minigraph_portchannels']):
        for _, v in mg_facts['minigraph_portchannels'].items():
            for member in v['members']:
                dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])
                if "dualtor-aa" in tbinfo["topo"]["name"] and mg_facts_unselected_dut is not None:
                    dst_port_indices.append(mg_facts_unselected_dut['minigraph_ptf_indices'][member])
    else:
        topo = tbinfo["topo"]["type"]
        upstream_neigh_types = get_all_upstream_neigh_type(topo)
        for upstream_neigh_type in upstream_neigh_types:
            dst_port_indices.extend(get_neighbor_ptf_port_list(rand_selected_dut, upstream_neigh_type, tbinfo))

    # Test IPv6-specific ACL rules
    test_pkts_ipv6 = build_testing_pkts_ipv6(router_mac)
    for rule, pkt in list(test_pkts_ipv6.items()):
        logger.info("Testing IPv6 ACL rule {}".format(rule))
        exp_pkt = build_exp_pkt(pkt)
        # Send and verify packet
        clear_acl_counter(rand_selected_dut)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            clear_acl_counter(rand_unselected_dut)
        if asic_type == 'vs':
            logger.info("Skip ACL verification on VS platform")
            continue
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port_indice)

        # For DROP rules, verify packet is not forwarded; for FORWARD rules, verify packet is forwarded
        if rule == 'DEFAULT_DROP_RULE':
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=dst_port_indices, timeout=5)
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=dst_port_indices, timeout=5)

        acl_counter = read_acl_counter(rand_selected_dut, rule)
        if "dualtor-aa" in tbinfo["topo"]["name"]:
            acl_counter_unselected_dut = read_acl_counter(rand_unselected_dut, rule)
            acl_counter += acl_counter_unselected_dut
        # Verify acl counter
        logger.info("ACL counter for rule {} is {}".format(rule, acl_counter))
        pytest_assert(acl_counter == 1, "ACL counter for {} didn't increase as expected".format(rule))


def build_testing_pkts_ipv6(router_mac):
    """
    Generate IPv6 packets for testing custom ACL table with SRC_IPV6, DST_IPV6, IP_TYPE, NEXT_HEADER
    """
    test_packets = {}

    # Test RULE_SRC_IPV6: Match source IPv6 address
    test_packets['RULE_SRC_IPV6'] = testutils.simple_tcpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:1::1',
        ipv6_dst='2001:db8:100::1'
    )

    # Test RULE_DST_IPV6: Match destination IPv6 address
    test_packets['RULE_DST_IPV6'] = testutils.simple_tcpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:100::2',
        ipv6_dst='2001:db8:2::1'
    )

    # Test RULE_SRC_DST_IPV6: Match both source and destination IPv6 addresses
    test_packets['RULE_SRC_DST_IPV6'] = testutils.simple_tcpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:3::1',
        ipv6_dst='2001:db8:4::1'
    )

    # Test RULE_NEXT_HEADER_TCP: Match destination IPv6 and next header (TCP = 6)
    test_packets['RULE_NEXT_HEADER_TCP'] = testutils.simple_tcpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:100::3',
        ipv6_dst='2001:db8:5::1'
    )

    # Test RULE_NEXT_HEADER_UDP: Match destination IPv6 and next header (UDP = 17)
    test_packets['RULE_NEXT_HEADER_UDP'] = testutils.simple_udpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:100::4',
        ipv6_dst='2001:db8:6::1'
    )

    # Test RULE_NEXT_HEADER_ICMPV6: Match destination IPv6 and next header (ICMPv6 = 58)
    test_packets['RULE_NEXT_HEADER_ICMPV6'] = testutils.simple_icmpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:100::5',
        ipv6_dst='2001:db8:7::1'
    )

    # Test DEFAULT_DROP_RULE: Match packets that don't match any higher priority rules
    # Using addresses that don't match any specific rules above
    test_packets['DEFAULT_DROP_RULE'] = testutils.simple_tcpv6_packet(
        eth_dst=router_mac,
        ipv6_src='2001:db8:200::1',
        ipv6_dst='2001:db8:201::1'
    )

    return test_packets
