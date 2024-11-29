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

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),  # Only run on T0 testbed
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
]

CUSTOM_ACL_TABLE_TYPE_SRC_FILE = "acl/custom_acl_table/custom_acl_table.json"
CUSTOM_ACL_TABLE_TYPE_DST_FILE = "/tmp/custom_acl_table.json"

ACL_RULE_SRC_FILE = "acl/custom_acl_table/acl_rules.json"
ACL_RULE_DST_FILE = "/tmp/acl_rules.json"

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


@pytest.fixture(scope='module')
def setup_custom_acl_table(rand_selected_dut, rand_unselected_dut, tbinfo):
    # Define a custom table type CUSTOM_TYPE by loading a json configuration
    rand_selected_dut.copy(src=CUSTOM_ACL_TABLE_TYPE_SRC_FILE, dest=CUSTOM_ACL_TABLE_TYPE_DST_FILE)
    rand_selected_dut.shell("sonic-cfggen -j {} -w".format(CUSTOM_ACL_TABLE_TYPE_DST_FILE))
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.copy(src=CUSTOM_ACL_TABLE_TYPE_SRC_FILE, dest=CUSTOM_ACL_TABLE_TYPE_DST_FILE)
        rand_unselected_dut.shell("sonic-cfggen -j {} -w".format(CUSTOM_ACL_TABLE_TYPE_DST_FILE))
    # Create an ACL table and bind to Vlan1000 interface
    cmd_create_table = "config acl add table CUSTOM_TABLE CUSTOM_TYPE -s ingress -p Vlan1000"
    cmd_remove_table = "config acl remove table CUSTOM_TABLE"
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="custom_acl")
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        loganalyzer = LogAnalyzer(ansible_host=rand_unselected_dut, marker_prefix="custom_acl")
    loganalyzer.load_common_config()

    try:
        logger.info("Creating ACL table CUSTOM_TABLE with type CUSTOM_TYPE")
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
    rand_selected_dut.shell("sonic-db-cli CONFIG_DB del \'ACL_TABLE_TYPE|CUSTOM_TYPE\'")
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell("sonic-db-cli CONFIG_DB del \'ACL_TABLE_TYPE|CUSTOM_TYPE\'")


@pytest.fixture(scope='module')
def setup_acl_rules(rand_selected_dut, rand_unselected_dut, tbinfo, setup_custom_acl_table):
    # Copy and load acl rules
    rand_selected_dut.copy(src=ACL_RULE_SRC_FILE, dest=ACL_RULE_DST_FILE)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.copy(src=ACL_RULE_SRC_FILE, dest=ACL_RULE_DST_FILE)
    cmd_add_rules = "sonic-cfggen -j {} -w".format(ACL_RULE_DST_FILE)
    cmd_rm_rules = "acl-loader delete CUSTOM_TABLE"

    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="custom_acl")
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        loganalyzer = LogAnalyzer(ansible_host=rand_unselected_dut, marker_prefix="custom_acl")
    loganalyzer.match_regex = [LOG_EXPECT_ACL_RULE_FAILED_RE]
    try:
        logger.info("Creating ACL rules in CUSTOM_TABLE")
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
    logger.info("Removing testing ACL rules")
    rand_selected_dut.shell(cmd_rm_rules)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        rand_unselected_dut.shell(cmd_rm_rules)


def build_testing_pkts(router_mac):
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

    # Verify matching destination IP and protocol
    test_packets['RULE_2'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                         ip_src='192.168.0.3',
                                                         ip_dst=DST_IP)

    # Verify matching IPV6 destination and next header
    test_packets['RULE_4'] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                                           ipv6_src='fc02:1000::3',
                                                           ipv6_dst=DST_IPV6)
    # Verify matching source port (IPV4)
    test_packets['RULE_5'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                         ip_src='192.168.0.3',
                                                         ip_dst='1.1.1.1',
                                                         tcp_sport=SRC_PORT)
    # Verify matching destination port (IPV6)
    test_packets['RULE_6'] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                                           ipv6_src='fc02:1000::3',
                                                           ipv6_dst='103:23:2:1::2',
                                                           tcp_dport=DST_PORT)
    # Verify matching source port range (IPV4)
    test_packets['RULE_7'] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                                         ip_src='192.168.0.3',
                                                         ip_dst='1.1.1.1',
                                                         tcp_sport=SRC_RANGE_PORT)
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
                    setup_acl_rules, toggle_all_simulator_ports_to_rand_selected_tor,  # noqa F811
                    setup_counterpoll_interval, remove_dataacl_table):   # noqa F811
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
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])
            if "dualtor-aa" in tbinfo["topo"]["name"]:
                dst_port_indices.append(mg_facts_unselected_dut['minigraph_ptf_indices'][member])

    test_pkts = build_testing_pkts(router_mac)
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
