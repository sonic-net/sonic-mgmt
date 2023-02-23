import logging
import re
import pytest
import ptf.testutils as testutils
from ptf import mask, packet
from collections import namedtuple
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.utilities import wait
from tests.route.test_route_flap import get_ip_route_info, get_route_prefix_len

pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx")
]

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 10,
    'basic': 50,
    'confident': 200
}

# Template json file used to test scale rules
STRESS_ACL_TABLE_TEMPLATE = "acl/templates/acltb_test_stress_acl_table.j2"
STRESS_ACL_RULE_TEMPLATE = "acl/templates/acltb_test_stress_acl_rules.j2"
STRESS_ACL_TABLE_JSON_FILE = "/tmp/acltb_test_stress_acl_table.json"
STRESS_ACL_RULE_JSON_FILE = "/tmp/acltb_test_stress_acl_rules.json"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_FAILED_RE = ".*Failed to create ACL rule.*"

ACL_RULE_NUMS = 10


@pytest.fixture(scope='module')
def prepare_test_file(rand_selected_dut):
    # Define a custom table type CUSTOM_TYPE by loading a json configuration
    rand_selected_dut.template(src=STRESS_ACL_TABLE_TEMPLATE, dest=STRESS_ACL_TABLE_JSON_FILE)
    rand_selected_dut.shell("sonic-cfggen -j {} -w".format(STRESS_ACL_TABLE_JSON_FILE))
    # Copy acl rules
    rand_selected_dut.template(src=STRESS_ACL_RULE_TEMPLATE, dest=STRESS_ACL_RULE_JSON_FILE)


@pytest.fixture(scope='module')
def prepare_dst_ip(rand_selected_dut, tbinfo):
    routes = namedtuple('routes', ['route', 'aspath'])
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    iproute_info = get_ip_route_info(rand_selected_dut)
    dst_prefix_list = []
    route_prefix_len = get_route_prefix_len(tbinfo, common_config)
    for route_prefix in iproute_info:
        if "/{}".format(route_prefix_len) in route_prefix:
            multipath = iproute_info[route_prefix][0].get('multipath', False)
            if multipath:
                out = iproute_info[route_prefix][0].get('path').split(' ')
                aspath = out[1:]
                entry = routes(route_prefix, ' '.join(aspath))
                dst_prefix_list.append(entry)
                break

    route_to_send = dst_prefix_list[0].route
    dst_ip_addr = route_to_send.strip('/{}'.format(route_prefix_len))

    return dst_ip_addr


def parse_interfaces(output_lines, pc_ports_map):
    """
    Parse the inerfaces from 'show ip route' into an array
    """
    route_targets = []
    ifaces = []
    output_lines = output_lines[3:]

    for item in output_lines:
        match = re.search(r"(Ethernet\d+|PortChannel\d+)", item)
        if match:
            route_targets.append(match.group(0))

    for route_target in route_targets:
        if route_target.startswith("Ethernet"):
            ifaces.append(route_target)
        elif route_target.startswith("PortChannel") and route_target in pc_ports_map:
            ifaces.extend(pc_ports_map[route_target])

    return ifaces


@pytest.fixture(scope='module')
def prepare_test_port(rand_selected_dut, tbinfo, prepare_dst_ip):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    if tbinfo["topo"]["type"] == "mx":
        dut_port = rand_selected_dut.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"][0]
    else:
        dut_port = list(mg_facts['minigraph_portchannels'].keys())[0]
    if not dut_port:
        pytest.skip('No portchannels found')
    if "Ethernet" in dut_port:
        dut_eth_port = dut_port
    elif "PortChannel" in dut_port:
        dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    pc_ports_map = {pc: mg_facts["minigraph_portchannels"][pc]["members"] for pc in
                    mg_facts["minigraph_portchannels"].keys()}

    out_ifaces = parse_interfaces(rand_selected_dut.command("show ip route {}"
                                                            .format(prepare_dst_ip))["stdout_lines"], pc_ports_map)

    out_ptf_indices = []
    for iface in out_ifaces:
        out_ptf_indices.append(mg_facts["minigraph_ptf_indices"][iface])

    return ptf_src_port, out_ptf_indices, dut_port


@pytest.fixture(scope='module')
def setup_stress_acl_table(rand_selected_dut, prepare_test_file, prepare_test_port):
    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port

    # Create an ACL table and bind to Vlan1000 interface
    cmd_create_table = "config acl add table STRESS_ACL L3 -s ingress -p {}".format(dut_port)
    cmd_remove_table = "config acl remove table STRESS_ACL"
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="stress_acl")
    loganalyzer.load_common_config()

    try:
        logger.info("Creating ACL table STRESS_ACL with type L3")
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        # Ignore any other errors to reduce noise
        loganalyzer.ignore_regex = [r".*"]
        with loganalyzer:
            rand_selected_dut.shell(cmd_create_table)
    except LogAnalyzerError as err:
        # Cleanup Config DB if table creation failed
        logger.error("ACL table creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_remove_table)
        raise err

    yield
    logger.info("Removing ACL table STRESS_ACL")
    # Remove ACL table
    rand_selected_dut.shell(cmd_remove_table)


@pytest.fixture(scope='module')
def setup_stress_acl_rules(rand_selected_dut, setup_stress_acl_table):
    cmd_add_rules = "sonic-cfggen -j {} -w".format(STRESS_ACL_RULE_JSON_FILE)
    cmd_rm_rules = "acl-loader delete STRESS_ACL"

    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="stress_acl")
    loganalyzer.match_regex = [LOG_EXPECT_ACL_RULE_FAILED_RE]
    try:
        logger.info("Creating ACL rules in STRESS_ACL")
        with loganalyzer:
            rand_selected_dut.shell(cmd_add_rules)
    except LogAnalyzerError as err:
        # Cleanup Config DB if failed
        logger.error("ACL rule creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_rm_rules)
        raise err
    yield
    # Remove testing rules
    logger.info("Removing testing ACL rules")
    rand_selected_dut.shell(cmd_rm_rules)


def verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, dst_ip_addr, verity_status):
    acl_nums = 0
    while(acl_nums < ACL_RULE_NUMS):
        acl_nums += 1
        src_ip_addr = "20.0.0.{}".format(acl_nums)
        pkt = testutils.simple_ip_packet(
            eth_dst=rand_selected_dut.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ip_src=src_ip_addr,
            ip_dst=dst_ip_addr,
            ip_proto=47,
            ip_tos=0x84,
            ip_id=0,
            ip_ihl=5,
            ip_ttl=121
        )

        pkt_copy = pkt.copy()
        exp_pkt = mask.Mask(pkt_copy)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, "dst")
        exp_pkt.set_do_not_care_scapy(packet.IP, "ihl")
        exp_pkt.set_do_not_care_scapy(packet.IP, "tos")
        exp_pkt.set_do_not_care_scapy(packet.IP, "len")
        exp_pkt.set_do_not_care_scapy(packet.IP, "id")
        exp_pkt.set_do_not_care_scapy(packet.IP, "flags")
        exp_pkt.set_do_not_care_scapy(packet.IP, "frag")
        exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(packet.IP, "proto")
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")

        ptfadapter.dataplane.flush()
        testutils.send(test=ptfadapter, port_id=ptf_src_port, pkt=pkt)
        if verity_status == "forward":
            testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
        elif verity_status == "drop":
            testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)


def test_acl_add_del_stress(rand_selected_dut, tbinfo, ptfadapter, prepare_dst_ip, prepare_test_port,
                            setup_stress_acl_rules, get_function_conpleteness_level,
                            toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811

    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port

    normalized_level = get_function_conpleteness_level
    cmd_add_rules = "sonic-cfggen -j {} -w".format(STRESS_ACL_RULE_JSON_FILE)
    cmd_rm_rules = "acl-loader delete STRESS_ACL"
    if normalized_level is None:
        normalized_level = 'basic'
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]
    wait_time = 2

    verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, prepare_dst_ip, "drop")
    while loop_times > 0:
        logger.info("loop_times: {}".format(loop_times))
        rand_selected_dut.shell(cmd_rm_rules)
        wait(wait_time, "Waiting {} sec acl rules to be removed".format(wait_time))
        verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, prepare_dst_ip, "forward")
        rand_selected_dut.shell(cmd_add_rules)
        wait(wait_time, "Waiting {} sec acl rules to be loaded".format(wait_time))
        verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, prepare_dst_ip, "drop")
        loop_times -= 1

    logger.info("End")
