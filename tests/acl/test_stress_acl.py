import ipaddress
import logging
import math
import random
import pytest
import json
import time
import ptf.testutils as testutils
from ptf import mask, packet
from collections import defaultdict
from ipaddress import ip_address, IPv4Address
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.utilities import wait_until
from tests.common.fixtures.ptfhost_utils import skip_traffic_test  # noqa: F401

pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx", "m1"),
    pytest.mark.device_type('vs')
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
DEL_STRESS_ACL_TABLE_TEMPLATE = "acl/templates/del_acltb_test_stress_acl_table.j2"
DEL_STRESS_ACL_TABLE_JSON_FILE = "/tmp/del_acltb_test_stress_acl_table.json"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_FAILED_RE = ".*Failed to create ACL rule.*"

ACL_RULE_NUMS = 10

DEFAULT_MAX_ACL_ENTRIES = 200

# key: platform name
# value: max number of ACL entries supported by the platform
rules_per_platform = {
    # arista
    '7050CX3': 512,
    '7050-QX': 256,
    '7050QX': 256,
    '7060CX': 256,
    '7060DX5': DEFAULT_MAX_ACL_ENTRIES,
    '7060X6': 767,
    '7170': DEFAULT_MAX_ACL_ENTRIES,
    '7260CX3': 512,
    '7280CR3': DEFAULT_MAX_ACL_ENTRIES,
    '7800R3': DEFAULT_MAX_ACL_ENTRIES,
    # celestica
    'DX010': 256
}


@pytest.fixture(scope="module")
def setup_table_and_rules(rand_selected_dut, prepare_test_port):

    logger.debug('Setting up rules')
    _, _, dut_port = prepare_test_port
    logger.debug(f'dut_port: {dut_port}')
    table_name = 'STRESS_ACL_MANY'

    # Get the max number of ACL entries supported by the platform
    hwsku = rand_selected_dut.facts['hwsku']
    model_str = hwsku.split('-')[1]
    max_acl_entries = rules_per_platform.get(model_str.upper(), DEFAULT_MAX_ACL_ENTRIES)
    logger.debug(f'HwSKU: {hwsku}. Max ACL entries supported by the platform {model_str}: {max_acl_entries}')
    rules = generate_acl_rules(table_name, max_acl_entries)
    f_name = f'generated_acl_rules_{max_acl_entries}.json'
    file_path = f'/tmp/{f_name}'
    with open(file_path, 'w') as f:
        json.dump(rules, f)
    logger.debug(f'Generated ACL rules written to {file_path}')
    # Add table
    cmd_add_table = f'config acl add table {table_name} L3 -s ingress -p {dut_port}'
    rand_selected_dut.shell(cmd_add_table)
    logger.debug('Table created')
    # Copy rules file and add rules
    rand_selected_dut.copy(src=file_path, dest=f'/tmp/{f_name}', mode="0755")
    cmd_add_rules = f'sonic-cfggen -j /tmp/{f_name} -w'
    rand_selected_dut.shell(cmd_add_rules)
    logger.debug('Rules created. Sleep for 1 minute for rules to be active')
    # verify if rules have been setup
    time.sleep(60)
    rules_out = rand_selected_dut.shell(f'show acl rule {table_name}')['stdout_lines']
    logger.debug(f'Installed rules: {rules_out}')
    active_count = 0
    rules_not_installed = []
    for line in rules_out:
        logger.debug(f'line: {line}')
        if 'RULE_' in line:
            if line.split()[-1] == 'Active':
                active_count += 1
            else:
                rules_not_installed.append(line)
    logger.debug(f'Number of active rules: {active_count}')
    if active_count != len(rules['ACL_RULE']):
        logger.debug('Warning: Some ACL rules did not install succesfully')
        pytest.fail(f'List of rules not installed: {rules_not_installed}')
    logger.info("Setup of ACL table for stress test done")

    yield rules['ACL_RULE']

    cmd_del_rules = f"acl-loader delete {table_name}"
    rand_selected_dut.shell(cmd_del_rules)
    cmd_del_table = f"config acl remove table {table_name}"
    rand_selected_dut.shell(cmd_del_table)


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    TABLE_NAME_1 = "DATAACL"
    data_acl_existing_duts = []
    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table {}".format(TABLE_NAME_1))['stdout_lines']
        data_acl_existing = False
        for line in lines:
            if TABLE_NAME_1 in line:
                data_acl_existing = True
                break

        if data_acl_existing:
            # Remove DATAACL
            logger.info("Removing ACL table {}".format(TABLE_NAME_1))
            duthost.shell(cmd="config acl remove table {}".format(TABLE_NAME_1))
            data_acl_existing_duts.append(duthost)

    if not data_acl_existing_duts:
        yield
        return

    yield
    # Recover DATAACL
    config_db_json = "/etc/sonic/config_db.json"
    for duthost in data_acl_existing_duts:
        output = duthost.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
        entry_json = json.loads(output)
        if TABLE_NAME_1 in entry_json:
            entry = entry_json[TABLE_NAME_1]
            cmd_create_table = "config acl add table {} {} -p {} -s {}"\
                .format(TABLE_NAME_1, entry['type'], ",".join(entry['ports']), entry['stage'])
            logger.info("Restoring ACL table {}".format(TABLE_NAME_1))
            duthost.shell(cmd_create_table)


@pytest.fixture(scope='module')
def prepare_test_file(rand_selected_dut):
    # Define a custom table type CUSTOM_TYPE by loading a json configuration
    rand_selected_dut.copy(src=STRESS_ACL_TABLE_TEMPLATE, dest=STRESS_ACL_TABLE_JSON_FILE, mode="0755")
    rand_selected_dut.shell("sonic-cfggen -j {} -w".format(STRESS_ACL_TABLE_JSON_FILE))
    # Copy acl rules
    rand_selected_dut.copy(src=STRESS_ACL_RULE_TEMPLATE, dest=STRESS_ACL_RULE_JSON_FILE, mode="0755")

    yield

    rand_selected_dut.copy(src=DEL_STRESS_ACL_TABLE_TEMPLATE, dest=DEL_STRESS_ACL_TABLE_JSON_FILE)
    rand_selected_dut.shell("configlet -d -j {}".format(DEL_STRESS_ACL_TABLE_JSON_FILE))
    rand_selected_dut.shell("rm -f {}".format(DEL_STRESS_ACL_TABLE_JSON_FILE))


@pytest.fixture(scope='module')
def prepare_test_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    ports = list(mg_facts['minigraph_portchannels'])
    if not ports:
        ports = mg_facts["minigraph_acls"]["DataAcl"]

    dut_port = ports[0] if ports else None

    if not dut_port:
        pytest.skip('No portchannels nor dataacl ports found')
    if "Ethernet" in dut_port:
        dut_eth_port = dut_port
    elif "PortChannel" in dut_port:
        dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    topo = tbinfo["topo"]["type"]
    topo_name = tbinfo["topo"]["name"]
    # Get the list of upstream ports
    upstream_ports = defaultdict(list)
    upstream_port_ids = []
    upstream_port_neighbor_ips = {}
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T2" in neighbor["name"]) or \
                (topo == "t0" and ("T1" in neighbor["name"] or "PT0" in neighbor["name"])) or \
                (topo == "m0" and "M1" in neighbor["name"]) or (topo == "mx" and "M0" in neighbor["name"]) or \
                (topo == "m1" and ("MA" in neighbor["name"] or "MB" in neighbor["name"])) or \
                (topo_name in ("t1-isolated-d32", "t1-isolated-d128") and "T0" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)
            ipv4_addr = [bgp_neighbor['addr'] for bgp_neighbor in mg_facts['minigraph_bgp']
                         if bgp_neighbor['name'] == neighbor["name"] and
                         isinstance(ip_address(bgp_neighbor['addr']), IPv4Address)][0]
            upstream_port_neighbor_ips[interface] = ipv4_addr

    dst_ip_addr = None
    if tbinfo["topo"]['name'] in ["t1-isolated-d28u1", "t1-isolated-d56u2", "t1-isolated-d448u15-lag",
                                  "t1-isolated-d56u1-lag", "t1-f2-d10u8"] or topo == "m1":
        dst_ip_addr = random.choices(list(upstream_port_neighbor_ips.values()))
    return ptf_src_port, upstream_port_ids, dut_port, dst_ip_addr


def verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                     acl_rule_list, del_rule_id, verity_status, dst_ip_addr=None):

    for acl_id in acl_rule_list:
        ip_addr1 = acl_id % 256
        ip_addr2 = int(acl_id / 256)

        src_ip_addr = "20.0.{}.{}".format(ip_addr2, ip_addr1)
        if not dst_ip_addr:
            dst_ip_addr = "10.0.0.1"
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
        pkt_copy.ttl = pkt_copy.ttl - 1
        exp_pkt = mask.Mask(pkt_copy)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")

        ptfadapter.dataplane.flush()
        testutils.send(test=ptfadapter, port_id=ptf_src_port, pkt=pkt)
        if verity_status == "forward" or acl_id == del_rule_id:
            testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
        elif verity_status == "drop" and acl_id != del_rule_id:
            testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)


def acl_rule_loaded(rand_selected_dut, acl_rule_list):
    acl_rule_infos = rand_selected_dut.show_and_parse("show acl rule")
    acl_id_list = []
    for acl_info in acl_rule_infos:
        acl_id = int(acl_info['rule'][len('RULE_'):])
        acl_id_list.append(acl_id)
    if sorted(acl_id_list) != sorted(acl_rule_list):
        return False
    return True


def test_acl_add_del_stress(rand_selected_dut, tbinfo, ptfadapter, prepare_test_file,
                            prepare_test_port, get_function_completeness_level,
                            toggle_all_simulator_ports_to_rand_selected_tor):   # noqa: F811

    ptf_src_port, ptf_dst_ports, dut_port, dst_ip_addr = prepare_test_port

    cmd_create_table = "config acl add table STRESS_ACL L3 -s ingress -p {}".format(dut_port)
    cmd_remove_table = "config acl remove table STRESS_ACL"
    cmd_add_rules = "sonic-cfggen -j {} -w".format(STRESS_ACL_RULE_JSON_FILE)
    cmd_rm_all_rules = "acl-loader delete STRESS_ACL"

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]
    wait_timeout = 15

    rand_selected_dut.shell(cmd_create_table)
    acl_rule_list = list(range(1, ACL_RULE_NUMS + 1))
    verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                     acl_rule_list, 0, "forward", dst_ip_addr=dst_ip_addr)
    try:
        loops = 0
        while loops <= loop_times:
            logger.info("loops: {}".format(loops))
            if loops == 0:
                rand_selected_dut.shell(cmd_add_rules)
            else:
                readd_id = loops + ACL_RULE_NUMS
                ip_addr1 = readd_id % 256
                ip_addr2 = int(readd_id / 256)
                rand_selected_dut.shell('sonic-db-cli CONFIG_DB hset "ACL_RULE|STRESS_ACL| RULE_{}" \
                                        "SRC_IP" "20.0.{}.{}/32" "PACKET_ACTION" "DROP" "PRIORITY" "{}"'
                                        .format(readd_id, ip_addr2, ip_addr1, readd_id))
                acl_rule_list.append(readd_id)

            wait_until(wait_timeout, 2, 0, acl_rule_loaded, rand_selected_dut, acl_rule_list)
            verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                             acl_rule_list, 0, "drop", dst_ip_addr=dst_ip_addr)

            del_rule_id = random.choice(acl_rule_list)
            rand_selected_dut.shell('sonic-db-cli CONFIG_DB del "ACL_RULE|STRESS_ACL| RULE_{}"'.format(del_rule_id))
            acl_rule_list.remove(del_rule_id)

            wait_until(wait_timeout, 2, 0, acl_rule_loaded, rand_selected_dut, acl_rule_list)
            verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                             acl_rule_list, del_rule_id, "drop", dst_ip_addr=dst_ip_addr)

            loops += 1
    finally:
        rand_selected_dut.shell(cmd_rm_all_rules)
        rand_selected_dut.shell(cmd_remove_table)
        logger.info("End")


########################################
# Stress test with large number of rules
########################################
def tcp_packet(rand_selected_dut, ptfadapter, ip_version,
               src_ip, dst_ip, proto, dport, sport=54321, flags=None):
    """Generate a TCP packet for testing."""
    if ip_version == "ipv4":
        pkt = testutils.simple_tcp_packet(
            eth_dst=rand_selected_dut.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0]),
            ip_dst=dst_ip,
            ip_src=src_ip,
            tcp_sport=int(sport),
            tcp_dport=int(dport),
            ip_ttl=64,
            tcp_flags=""
        )
        if proto:
            pkt["IP"].proto = int(proto)
    else:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=rand_selected_dut.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0]),
            ipv6_dst=dst_ip,
            ipv6_src=src_ip,
            tcp_sport=int(sport),
            tcp_dport=int(dport),
            ipv6_hlim=64
        )
        if proto:
            pkt["IPv6"].nh = proto
    if flags:
        flag_val = ''
        prefix_len = len('TCP_')
        for f in flags:
            flag_val += f[prefix_len:prefix_len+1]
        pkt["TCP"].flags = flag_val

    return pkt


def udp_packet(rand_selected_dut, ptfadapter, ip_version,
               src_ip, dst_ip, dport, sport=54321):
    """Generate a UDP packet for testing."""
    if ip_version == "ipv4":
        return testutils.simple_udp_packet(
            eth_dst=rand_selected_dut.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0]),
            ip_dst=dst_ip,
            ip_src=src_ip,
            udp_sport=int(sport),
            udp_dport=int(dport),
            ip_ttl=64
        )
    else:
        return testutils.simple_udpv6_packet(
            eth_dst=rand_selected_dut.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0]),
            ipv6_dst=dst_ip,
            ipv6_src=src_ip,
            udp_sport=int(sport),
            udp_dport=int(dport),
            ipv6_hlim=64
        )


def ip_packet(rand_selected_dut, ptfadapter,
              ip_proto, src_ip, dst_ip, ptf_src_port):
    return testutils.simple_ip_packet(
        eth_dst=rand_selected_dut.facts['router_mac'],
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_proto=ip_proto,
        ip_tos=0x84,
        ip_id=0,
        ip_ihl=5,
        ip_ttl=121
    )


def generate_ipv4_addresses(subnet):
    network = ipaddress.IPv4Network(subnet)
    ip_addresses = [str(ip) for ip in network.hosts()]
    return ip_addresses


def generate_acl_rules(table_name, n_rules):
    # Generate rules with various destination IP addresses
    # based on the subnets below.
    subnets = [
        '192.168.8.0/25',
        '192.168.8.128/25',
        '192.168.16.0/25',
        '192.168.16.128/25',
        '192.168.24.0/25',
        '192.168.24.128/25',
        '193.11.176.0/25',
        '193.11.176.128/25',
        '193.11.184.0/25',
        '193.11.184.128/25',
        '193.11.192.0/25',
        '193.11.192.128/25',
        '193.11.200.0/25',
        '193.11.200.128/25',
        '193.11.208.0/25',
        '193.11.208.128/25',
        '193.11.216.0/25',
        '193.11.216.128/25',
        '193.11.224.0/25',
        '193.11.224.128/25',
        '193.11.232.0/25',
        '193.11.232.128/25',
        '193.11.240.0/25',
        '193.11.240.128/25',
        '193.11.248.0/25',
        '193.11.248.128/25'
    ]
    rules = {}
    rules['ACL_RULE'] = {}
    # /25 subnets have 126 usable IP addresses
    use_n_subnets = math.ceil(n_rules / 126)
    src_ip = '20.0.0.1'  # don't care what it is
    j = 1
    finish = False
    action = 'FORWARD'
    for i in range(use_n_subnets):
        if finish is True:
            break
        subnet = subnets[i]
        ip_addresses = generate_ipv4_addresses(subnet)
        for ip in ip_addresses:
            rule_name = f'{table_name}|RULE_{j}'
            rules['ACL_RULE'][rule_name] = {
                'PACKET_ACTION': action,
                'SRC_IP': src_ip,
                'DST_IP': ip,
                'IP_PROTOCOL': '6',
                'PRIORITY': str(j)
            }
            # toggle actions
            if action == 'FORWARD':
                action = 'DROP'
            if action == 'DROP':
                action = 'FORWARD'
            if j == n_rules:
                finish = True
                break
            j += 1
    return rules


@pytest.mark.stress_test
def test_scale_acl_rules(request, rand_selected_dut, prepare_test_port, tbinfo,  # noqa: F811
                         ptfadapter, setup_table_and_rules,
                         get_function_completeness_level, skip_traffic_test):  # noqa: F811

    if skip_traffic_test:
        return

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    logger.debug('Starting ACL scale test')
    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port
    logger.debug(f'DUT port used in test {dut_port}')
    acl_rules = setup_table_and_rules
    logger.debug(f'Number of rules: {len(acl_rules)}')
    pkt = None
    loop = 0
    while loop < loop_times:
        loop += 1
        for rule_name, rule in acl_rules.items():
            if rule.get('IP_PROTOCOL') == '6':
                dport = rule.get('L4_DST_PORT') if rule.get('L4_DST_PORT') else '12345'
                pkt = tcp_packet(rand_selected_dut=rand_selected_dut,
                                 ptfadapter=ptfadapter,
                                 ip_version='ipv4',
                                 src_ip=rule['SRC_IP'],
                                 dst_ip=rule['DST_IP'],
                                 proto=rule['IP_PROTOCOL'],
                                 dport=dport)
            elif rule.get('IP_PROTOCOL') == '17':
                dport = rule.get('L4_DST_PORT') if rule.get('L4_DST_PORT') else '12345'
                pkt = udp_packet(rand_selected_dut=rand_selected_dut,
                                 ptfadapter=ptfadapter,
                                 ip_version='ipv4',
                                 src_ip=rule['SRC_IP'],
                                 dst_ip=rule['DST_IP'],
                                 dport=dport)
            else:
                pkt = ip_packet(rand_selected_dut=rand_selected_dut,
                                ptfadapter=ptfadapter,
                                ip_proto=47,
                                src_ip=rule['SRC_IP'],
                                dst_ip=rule['DST_IP'],
                                ptf_src_port=ptf_src_port)

            pkt_copy = pkt.copy()
            pkt_copy.ttl = pkt_copy.ttl - 1
            exp_pkt = mask.Mask(pkt_copy)
            exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
            exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
            exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
            ptfadapter.dataplane.flush()
            testutils.send(test=ptfadapter, port_id=ptf_src_port, pkt=pkt)
            if rule['PACKET_ACTION'] == 'FORWARD':
                testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
            elif rule['PACKET_ACTION'] == 'DROP':
                testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
