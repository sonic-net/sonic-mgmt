import logging
import random
import pytest
import json
import ptf.testutils as testutils
from ptf import mask, packet
from collections import defaultdict
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.utilities import wait_until
from tests.common.fixtures.ptfhost_utils import skip_traffic_test   # noqa F401

pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx"),
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
STRESS_ACL_READD_RULE_TEMPLATE = "acl/templates/acltb_test_stress_acl_readd_rules.j2"
DEL_STRESS_ACL_TABLE_TEMPLATE = "acl/templates/del_acltb_test_stress_acl_table.j2"
STRESS_ACL_TABLE_JSON_FILE = "/tmp/acltb_test_stress_acl_table.json"
STRESS_ACL_RULE_JSON_FILE = "/tmp/acltb_test_stress_acl_rules.json"
DEL_STRESS_ACL_TABLE_JSON_FILE = "/tmp/del_acltb_test_stress_acl_table.json"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_FAILED_RE = ".*Failed to create ACL rule.*"

ACL_RULE_NUMS = 10


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts, rand_selected_dut):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    TABLE_NAME_1 = "DATAACL"
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
            rand_selected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME_1))

    if not data_acl_existing:
        yield
        return

    yield
    # Recover DATAACL
    config_db_json = "/etc/sonic/config_db.json"
    output = rand_selected_dut.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
    entry_json = json.loads(output)
    if TABLE_NAME_1 in entry_json:
        entry = entry_json[TABLE_NAME_1]
        cmd_create_table = "config acl add table {} {} -p {} -s {}"\
            .format(TABLE_NAME_1, entry['type'], ",".join(entry['ports']), entry['stage'])
        logger.info("Restoring ACL table {}".format(TABLE_NAME_1))
        rand_selected_dut.shell(cmd_create_table)


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

    topo = tbinfo["topo"]["type"]
    # Get the list of upstream ports
    upstream_ports = defaultdict(list)
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]) or \
                (topo == "m0" and "M1" in neighbor["name"]) or (topo == "mx" and "M0" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)

    return ptf_src_port, upstream_port_ids, dut_port


def verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                     acl_rule_list, del_rule_id, verity_status, skip_traffic_test):     # noqa F811

    for acl_id in acl_rule_list:
        ip_addr1 = acl_id % 256
        ip_addr2 = int(acl_id / 256)

        src_ip_addr = "20.0.{}.{}".format(ip_addr2, ip_addr1)
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

        if not skip_traffic_test:
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
                            prepare_test_port, get_function_conpleteness_level,
                            toggle_all_simulator_ports_to_rand_selected_tor, skip_traffic_test):   # noqa F811

    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port

    cmd_create_table = "config acl add table STRESS_ACL L3 -s ingress -p {}".format(dut_port)
    cmd_remove_table = "config acl remove table STRESS_ACL"
    cmd_add_rules = "sonic-cfggen -j {} -w".format(STRESS_ACL_RULE_JSON_FILE)
    cmd_rm_all_rules = "acl-loader delete STRESS_ACL"

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'basic'
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]
    wait_timeout = 15

    rand_selected_dut.shell(cmd_create_table)
    acl_rule_list = list(range(1, ACL_RULE_NUMS + 1))
    verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                     acl_rule_list, 0, "forward", skip_traffic_test)
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
                             acl_rule_list, 0, "drop", skip_traffic_test)

            del_rule_id = random.choice(acl_rule_list)
            rand_selected_dut.shell('sonic-db-cli CONFIG_DB del "ACL_RULE|STRESS_ACL| RULE_{}"'.format(del_rule_id))
            acl_rule_list.remove(del_rule_id)

            wait_until(wait_timeout, 2, 0, acl_rule_loaded, rand_selected_dut, acl_rule_list)
            verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports,
                             acl_rule_list, del_rule_id, "drop", skip_traffic_test)

            loops += 1
    finally:
        rand_selected_dut.shell(cmd_rm_all_rules)
        rand_selected_dut.shell(cmd_remove_table)
        logger.info("End")
