# Summary: Inner packet hashing test for Fine Grained ECMP next-hops.
#          This is a MSFT internal ONLY test because it contains proprietary Service Tunnel packet format
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> -u -m group -e --skip_sanity -l info -c ecmp/inner_hashing/test_fgnhg_inner_hashing_internal.py

import pytest
from datetime import datetime

import time
import logging
import ipaddress
import json
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.errors import RunAnsibleModuleFail

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

# Constants
NUM_NHs = 12
DEFAULT_VLAN_ID = 1000
DEFAULT_VLAN_IPv4 = ipaddress.ip_network(u'200.200.200.0/28')
DEFAULT_VLAN_IPv6 = ipaddress.ip_network(u'200:200:200:200::/124')
PREFIX_IPv4 = u'100.50.25.12/32'
PREFIX_IPv6 = u'fc:05::/128'
ARP_CFG = '/tmp/arp_cfg.json'
FG_ECMP_CFG = '/tmp/fg_ecmp.json'
NUM_FLOWS = 1000

VXLAN_PORT = 13330
DUT_VXLAN_PORT_JSON_FILE = '/tmp/vxlan.switch.json'

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]

logger = logging.getLogger(__name__)

TABLE_NAME = "pbh_table"
TABLE_DESCRIPTION = "NVGRE-ST/NVGRE and VxLAN"
HASH_NAME = "inner_hash"
VXLAN_RULE_PRIO = "1"
NVGRE_RULE_PRIO = "2"
NVGRE_ST_PRIO = "3"
ECMP_PACKET_ACTION = "SET_ECMP_HASH"
V4_ETHER_TYPE = "0x0800"
V6_ETHER_TYPE = "0x86dd"
VXLAN_IP_PROTOCOL = "0x11"
NVGRE_IP_PROTOCOL = "0x2f"
GRE_KEY = "0x6400"
GRE_MASK = "0xffffff00"
IPV4_OPTION = " --ip-protocol {}"
IPV6_OPTION = " --ipv6-next-header {}"
VXLAN_L4_DST_PORT = hex(VXLAN_PORT)
VXLAN_L4_DST_PORT_OPTION = " --l4-dst-port {}".format(VXLAN_L4_DST_PORT)
NVGRE_GRE_KEY_OPTION = " --gre-key {}/{}".format(GRE_KEY, GRE_MASK)
ADD_PBH_TABLE_CMD = "sudo config pbh table add '{}' --interface-list '{}' --description '{}'"
ADD_PBH_RULE_BASE_CMD = "sudo config pbh rule add '{}' '{}' --priority '{}' --ether-type {}" \
                        " --inner-ether-type '{}' --hash '{}' --packet-action '{}' --flow-counter 'DISABLED'"
ADD_PBH_HASH_CMD = "sudo config pbh hash add '{}' --hash-field-list '{}'"
ADD_PBH_HASH_FIELD_CMD = "sudo config pbh hash-field add '{}' --hash-field '{}' --sequence-id '{}'"

PBH_HASH_FIELD_LIST = "inner_ip_proto," \
                      "inner_l4_dst_port,inner_l4_src_port," \
                      "inner_dst_ipv4,inner_src_ipv4," \
                      "inner_dst_ipv6,inner_src_ipv6"
HASH_FIELD_CONFIG = {
    "inner_dst_ipv4": {"field": "INNER_DST_IPV4", "sequence": "1", "mask": "255.255.255.255"},
    "inner_src_ipv4": {"field": "INNER_SRC_IPV4", "sequence": "1", "mask": "255.255.255.255"},
    "inner_src_ipv6": {"field": "INNER_SRC_IPV6", "sequence": "2", "mask": "::ffff:ffff"},
    "inner_dst_ipv6": {"field": "INNER_DST_IPV6", "sequence": "2", "mask": "::ffff:ffff"},
    "inner_l4_dst_port": {"field": "INNER_L4_DST_PORT", "sequence": "3"},
    "inner_l4_src_port": {"field": "INNER_L4_SRC_PORT", "sequence": "3"},
    "inner_ip_proto": {"field": "INNER_IP_PROTOCOL", "sequence": "4"},
}


def configure_interfaces(cfg_facts, duthost, ptfhost, vlan_ip):
    config_port_indices = cfg_facts['port_index_map']
    port_list = []
    eth_port_list = []
    ip_to_port = {}
    bank_0_port = []
    bank_1_port = []
    global ptf_to_dut_port_map

    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    index = 0
    for vlan in cfg_facts['VLAN_MEMBER'].keys():
        vlan_id = vlan[4:]
        DEFAULT_VLAN_ID = int(vlan_id)
        if len(port_list) == NUM_NHs:
            break
        for port in vlan_members[vlan]:
            if len(port_list) == NUM_NHs:
                break
            ptf_port_id = config_port_indices[port]
            port_list.append(ptf_port_id)
            eth_port_list.append(port)
            index = index + 1

    port_list.sort()
    bank_0_port = port_list[:len(port_list)/2]
    bank_1_port = port_list[len(port_list)/2:]

    # Create vlan if
    duthost.command('config interface ip add Vlan' + str(DEFAULT_VLAN_ID) + ' ' + str(vlan_ip))

    for index, ip in enumerate(vlan_ip.hosts()):
        if len(ip_to_port) == NUM_NHs:
            break
        ip_to_port[str(ip)] = port_list[index]

    return port_list, ip_to_port, bank_0_port, bank_1_port, eth_port_list


def configure_switch_vxlan_cfg(duthost):
    vxlan_switch_config = [{
        "SWITCH_TABLE:switch": {
            "vxlan_port": VXLAN_PORT
        },
        "OP": "SET"
    }]

    logger.info("Copying vxlan.switch.json with data: " + str(vxlan_switch_config))

    duthost.copy(content=json.dumps(vxlan_switch_config, indent=4), dest=DUT_VXLAN_PORT_JSON_FILE)
    duthost.shell("docker cp {} swss:/vxlan.switch.json".format(DUT_VXLAN_PORT_JSON_FILE))
    duthost.shell("docker exec swss sh -c \"swssconfig /vxlan.switch.json\"")


def configure_static_pbh(duthost):
    device_metadata = {}

    device_metadata['DEVICE_METADATA'] = {}
    device_metadata['DEVICE_METADATA']['localhost'] = {
        "resource_type": "FPGASTP"
    }

    logger.info("static pbh programmed to DUT " + str(device_metadata))
    duthost.copy(content=json.dumps(device_metadata, indent=2), dest="/tmp/device_metadata.json")
    duthost.shell("sonic-cfggen -j /tmp/device_metadata.json --write-to-db")
    
    #Persist it so that we can re-init dut with pbh enabled
    duthost.shell("sudo config save -y")

    config_reload(duthost, config_source='config_db', safe_reload=True)


def generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix):
    if isinstance(ipaddress.ip_network(prefix), ipaddress.IPv4Network):
        fgnhg_name = 'fgnhg_v4'
    else:
        fgnhg_name = 'fgnhg_v6'

    fgnhg_data = {}

    fgnhg_data['FG_NHG'] = {}
    fgnhg_data['FG_NHG'][fgnhg_name] = {
        "bucket_size": 125,
        "match_mode": "nexthop-based"
    }

    fgnhg_data['FG_NHG_MEMBER'] = {}
    for ip, port in ip_to_port.items():
        bank = "0"
        if port in bank_1_port:
            bank = "1"
        fgnhg_data['FG_NHG_MEMBER'][ip] = {
            "bank": bank,
            "FG_NHG": fgnhg_name
        }

    logger.info("fgnhg entries programmed to DUT " + str(fgnhg_data))
    duthost.copy(content=json.dumps(fgnhg_data, indent=2), dest="/tmp/fgnhg.json")
    duthost.shell("sonic-cfggen -j /tmp/fgnhg.json --write-to-db")


def setup_neighbors(duthost, ptfhost, ip_to_port):
    vlan_name = "Vlan"+ str(DEFAULT_VLAN_ID)
    neigh_entries = {}
    neigh_entries['NEIGH'] = {}

    for ip, port in ip_to_port.items():

        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
            neigh_entries['NEIGH'][vlan_name + "|" + ip] = {
                "neigh": ptfhost.shell("cat /sys/class/net/eth" + str(port) + "/address")["stdout_lines"][0],
                "family": "IPv4"
            }
        else:
            neigh_entries['NEIGH'][vlan_name + "|" + ip] = {
                "neigh": ptfhost.shell("cat /sys/class/net/eth" + str(port) + "/address")["stdout_lines"][0],
                "family": "IPv6"
            }

    logger.info("neigh entries programmed to DUT " + str(neigh_entries))
    duthost.copy(content=json.dumps(neigh_entries, indent=2), dest="/tmp/neigh.json")
    duthost.shell("sonic-cfggen -j /tmp/neigh.json --write-to-db")


def create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports, prefix):
    fg_ecmp = {
            "port_list": port_list,
            "bank_0_port": bank_0_port,
            "bank_1_port": bank_1_port,
            "dut_mac": router_mac,
            "net_ports": net_ports,
            "num_flows": NUM_FLOWS 
    }

    logger.info("fg_ecmp config sent to PTF: " + str(fg_ecmp))
    ptfhost.copy(content=json.dumps(fg_ecmp, indent=2), dest=FG_ECMP_CFG)


def configure_fgnhg(duthost, ptfhost, cfg_facts, router_mac, net_ports, vlan_ip, prefix):
    port_list, ip_to_port, bank_0_port, bank_1_port, eth_port_list = configure_interfaces(cfg_facts, duthost, ptfhost, vlan_ip)
    generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix)
    time.sleep(60)
    setup_neighbors(duthost, ptfhost, ip_to_port)
    create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports, prefix)
    return port_list, ip_to_port, bank_0_port, bank_1_port, eth_port_list


def cleanup(duthost):
    logger.info("Cleanup after test...")
    config_reload(duthost, config_source='minigraph', safe_reload=True)


def config_pbh(duthost, intf_list):
    config_hash_fields(duthost)
    config_hash(duthost)
    config_pbh_table(duthost, intf_list)
    config_rules(duthost)


def config_hash_fields(duthost):
    logging.info("Create PBH hash-fields")
    for hash_field, hash_field_params_dict in list(HASH_FIELD_CONFIG.items()):
        cmd = get_hash_field_add_cmd(hash_field, hash_field_params_dict)
        duthost.command(cmd)


def get_hash_field_add_cmd(hash_field_name, hash_field_params_dict):
    cmd = ADD_PBH_HASH_FIELD_CMD.format(hash_field_name,
                                        hash_field_params_dict["field"],
                                        hash_field_params_dict["sequence"])
    if "mask" in hash_field_params_dict:
        cmd += " --ip-mask '{}'".format(hash_field_params_dict["mask"])
    return cmd


def config_hash(duthost):
    logging.info("Create PBH hash: {}".format(HASH_NAME))
    duthost.command(ADD_PBH_HASH_CMD.format(HASH_NAME, PBH_HASH_FIELD_LIST))


def config_pbh_table(duthost, intf_list):
    logging.info("Create PBH table: {}".format(TABLE_NAME))
    duthost.command(ADD_PBH_TABLE_CMD.format(TABLE_NAME,
                                             ",".join(intf_list),
                                             TABLE_DESCRIPTION))

def config_rules(duthost):
    logging.info("Create PBH rules")
    config_rule(duthost, "nvgre_st", NVGRE_ST_PRIO, V4_ETHER_TYPE, IPV4_OPTION, NVGRE_IP_PROTOCOL, V6_ETHER_TYPE, NVGRE_GRE_KEY_OPTION)
    config_rule(duthost, "nvgre_v4", NVGRE_RULE_PRIO, V4_ETHER_TYPE, IPV4_OPTION, NVGRE_IP_PROTOCOL, V4_ETHER_TYPE)
    config_rule(duthost, "nvgre_v6", NVGRE_RULE_PRIO, V6_ETHER_TYPE, IPV6_OPTION, NVGRE_IP_PROTOCOL, V4_ETHER_TYPE)
    config_rule(duthost, "vxlan_v4", VXLAN_RULE_PRIO, V4_ETHER_TYPE, IPV4_OPTION, VXLAN_IP_PROTOCOL, V4_ETHER_TYPE, VXLAN_L4_DST_PORT_OPTION)
    config_rule(duthost, "vxlan_v6", VXLAN_RULE_PRIO, V6_ETHER_TYPE, IPV6_OPTION, VXLAN_IP_PROTOCOL, V4_ETHER_TYPE, VXLAN_L4_DST_PORT_OPTION)

def config_rule(duthost, rule_name, rule_priority, ether_type, ip_ver_option, ip_ver_value, inner_ether_type, hash_option=""):
    logging.info("Create PBH rule: {}".format(rule_name))
    duthost.command((ADD_PBH_RULE_BASE_CMD + ip_ver_option + hash_option)
                    .format(TABLE_NAME,
                            rule_name,
                            rule_priority,
                            ether_type,
                            inner_ether_type,
                            HASH_NAME,
                            ECMP_PACKET_ACTION,
                            ip_ver_value))


@pytest.fixture(scope="module")
def common_setup_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    try:
        mg_facts   = duthost.get_extended_minigraph_facts(tbinfo)
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        router_mac = duthost.facts['router_mac']
        net_ports = []
        port_channels = []

        for name, val in mg_facts['minigraph_portchannels'].items():
            #add name into port_channels
            port_channels.append(name)
            members = [mg_facts['minigraph_ptf_indices'][member] for member in val['members']]
            net_ports.extend(members)

        # configure vxlan
        configure_switch_vxlan_cfg(duthost)

        # IPv4 config
        port_list, ipv4_to_port, _, _, eth_port_list = configure_fgnhg(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv4, PREFIX_IPv4)

        # IPv6 config
        port_list, ipv6_to_port, _, _, _, = configure_fgnhg(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv6, PREFIX_IPv6)

        #log combine of eth_port_list and port_channels which are interfaces to be used for dynamic pbh
        logger.info("Interfaces to be used for dynamic pbh: " + str(eth_port_list + port_channels))

        release = duthost.os_version
        if release is not None and release < '202205':
            logger.info("release version does not support dynamic pbh, configure static pbh")
            # configure Static PBH
            configure_static_pbh(duthost)
        else:
            # configure Dynamic PBH
            logger.info("release version supports dynamic pbh, configure dynamic pbh")
            config_pbh(duthost, eth_port_list + port_channels)

        yield duthost, port_list, ipv4_to_port, ipv6_to_port

    finally:
        cleanup(duthost)


def test_fg_inner_hash(common_setup_teardown, ptfhost):
    duthost, port_list, ipv4_to_port, ipv6_to_port = common_setup_teardown

    for nexthop in ipv4_to_port:
        duthost.shell("vtysh -c 'configure terminal' -c 'ip route {} {}'".format(PREFIX_IPv4, nexthop))

    for nexthop in ipv6_to_port:
        duthost.shell("vtysh -c 'configure terminal' -c 'ipv6 route {} {}'".format(PREFIX_IPv6, nexthop))
    time.sleep(1)

    test_time = str(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.inner_hash_test.log".format(test_time)

    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(port_list)
    for port in port_list:
        exp_flow_count[port] = flows_per_nh

    ptf_runner(ptfhost,
            "ptftests",
            "inner_hash_test_internal",
            platform_dir="ptftests",
            params={
                "config_file": FG_ECMP_CFG,
                "exp_flow_count": exp_flow_count,
                "outer_dst_ipv4": PREFIX_IPv4.split('/')[0],
                "outer_dst_ipv6": PREFIX_IPv6.split('/')[0],
                "vxlan_port": VXLAN_PORT},
            qlen=1000,
            log_file=log_file,
            is_python3=True)
