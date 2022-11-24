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
DEFAULT_VLAN_IPv4 = ipaddress.ip_network('200.200.200.0/28')
DEFAULT_VLAN_IPv6 = ipaddress.ip_network('200:200:200:200::/124')
PREFIX_IPv4 = '100.50.25.12/32'
PREFIX_IPv6 = 'fc:05::/128'
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
    for vlan in list(cfg_facts['VLAN_MEMBER'].keys()):
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

    return port_list, ip_to_port, bank_0_port, bank_1_port


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
    for ip, port in list(ip_to_port.items()):
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

    for ip, port in list(ip_to_port.items()):

        if isinstance(ipaddress.ip_address(ip.decode('utf8')), ipaddress.IPv4Address):
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


def setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, vlan_ip, prefix):
    port_list, ip_to_port, bank_0_port, bank_1_port = configure_interfaces(cfg_facts, duthost, ptfhost, vlan_ip)
    generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix)
    time.sleep(60)
    setup_neighbors(duthost, ptfhost, ip_to_port)
    create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports, prefix)
    return port_list, ip_to_port, bank_0_port, bank_1_port


def cleanup(duthost):
    logger.info("Cleanup after test...")
    config_reload(duthost, config_source='minigraph', safe_reload=True)


@pytest.fixture(scope="module")
def common_setup_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    try:
        mg_facts   = duthost.get_extended_minigraph_facts(tbinfo)
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        router_mac = duthost.facts['router_mac']
        net_ports = []
        for name, val in list(mg_facts['minigraph_portchannels'].items()):
            members = [mg_facts['minigraph_ptf_indices'][member] for member in val['members']]
            net_ports.extend(members)

        # configure Static PBH
        configure_static_pbh(duthost)

        # configure vxlan
        configure_switch_vxlan_cfg(duthost)

        # IPv4 config
        port_list, ipv4_to_port, _, _ = setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv4, PREFIX_IPv4)

        # IPv6 config
        port_list, ipv6_to_port, _, _ = setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv6, PREFIX_IPv6)

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
