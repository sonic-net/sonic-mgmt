import pytest
from datetime import datetime

import time
import logging
import ipaddress
import json
from tests.ptf_runner import ptf_runner
from tests.common import config_reload

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

# Constants
NUM_NHs = 8
DEFAULT_VLAN_ID = 1000
DEFAULT_VLAN_IPv4 = ipaddress.ip_network(u'200.200.200.0/28')
DEFAULT_VLAN_IPv6 = ipaddress.ip_network(u'200:200:200:200::/124')
PREFIX_IPv4 = u'100.50.25.12/32'
PREFIX_IPv6 = u'fc:05::/128'
ARP_CFG = '/tmp/arp_cfg.json'
FG_ECMP_CFG = '/tmp/fg_ecmp.json'
USE_INNER_HASHING = False
NUM_FLOWS = 1000

SUPPORTED_TOPO = ['t0']
SUPPORTED_PLATFORMS = ['mellanox']

logger = logging.getLogger(__name__)

def configure_interfaces(cfg_facts, duthost, ptfhost, ptfadapter, vlan_ip):
    config_port_indices = cfg_facts['port_index_map']
    port_list = []
    eth_port_list = []
    ip_to_port = {}
    bank_0_port = []
    bank_1_port = []

    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    print vlan_members
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

    return port_list, ip_to_port, bank_0_port, bank_1_port


def generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix):
    if isinstance(ipaddress.ip_network(prefix), ipaddress.IPv4Network):
        fgnhg_name = 'fgnhg_v4'
    else:
        fgnhg_name = 'fgnhg_v6'

    fgnhg_data = {}

    fgnhg_data['FG_NHG'] = {}
    fgnhg_data['FG_NHG'][fgnhg_name] = {
        "bucket_size": 125
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

    fgnhg_data['FG_NHG_PREFIX'] = {}
    fgnhg_data['FG_NHG_PREFIX'][prefix] = {
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
            "ip_to_port": ip_to_port,
            "port_list": port_list,
            "bank_0_port": bank_0_port,
            "bank_1_port": bank_1_port,
            "dut_mac": router_mac,
            "dst_ip": prefix.split('/')[0],
            "net_ports": net_ports,
            "inner_hashing": USE_INNER_HASHING,
            "num_flows": NUM_FLOWS 
    }

    logger.info("fg_ecmp config sent to PTF: " + str(fg_ecmp))
    ptfhost.copy(content=json.dumps(fg_ecmp, indent=2), dest=FG_ECMP_CFG)


def setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, vlan_ip, prefix):
    port_list, ip_to_port, bank_0_port, bank_1_port = configure_interfaces(cfg_facts, duthost, ptfhost, ptfadapter, vlan_ip)
    generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix)
    time.sleep(60)
    setup_neighbors(duthost, ptfhost, ip_to_port)
    create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports, prefix)
    return port_list, ip_to_port, bank_0_port, bank_1_port


def fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, prefix):

    if isinstance(ipaddress.ip_network(prefix), ipaddress.IPv4Network):
        ipcmd = "ip route"
    else:
        ipcmd = "ipv6 route"

    for nexthop in ip_to_port:
        duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))
    time.sleep(1)

    test_time = str(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.create_flows.log".format(test_time)

    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(port_list)
    for port in port_list:
        exp_flow_count[port] = flows_per_nh

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'create_flows',
                "exp_flow_count": exp_flow_count,
                "config_file": FG_ECMP_CFG},
            qlen=1000,
            log_file=log_file)


    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.initial_hash_check.log".format(test_time)

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'initial_hash_check',
                "exp_flow_count": exp_flow_count,
                "config_file": FG_ECMP_CFG},
            qlen=1000,
            log_file=log_file) 

    exp_flow_count = {}
    flows_for_withdrawn_nh_bank = (NUM_FLOWS/2)/(len(bank_0_port) - 1)
    withdraw_nh_port = bank_0_port[1]
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh
    for port in bank_0_port:
        if port != withdraw_nh_port:
            exp_flow_count[port] = flows_for_withdrawn_nh_bank

    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            duthost.shell("vtysh -c 'configure terminal' -c 'no {} {} {}'".format(ipcmd, prefix, nexthop))


    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.withdraw_nh.log".format(test_time)

    time.sleep(1)

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'withdraw_nh',
                "config_file": FG_ECMP_CFG,
                "exp_flow_count": exp_flow_count,
                "withdraw_nh_port": withdraw_nh_port},
            qlen=1000,
            log_file=log_file)


    exp_flow_count = {}
    for port in port_list:
        exp_flow_count[port] = flows_per_nh

    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))


    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.add_nh.{}.log".format(test_time)

    time.sleep(1)

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'add_nh',
                "config_file": FG_ECMP_CFG,
                "exp_flow_count": exp_flow_count,
                "add_nh_port": withdraw_nh_port},
            qlen=1000,
            log_file=log_file)


    withdraw_nh_bank = bank_0_port
    for nexthop, port in ip_to_port.items():
        if port in withdraw_nh_bank:
            duthost.shell("vtysh -c 'configure terminal' -c 'no {} {} {}'".format(ipcmd, prefix, nexthop))


    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.withdraw_bank.log".format(test_time)

    time.sleep(1)

    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(bank_1_port)
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'withdraw_bank',
                "config_file": FG_ECMP_CFG,
                "exp_flow_count": exp_flow_count,
                "withdraw_nh_bank": withdraw_nh_bank},
            qlen=1000,
            log_file=log_file)

    first_nh = bank_0_port[3]
    for nexthop, port in ip_to_port.items():
        if port == first_nh:
            duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))

    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.add_first_nh.log".format(test_time)

    time.sleep(1)

    exp_flow_count = {}
    flows_per_nh = (NUM_FLOWS/2)/(len(bank_1_port))
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh

    exp_flow_count[first_nh] = NUM_FLOWS/2

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params={"test_case": 'add_first_nh',
                "config_file": FG_ECMP_CFG,
                "exp_flow_count": exp_flow_count,
                "first_nh": first_nh},
            qlen=1000,
            log_file=log_file)


def cleanup(duthost):
    config_reload(duthost)


@pytest.fixture(scope="module")
def common_setup_teardown(tbinfo, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if tbinfo['topo']['name'] not in SUPPORTED_TOPO:
        logger.warning("Unsupported topology, currently supports " + str(SUPPORTED_TOPO))
        pytest.skip("Unsupported topology")
    if duthost.facts["asic_type"] not in SUPPORTED_PLATFORMS:
        logger.warning("Unsupported platform, currently supports " + str(SUPPORTED_PLATFORMS))
        pytest.skip("Unsupported platform")

    try:
        mg_facts   = duthost.get_extended_minigraph_facts(tbinfo)
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        router_mac = duthost.facts['router_mac']
        net_ports = []
        for name, val in mg_facts['minigraph_portchannels'].items():
            members = [mg_facts['minigraph_ptf_indices'][member] for member in val['members']]
            net_ports.extend(members)
        yield duthost, cfg_facts, router_mac, net_ports 

    finally:
        cleanup(duthost)


def test_fg_ecmp(common_setup_teardown, ptfadapter, ptfhost):
    duthost, cfg_facts, router_mac, net_ports = common_setup_teardown

    # IPv4 test
    port_list, ip_to_port, bank_0_port, bank_1_port = setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv4, PREFIX_IPv4)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, PREFIX_IPv4) 

    # IPv6 test
    port_list, ip_to_port, bank_0_port, bank_1_port = setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv6, PREFIX_IPv6)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, PREFIX_IPv6) 
