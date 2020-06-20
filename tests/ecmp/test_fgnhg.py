import pytest
import ptf.testutils as testutils
from collections import defaultdict
from datetime import datetime

import time
import itertools
import logging
import pprint
import ipaddress
import json
from jinja2 import Template
from ptf.mask import Mask
import ptf.packet as scapy
from ptf_runner import ptf_runner

# Constants
NUM_NHs = 8
DEFAULT_VLAN_ID = 1000
DEFAULT_VLAN_IPv4 = ipaddress.ip_network(u'200.200.200.0/28')
DEFAULT_VLAN_IPv6 = ipaddress.ip_network(u'200:200:200:200::/124')
PREFIX_IPv4 = u'100.50.25.12/32'
PREFIX_IPv6 = u'fc:05::/128'
ARP_CFG = '/tmp/arp_cfg.json'
FG_ECMP_CFG = '/tmp/fg_ecmp.json'

logger = logging.getLogger(__name__)

def configure_interfaces(cfg_facts, duthost, ptfhost, ptfadapter, vlan_ip):
    config_port_indices = cfg_facts['port_index_map']
    port_list = []
    eth_port_list = []
    ip_to_port = {}
    bank_0_port = []
    bank_1_port = []

    # remove existing IPs from PTF host
    ptfhost.script('scripts/remove_ip.sh')
    # set unique MACs to PTF interfaces
    ptfhost.script('scripts/change_mac.sh')
    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit()

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
        "bucket_size": 120
    }

    fgnhg_data['FG_NHG_MEMBER'] = {}
    for ip, port in ip_to_port.items():
        bank = 0
        if port in bank_1_port:
            bank = 1
        fgnhg_data['FG_NHG_MEMBER'][ip] = {
            "bank": bank,
            "FG_NHG": fgnhg_name
        }

    fgnhg_data['FG_NHG_PREFIX'] = {}
    fgnhg_data['FG_NHG_PREFIX'][prefix] = {
        "FG_NHG": fgnhg_name
    }

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
            "net_ports": net_ports
    }
    ptfhost.copy(content=json.dumps(fg_ecmp, indent=2), dest=FG_ECMP_CFG)


def setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, vlan_ip, prefix):
    port_list, ip_to_port, bank_0_port, bank_1_port = configure_interfaces(cfg_facts, duthost, ptfhost, ptfadapter, vlan_ip)
    generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port, prefix)
    time.sleep(60)
    setup_neighbors(duthost, ptfhost, ip_to_port)
    create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports, prefix)
    ptfhost.copy(src="ptftests/fg_ecmp_test.py", dest="/root/ptftests")
    return port_list, ip_to_port, bank_0_port, bank_1_port


def fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, prefix):

    if isinstance(ipaddress.ip_network(prefix), ipaddress.IPv4Network):
        ipcmd = "ip route"
    else:
        ipcmd = "ipv6 route"

    for nexthop in ip_to_port:
        duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))
    time.sleep(1)

    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'create_flows',
		    "config_file": FG_ECMP_CFG},
	    qlen=1000,
	    log_file=log_file)

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'initial_hash_check',
		    "config_file": FG_ECMP_CFG},
	    qlen=1000,
	    log_file=log_file) 

    withdraw_nh_port = bank_0_port[1]
    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            duthost.shell("vtysh -c 'configure terminal' -c 'no {} {} {}'".format(ipcmd, prefix, nexthop))

    time.sleep(1)

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'withdraw_nh',
		    "config_file": FG_ECMP_CFG,
                    "withdraw_nh_port": withdraw_nh_port},
	    qlen=1000,
	    log_file=log_file)

    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))

    time.sleep(1)

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'add_nh',
		    "config_file": FG_ECMP_CFG,
                    "add_nh_port": withdraw_nh_port},
	    qlen=1000,
	    log_file=log_file)


    withdraw_nh_bank = bank_0_port
    for nexthop, port in ip_to_port.items():
        if port in withdraw_nh_bank:
            duthost.shell("vtysh -c 'configure terminal' -c 'no {} {} {}'".format(ipcmd, prefix, nexthop))

    time.sleep(1)

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'withdraw_bank',
		    "config_file": FG_ECMP_CFG,
                    "withdraw_nh_bank": withdraw_nh_bank},
	    qlen=1000,
	    log_file=log_file)

    first_nh = bank_0_port[3]
    for nexthop, port in ip_to_port.items():
        if port == first_nh:
            duthost.shell("vtysh -c 'configure terminal' -c '{} {} {}'".format(ipcmd, prefix, nexthop))

    time.sleep(1)

    ptf_runner(ptfhost,
	   "ptftests",
	   "fg_ecmp_test.FgEcmpTest",
	    platform_dir="ptftests",
	    params={"test_case": 'add_first_nh',
		    "config_file": FG_ECMP_CFG,
                    "first_nh": first_nh},
	    qlen=1000,
	    log_file=log_file)


@pytest.mark.bsl
def test_fg_ecmp(ansible_adhoc, testbed, ptfadapter, duthost, ptfhost):
    if testbed['topo']['name'] != 't0':
        pytest.skip("Unsupported topology")

    host_facts  = duthost.setup()['ansible_facts']
    mg_facts   = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    router_mac = host_facts['ansible_Ethernet0']['macaddress']
    net_ports = []
    for name, val in mg_facts['minigraph_portchannels'].items():
        members = [mg_facts['minigraph_port_indices'][member] for member in val['members']]
        net_ports.extend(members)

    # IPv4 test
    port_list, ip_to_port, bank_0_port, bank_1_port = setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv4, PREFIX_IPv4)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, PREFIX_IPv4) 

    # IPv6 test
    port_list, ip_to_port, bank_0_port, bank_1_port = setup_test_config(ptfadapter, duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv6, PREFIX_IPv6)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, PREFIX_IPv6) 
