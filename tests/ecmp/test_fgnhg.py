import pytest

import time
import logging
import ipaddress
import json
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

# Constants
NUM_NHs = 8
DEFAULT_VLAN_ID = 1000
DEFAULT_VLAN_IPv4 = ipaddress.ip_network(u'200.200.200.0/28')
DEFAULT_VLAN_IPv6 = ipaddress.ip_network(u'200:200:200:200::/124')
PREFIX_IPV4_LIST = [u'100.50.25.12/32', u'100.50.25.13/32', u'100.50.25.14/32']
PREFIX_IPV6_LIST = [u'fc:05::/128', u'fc:06::/128', u'fc:07::/128']
FG_ECMP_CFG = '/tmp/fg_ecmp.json'
USE_INNER_HASHING = False
NUM_FLOWS = 1000
ptf_to_dut_port_map = {}

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox'),
    pytest.mark.disable_loganalyzer
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
            ptf_to_dut_port_map[ptf_port_id] = port

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


def generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port):
    if '.' in ip_to_port.keys()[0]:
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
            "link": ptf_to_dut_port_map[port],
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


def create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports):
    fg_ecmp = {
            "serv_ports": port_list,
            "bank_0_port": bank_0_port,
            "bank_1_port": bank_1_port,
            "dut_mac": router_mac,
            "net_ports": net_ports,
            "inner_hashing": USE_INNER_HASHING,
            "num_flows": NUM_FLOWS 
    }

    logger.info("fg_ecmp config sent to PTF: " + str(fg_ecmp))
    ptfhost.copy(content=json.dumps(fg_ecmp, indent=2), dest=FG_ECMP_CFG)


def setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, vlan_ip):
    port_list, ip_to_port, bank_0_port, bank_1_port = configure_interfaces(cfg_facts, duthost, ptfhost, vlan_ip)
    generate_fgnhg_config(duthost, ip_to_port, bank_0_port, bank_1_port)
    time.sleep(60)
    setup_neighbors(duthost, ptfhost, ip_to_port)
    create_fg_ptf_config(ptfhost, ip_to_port, port_list, bank_0_port, bank_1_port, router_mac, net_ports)
    return port_list, ip_to_port, bank_0_port, bank_1_port


def configure_dut(duthost, cmd):
    logger.info("Configuring dut with " + cmd)
    duthost.shell(cmd, executable="/bin/bash")


def partial_ptf_runner(ptfhost, test_case, dst_ip, exp_flow_count, **kwargs):
    log_file = "/tmp/fg_ecmp_test.FgEcmpTest.{}".format(test_case)
    params = {
                "test_case": test_case,
                "dst_ip": dst_ip,
                "exp_flow_count": exp_flow_count,
                "config_file": FG_ECMP_CFG
             }
    params.update(kwargs)

    ptf_runner(ptfhost,
            "ptftests",
            "fg_ecmp_test.FgEcmpTest",
            platform_dir="ptftests",
            params= params,
            qlen=1000,
            log_file=log_file)


def fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, prefix_list):

    # Init base test params
    if isinstance(ipaddress.ip_network(prefix_list[0]), ipaddress.IPv4Network):
        ipcmd = "ip route"
    else:
        ipcmd = "ipv6 route"

    vtysh_base_cmd = "vtysh -c 'configure terminal'"
    vtysh_base_cmd = duthost.get_vtysh_cmd_for_namespace(vtysh_base_cmd, DEFAULT_NAMESPACE)
    dst_ip_list = []
    for prefix in prefix_list:
        dst_ip_list.append(prefix.split('/')[0])

    ### Start test in state where 1 link is down, when nexthop addition occurs for link which is down, the nexthop
    ### should not go to active
    shutdown_link = bank_0_port[0]
    dut_if_shutdown = ptf_to_dut_port_map[shutdown_link]
    logger.info("Initialize test by creating flows and checking basic ecmp, "
                "we start in a state where link " + dut_if_shutdown + " is down")

    configure_dut(duthost, "config interface shutdown " + dut_if_shutdown)
    time.sleep(30)

    # Now add the route and nhs
    for prefix in prefix_list:
        cmd = vtysh_base_cmd
        for nexthop in ip_to_port:
            cmd = cmd + " -c '{} {} {}'".format(ipcmd, prefix, nexthop)
        configure_dut(duthost, cmd)

    time.sleep(3)

    # Calculate expected flow counts per port to verify in ptf host
    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(port_list)
    for port in port_list:
        exp_flow_count[port] = flows_per_nh
        
    flows_to_redist = exp_flow_count[shutdown_link]
    for port in bank_0_port:
        if port != shutdown_link:
            exp_flow_count[port] = exp_flow_count[port] + flows_to_redist/(len(bank_0_port) - 1)
    del exp_flow_count[shutdown_link]

    # Send the packets

    for dst_ip in dst_ip_list:
        partial_ptf_runner(ptfhost, 'create_flows', dst_ip, exp_flow_count)


    ### Hashing verification: Send the same flows again,
    ### and verify packets end up on the same ports for a given flow
    logger.info("Hashing verification: Send the same flows again, "
                "and verify packets end up on the same ports for a given flow")

    for dst_ip in dst_ip_list:
        partial_ptf_runner(ptfhost, 'initial_hash_check', dst_ip, exp_flow_count)


    ### Send the same flows again, but unshut the port which was shutdown at the beginning of test
    ### Check if hash buckets rebalanced as expected
    logger.info("Send the same flows again, but unshut " + dut_if_shutdown + " and check "
                "if flows reblanced as expected and are seen on now brought up link")

    configure_dut(duthost, "config interface startup " + dut_if_shutdown)
    time.sleep(30)

    flows_per_nh = NUM_FLOWS/len(port_list)
    for port in port_list:
        exp_flow_count[port] = flows_per_nh

    for dst_ip in dst_ip_list:
        partial_ptf_runner(ptfhost, 'add_nh', dst_ip, exp_flow_count, add_nh_port=shutdown_link)


    ### Send the same flows again, but withdraw one next-hop before sending the flows, check if hash bucket
    ### rebalanced as expected, and the number of flows received on a link is as expected
    logger.info("Send the same flows again, but withdraw one next-hop before sending the flows, check if hash bucket "
                "rebalanced as expected, and the number of flows received on a link is as expected")

    # Modify and test 1 prefix only for the rest of this test
    dst_ip = dst_ip_list[0]
    prefix = prefix_list[0]

    withdraw_nh_port = bank_0_port[1]
    cmd = vtysh_base_cmd
    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            cmd = cmd + " -c 'no {} {} {}'".format(ipcmd, prefix, nexthop)
    configure_dut(duthost, cmd)
    time.sleep(3)

    flows_for_withdrawn_nh_bank = (NUM_FLOWS/2)/(len(bank_0_port) - 1)
    for port in bank_0_port:
        if port != withdraw_nh_port:
            exp_flow_count[port] = flows_for_withdrawn_nh_bank
    del exp_flow_count[withdraw_nh_port]

    # Validate packets with withdrawn nhs
    partial_ptf_runner(ptfhost, 'withdraw_nh', dst_ip, exp_flow_count, withdraw_nh_port=withdraw_nh_port)
    # Validate that the other 2 prefixes using Fine Grained ECMP were unaffected
    for ip in dst_ip_list:
        if ip == dst_ip: continue
        partial_ptf_runner(ptfhost, 'initial_hash_check', ip, exp_flow_count)


    ### Send the same flows again, but disable one of the links,
    ### and check flow hash redistribution
    shutdown_link = bank_0_port[2]
    dut_if_shutdown = ptf_to_dut_port_map[shutdown_link]
    logger.info("Send the same flows again, but shutdown " + dut_if_shutdown + " and check "
                "the flow hash redistribution")

    configure_dut(duthost, "config interface shutdown " + dut_if_shutdown)
    time.sleep(30)

    flows_for_shutdown_links_bank = (NUM_FLOWS/2)/(len(bank_0_port) - 2)
    for port in bank_0_port:
        if port != withdraw_nh_port and port != shutdown_link:
            exp_flow_count[port] = flows_for_shutdown_links_bank
    del exp_flow_count[shutdown_link]

    partial_ptf_runner(ptfhost, 'withdraw_nh', dst_ip, exp_flow_count, withdraw_nh_port=shutdown_link)


    ### Send the same flows again, but enable the link we disabled the last time
    ### and check flow hash redistribution
    logger.info("Send the same flows again, but startup " + dut_if_shutdown + " and check "
                "the flow hash redistribution")

    configure_dut(duthost, "config interface startup " + dut_if_shutdown)
    time.sleep(30)

    exp_flow_count = {}
    flows_for_withdrawn_nh_bank = (NUM_FLOWS/2)/(len(bank_0_port) - 1)
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh
    for port in bank_0_port:
        if port != withdraw_nh_port:
            exp_flow_count[port] = flows_for_withdrawn_nh_bank

    partial_ptf_runner(ptfhost, 'add_nh', dst_ip, exp_flow_count, add_nh_port=shutdown_link) 


    ### Send the same flows again, but enable the next-hop which was down previously
    ### and check flow hash redistribution
    logger.info("Send the same flows again, but enable the next-hop which was down previously "
                " and check flow hash redistribution")

    cmd = vtysh_base_cmd
    for nexthop, port in ip_to_port.items():
        if port == withdraw_nh_port:
            cmd = cmd + " -c '{} {} {}'".format(ipcmd, prefix, nexthop)
    configure_dut(duthost, cmd)
    time.sleep(3)

    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(port_list)
    for port in port_list:
        exp_flow_count[port] = flows_per_nh

    partial_ptf_runner(ptfhost, 'add_nh', dst_ip, exp_flow_count, add_nh_port=withdraw_nh_port) 


    ### Simulate route and link flap conditions by toggling the route
    ### and ensure that there is no orch crash and data plane impact
    logger.info("Simulate route and link flap conditions by toggling the route "
                "and ensure that there is no orch crash and data plane impact")
    nexthop_to_toggle = ip_to_port.keys()[0]

    cmd = "for i in {1..50}; do "
    cmd = cmd + vtysh_base_cmd
    cmd = cmd + "  -c 'no {} {} {}';".format(ipcmd, prefix, nexthop_to_toggle)
    cmd = cmd + " sleep 0.5;"
    cmd = cmd + vtysh_base_cmd
    cmd = cmd + "  -c '{} {} {}';".format(ipcmd, prefix, nexthop_to_toggle)
    cmd = cmd + " sleep 0.5;"
    cmd = cmd + " done;"

    configure_dut(duthost, cmd)
    time.sleep(30)

    result = duthost.shell(argv=["pgrep", "orchagent"])
    pytest_assert(int(result["stdout"]) > 0, "Orchagent is not running")
    partial_ptf_runner(ptfhost, 'bank_check', dst_ip, exp_flow_count)


    ### Send the same flows again, but disable all next-hops in a bank
    ### to test flow redistribution to the other bank
    logger.info("Send the same flows again, but disable all next-hops in a bank "
                "to test flow redistribution to the other bank")

    withdraw_nh_bank = bank_0_port

    cmd = vtysh_base_cmd
    for nexthop, port in ip_to_port.items():
        if port in withdraw_nh_bank:
            cmd = cmd + " -c 'no {} {} {}'".format(ipcmd, prefix, nexthop)
    configure_dut(duthost, cmd)
    time.sleep(3)

    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(bank_1_port)
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh

    partial_ptf_runner(ptfhost, 'withdraw_bank', dst_ip, exp_flow_count, withdraw_nh_bank=withdraw_nh_bank) 


    ### Send the same flows again, but enable 1 next-hop in a previously down bank to check 
    ### if flows redistribute back to previously down bank
    logger.info("Send the same flows again, but enable 1 next-hop in a previously down bank to check "
                "if flows redistribute back to previously down bank")

    first_nh = bank_0_port[3]

    cmd = vtysh_base_cmd
    for nexthop, port in ip_to_port.items():
        if port == first_nh:
            cmd = cmd + " -c '{} {} {}'".format(ipcmd, prefix, nexthop)
    configure_dut(duthost, cmd)
    time.sleep(3)

    exp_flow_count = {}
    flows_per_nh = (NUM_FLOWS/2)/(len(bank_1_port))
    for port in bank_1_port:
        exp_flow_count[port] = flows_per_nh
    exp_flow_count[first_nh] = NUM_FLOWS/2

    partial_ptf_runner(ptfhost, 'add_first_nh', dst_ip, exp_flow_count, first_nh=first_nh)

    logger.info("Completed ...")


def fg_ecmp_to_regular_ecmp_transitions(ptfhost, duthost, router_mac, net_ports, port_list, ip_to_port, bank_0_port, bank_1_port, prefix_list, cfg_facts):
    logger.info("fg_ecmp_to_regular_ecmp_transitions")
    # Init base test params
    ipv4 = False
    if isinstance(ipaddress.ip_network(prefix_list[0]), ipaddress.IPv4Network):
        ipcmd = "ip route"
        ipv4 = True
    else:
        ipcmd = "ipv6 route"

    vtysh_base_cmd = "vtysh -c 'configure terminal'"
    vtysh_base_cmd = duthost.get_vtysh_cmd_for_namespace(vtysh_base_cmd, DEFAULT_NAMESPACE)
    dst_ip_list = []
    for prefix in prefix_list:
        dst_ip_list.append(prefix.split('/')[0])

    prefix = prefix_list[0]
    dst_ip = dst_ip_list[0]

    logger.info("Transition prefix to non fine grained ecmp and validate packets")

    pc_ips = []
    for ip in cfg_facts['BGP_NEIGHBOR']:
        if ipv4 and '.' in ip:
            pc_ips.append(ip)
        elif not ipv4 and ':' in ip:
            pc_ips.append(ip)

    # Init flows
    exp_flow_count = {}
    flows_per_nh = (NUM_FLOWS)/(len(port_list))
    for port in port_list:
        exp_flow_count[port] = flows_per_nh
    for ip in dst_ip_list:
        if ip == dst_ip: continue
        partial_ptf_runner(ptfhost, 'create_flows', ip, exp_flow_count)

    cmd = vtysh_base_cmd
    for ip in pc_ips:
        cmd = cmd + " -c '{} {} {}'".format(ipcmd, prefix, ip)
    for nexthop in ip_to_port.keys():
        cmd = cmd + " -c 'no {} {} {}'".format(ipcmd, prefix, nexthop)
    configure_dut(duthost, cmd)
    time.sleep(3)

    exp_flow_count = {}
    flows_per_nh = (NUM_FLOWS)/(len(net_ports))
    for port in net_ports:
        exp_flow_count[port] = flows_per_nh

    partial_ptf_runner(ptfhost, 'net_port_hashing', dst_ip, exp_flow_count)

    # Validate that the other 2 prefixes using Fine Grained ECMP were unaffected
    exp_flow_count = {}
    flows_per_nh = (NUM_FLOWS)/(len(port_list))
    for port in port_list:
        exp_flow_count[port] = flows_per_nh
    for ip in dst_ip_list:
        if ip == dst_ip: continue
        partial_ptf_runner(ptfhost, 'initial_hash_check', ip, exp_flow_count)


    ### Transition prefix back to fine grained ecmp and validate packets
    logger.info("Transition prefix back to fine grained ecmp and validate packets")

    cmd = vtysh_base_cmd
    for nexthop in ip_to_port.keys():
        cmd = cmd + " -c '{} {} {}'".format(ipcmd, prefix, nexthop)
    for ip in pc_ips:
        cmd = cmd + " -c 'no {} {} {}'".format(ipcmd, prefix, ip)
    configure_dut(duthost, cmd)
    time.sleep(3)

    partial_ptf_runner(ptfhost, 'create_flows', dst_ip, exp_flow_count)

    # Validate that the other 2 prefixes using Fine Grained ECMP were unaffected
    for ip in dst_ip_list:
        if ip == dst_ip: continue
        partial_ptf_runner(ptfhost, 'initial_hash_check', ip, exp_flow_count)


def cleanup(duthost, ptfhost):
    logger.info("Start cleanup")
    ptfhost.command('rm /tmp/fg_ecmp_persist_map.json')
    config_reload(duthost)


@pytest.fixture(scope="module")
def common_setup_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

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
        cleanup(duthost, ptfhost)


def test_fg_ecmp(common_setup_teardown, ptfhost):
    duthost, cfg_facts, router_mac, net_ports = common_setup_teardown

    # IPv4 test
    port_list, ipv4_to_port, bank_0_port, bank_1_port = setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv4)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ipv4_to_port, bank_0_port, bank_1_port, PREFIX_IPV4_LIST)
    fg_ecmp_to_regular_ecmp_transitions(ptfhost, duthost, router_mac, net_ports, port_list, ipv4_to_port, bank_0_port, bank_1_port, PREFIX_IPV4_LIST, cfg_facts)

    # IPv6 test
    port_list, ipv6_to_port, bank_0_port, bank_1_port = setup_test_config(duthost, ptfhost, cfg_facts, router_mac, net_ports, DEFAULT_VLAN_IPv6)
    fg_ecmp(ptfhost, duthost, router_mac, net_ports, port_list, ipv6_to_port, bank_0_port, bank_1_port, PREFIX_IPV6_LIST)
    fg_ecmp_to_regular_ecmp_transitions(ptfhost, duthost, router_mac, net_ports, port_list, ipv6_to_port, bank_0_port, bank_1_port, PREFIX_IPV6_LIST, cfg_facts)
