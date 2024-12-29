import random
import pytest
import ipaddress
import logging
import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask
import six
from ipaddress import ip_address, IPv4Address
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m   # noqa F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host   # noqa F401
from tests.vlan.test_vlan import populate_mac_table   # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't0-52', 'm0', 'mx', 't0-2vlans')
]


def static_neighbor_entry(duthost, dic, oper, ip_version="both"):
    """
    Performs addition or deletion of static entries of ipv4 and v6 neighbors in DUT based on 'oper' parameter
    """
    for member in list(dic.values()):
        if ip_version in ["4", "both"]:
            if oper == "add":
                logger.debug("adding ipv4 static arp entry for ip %s on DUT" % (member['ipv4']))
                duthost.shell("sudo arp -s {0} {1}".format(member['ipv4'], member['mac']))

            elif oper == "del":
                logger.debug("deleting ipv4 static arp entry for ip %s on DUT" % (member['ipv4']))
                duthost.shell("sudo arp -d {0}".format(member['ipv4']))
            else:
                logger.debug("unknown operation")

        if ip_version in ["6", "both"]:
            if oper == "add":
                logger.debug("adding ipv6 static arp entry for ip %s on DUT" % (member['ipv6']))
                duthost.shell(
                    "sudo ip -6 neigh add {0} lladdr {1} dev Vlan{2}".format(member['ipv6'], member['mac'],
                                                                             member['Vlanid']))
            elif oper == "del":
                logger.debug("deleting ipv6 static arp entry for ip %s on DUT" % (member['ipv6']))
                duthost.shell("sudo ip -6 neigh del {0} lladdr {1} dev Vlan{2}".format(member['ipv6'], member['mac'],
                                                                                       member['Vlanid']))
            else:
                logger.debug("unknown operation")

        else:
            logger.debug("unknown IP version")


@pytest.fixture(scope='module')
def vlan_ping_setup(duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, tbinfo, lower_tor_host):   # noqa F811
    """
    Setup:      Collecting vm_host_info, ptfhost_info
    Teardown:   Removing all added ipv4 and ipv6 neighbors
    """
    vm_host_info = {}

    vm_name, vm_info = None, None
    topo_type = tbinfo["topo"]["type"]
    for nbr_name, nbr_info in list(nbrhosts.items()):
        if topo_type != "m0" or (topo_type == "m0" and "M1" in nbr_name):
            vm_name = nbr_name
            vm_info = nbr_info
            break

    py_assert(vm_name is not None, "Can't get neighbor vm")
    if topo_type == "mx":
        vm_ip_with_prefix = six.ensure_text(vm_info['conf']['interfaces']['Ethernet1']['ipv4'])
        output = vm_info['host'].command("ip addr show dev eth1")
    else:
        vm_ip_with_prefix = six.ensure_text(vm_info['conf']['interfaces']['Port-Channel1']['ipv4'])
        output = vm_info['host'].command("ip addr show dev po1")
        # in case of lower tor host we need to use the next portchannel
        if "dualtor-aa" in tbinfo["topo"]["name"] and rand_one_dut_hostname == lower_tor_host.hostname:
            vm_ip_with_prefix = six.ensure_text(vm_info['conf']['interfaces']['Port-Channel2']['ipv4'])
            output = vm_info['host'].command("ip addr show dev po2")
    vm_host_info["mac"] = output['stdout_lines'][1].split()[1]
    vm_ip_intf = ipaddress.IPv4Interface(vm_ip_with_prefix).ip
    vm_host_info["ipv4"] = vm_ip_intf
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        idx = duthosts.index(duthost)
        unselected_duthost = duthosts[1 - idx]
        unslctd_mg_facts = unselected_duthost.minigraph_facts(host=unselected_duthost.hostname)['ansible_facts']
        unslctd_mg_facts['mg_ptf_idx'] = unslctd_mg_facts['minigraph_port_indices'].copy()
        try:
            map = tbinfo['topo']['ptf_map'][str(1 - idx)]
            if map:
                for port, index in list(unslctd_mg_facts['minigraph_port_indices'].items()):
                    if str(index) in map:
                        unslctd_mg_facts['mg_ptf_idx'][port] = map[str(index)]
        except (ValueError, KeyError):
            pass
    my_cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ptfhost_info = {}
    ip4 = None
    ip6 = None
    for a_bgp_nbr in mg_facts['minigraph_bgp']:
        # Get the bgp neighbor connected to the selected VM
        if a_bgp_nbr['name'] == vm_name and a_bgp_nbr['addr'] == str(vm_host_info['ipv4']):
            # Find the interface that connects to the selected VM
            if topo_type == "mx":
                for intf in mg_facts['minigraph_interfaces']:
                    if intf['peer_addr'] == str(vm_host_info['ipv4']):
                        vm_host_info['port_index_list'] = [mg_facts['minigraph_ptf_indices'][intf['attachto']]]
                        break
            else:
                ifaces_list = []
                # UL pkt may take any of the tor in case of dualtor-aa
                if "dualtor-aa" in tbinfo["topo"]["name"]:
                    for intf in mg_facts['minigraph_portchannel_interfaces']:
                        if type(ip_address(intf['peer_addr'])) is IPv4Address:
                            portchannel = intf['attachto']
                            for iface in mg_facts['minigraph_portchannels'][portchannel]['members']:
                                ifaces_list.append(mg_facts['minigraph_ptf_indices'][iface])
                                ifaces_list.append(unslctd_mg_facts['mg_ptf_idx'][iface])
                    ifaces_list = list(dict.fromkeys(ifaces_list))
                else:
                    for intf in mg_facts['minigraph_portchannel_interfaces']:
                        if intf['peer_addr'] == str(vm_host_info['ipv4']):
                            portchannel = intf['attachto']
                            for iface in mg_facts['minigraph_portchannels'][portchannel]['members']:
                                ifaces_list.append(mg_facts['minigraph_ptf_indices'][iface])
                vm_host_info['port_index_list'] = ifaces_list
            break

    # getting the ipv4, ipv6 and vlan id of a vlan in DUT with 2 or more vlan members
    for k, v in list(my_cfg_facts['VLAN'].items()):
        vlanid = v['vlanid']
        if len(my_cfg_facts['VLAN_MEMBER']['Vlan' + vlanid]) >= 2:
            for addr in my_cfg_facts['VLAN_INTERFACE']['Vlan' + vlanid]:
                if addr.find(':') == -1:
                    ip4 = addr
                else:
                    ip6 = addr
            break  # need only 1 vlan details
        else:
            continue

    # ip prefixes of the vlan
    vlan_ip_address_v4 = ipaddress.IPv4Interface(ip4).ip
    vlan_ip_network_v4 = ipaddress.IPv4Interface(ip4).network

    # selecting 2 random vlan members of DUT
    # Remove portchannel in vlan member list
    filter_vlan_member_list = [member for member in list(my_cfg_facts['VLAN_MEMBER']['Vlan' + vlanid].keys())
                               if member in mg_facts['minigraph_ptf_indices']]
    rand_vlan_member_list = random.sample(filter_vlan_member_list, 2)
    exclude_ip = []
    exclude_ip.extend(
        [ipaddress.IPv4Interface(ip4).network.network_address, ipaddress.IPv4Interface(ip4).network.broadcast_address,
         vlan_ip_address_v4]
    )
    # getting port index, mac, ipv4 and ipv6 of ptf ports into a dict
    ips_in_vlan = [x for x in vlan_ip_network_v4 if x not in exclude_ip]
    for member in rand_vlan_member_list:
        # Get first and last ip in vlan for two vlan members
        ip_in_vlan = ips_in_vlan[0 if len(list(ptfhost_info.keys())) == 0 else -1]
        ptfhost_info[member] = {}
        ptfhost_info[member]["Vlanid"] = vlanid
        ptfhost_info[member]["port_index_list"] = [mg_facts['minigraph_ptf_indices'][member]]
        ptfhost_info[member]["mac"] = (ptfhost.shell(
            "ifconfig eth%d | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'" % ptfhost_info[member][
                "port_index_list"][0]))['stdout']
        ptfhost_info[member]["ipv4"] = str(ip_in_vlan)
        ptfhost_info[member]["ipv6"] = str(
            ipaddress.IPv6Interface(ip6).network[ptfhost_info[member]["port_index_list"][0]])

    yield vm_host_info, ptfhost_info

    logger.info("Removing all added ipv4 and ipv6 neighbors")
    duthost.shell("sudo ip neigh flush nud permanent")


def verify_icmp_packet(dut_mac, src_port, dst_port, ptfadapter, tbinfo,
                       vlan_mac=None, dtor_ul=False, dtor_dl=False):
    if dtor_ul is True:
        # use vlan int mac in case of dualtor UL test pkt
        pkt = testutils.simple_icmp_packet(eth_src=str(src_port['mac']),
                                           eth_dst=str(vlan_mac),
                                           ip_src=str(src_port['ipv4']),
                                           ip_dst=str(dst_port['ipv4']), ip_ttl=64)
    else:
        # use dut mac addr for all other test pkts
        pkt = testutils.simple_icmp_packet(eth_src=str(src_port['mac']),
                                           eth_dst=str(dut_mac),
                                           ip_src=str(src_port['ipv4']),
                                           ip_dst=str(dst_port['ipv4']), ip_ttl=64)
    if dtor_dl is True:
        # expect vlan int mac as src mac in dualtor DL test pkt
        exptd_pkt = testutils.simple_icmp_packet(eth_src=str(vlan_mac),
                                                 eth_dst=str(dst_port['mac']),
                                                 ip_src=str(src_port['ipv4']),
                                                 ip_dst=str(dst_port['ipv4']), ip_ttl=63)
    else:
        # expect dut mac as src mac for non dualtor DL test pkt
        exptd_pkt = testutils.simple_icmp_packet(eth_src=str(dut_mac),
                                                 eth_dst=str(dst_port['mac']),
                                                 ip_src=str(src_port['ipv4']),
                                                 ip_dst=str(dst_port['ipv4']), ip_ttl=63)
    # skip smac check for dualtor-aa UL test pkt
    if "dualtor-aa" in tbinfo["topo"]["name"] and dtor_ul is True:
        exptd_pkt = Mask(exptd_pkt)
        exptd_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    for i in range(5):
        testutils.send_packet(ptfadapter, src_port['port_index_list'][0], pkt)
        try:
            testutils.verify_packet_any_port(ptfadapter, exptd_pkt, dst_port['port_index_list'])
            # if verification succeeds, break the loop
            break
        except Exception as e:
            if i >= 4:
                raise e  # If it fails on the last attempt, raise the exception


def test_vlan_ping(vlan_ping_setup, duthosts, rand_one_dut_hostname, ptfadapter, tbinfo,
                   toggle_all_simulator_ports_to_rand_selected_tor_m, populate_mac_table):  # noqa F811
    """
    test for checking connectivity of statically added ipv4 and ipv6 arp entries
    """
    duthost = duthosts[rand_one_dut_hostname]
    vmhost_info, ptfhost_info = vlan_ping_setup
    device2 = dict(list(ptfhost_info.items())[1:])
    device1 = dict(list(ptfhost_info.items())[:1])
    # use mac addr of vlan interface in case of dualtor
    if 'dualtor' in tbinfo["topo"]["name"]:
        vlan_table = duthost.get_running_config_facts()['VLAN']
        vlan_name = list(vlan_table.keys())[0]
        vlan_mac = duthost.get_dut_iface_mac(vlan_name)
        # dump neigh entries
        logger.info("Dumping all ipv4 and ipv6 neighbors")
        duthost.shell("sudo ip neigh show")
        # flush entries of vlan interface in case of dualtor to avoid issue#12302
        logger.info("Flushing all ipv4 and ipv6 neighbors on {}".format(vlan_name))
        duthost.shell("sudo ip neigh flush dev {} all".format(vlan_name))

    # initial setup and checking connectivity, try to break in more chunks
    logger.info("initializing setup for ipv4 and ipv6")
    static_neighbor_entry(duthost, ptfhost_info, "add")
    logger.info("Checking connectivity to ptf ports")

    for member in ptfhost_info:
        if 'dualtor' in tbinfo["topo"]["name"]:
            verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member],
                               vmhost_info, ptfadapter, tbinfo, vlan_mac, dtor_ul=True)
            verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member],
                               ptfadapter, tbinfo, vlan_mac, dtor_dl=True)
        else:
            verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member], vmhost_info, ptfadapter, tbinfo)
            verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member], ptfadapter, tbinfo)

    # flushing and re-adding ipv6 static arp entry
    static_neighbor_entry(duthost, ptfhost_info, "del", "6")
    static_neighbor_entry(duthost, dict(reversed(list(ptfhost_info.items()))), "add", "6")

    # flushing and re-adding ipv4 static arp entry for 2nd ptf host
    static_neighbor_entry(duthost, device2, "del", "4")
    static_neighbor_entry(duthost, device2, "add", "4")

    # flushing and re-adding ipv4 static arp entry for 1st ptf host
    static_neighbor_entry(duthost, device1, "del", "4")
    static_neighbor_entry(duthost, device1, "add", "4")

    # Checking for connectivity
    logger.info("Check connectivity to both ptfhost")
    for member in ptfhost_info:
        if 'dualtor' in tbinfo["topo"]["name"]:
            verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member],
                               vmhost_info, ptfadapter, tbinfo, vlan_mac, dtor_ul=True)
            verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member],
                               ptfadapter, tbinfo, vlan_mac, dtor_dl=True)
        else:
            verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member], vmhost_info, ptfadapter, tbinfo)
            verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member], ptfadapter, tbinfo)
