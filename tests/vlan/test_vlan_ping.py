import random
import pytest
import ipaddress
import logging
import ptf.testutils as testutils
from tests.common.plugins import ptfadapter

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't0-52')
]


def static_neighbor_entry(duthost, dic, oper, ip_version="both"):
    """
    Performs addition or deletion of static entries of ipv4 and v6 neighbors in DUT based on 'oper' parameter
    """
    for member in dic.itervalues():
        if ip_version == "4" or "both":
            if oper == "add":
                logger.debug("adding ipv4 static arp entry for ip %s on DUT" % (member['ipv4']))
                duthost.shell("sudo arp -s {0} {1}".format(member['ipv4'], member['mac']))

            elif oper == "del":
                logger.debug("deleting ipv4 static arp entry for ip %s on DUT" % (member['ipv4']))
                duthost.shell("sudo arp -d {0}".format(member['ipv4']))
            else:
                logger.debug("unknown operation")

        elif ip_version == "6" or "both":
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
def vlan_ping_setup(duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, tbinfo):
    """
    Setup:      adds ipv4 and ipv6 address on ptf hosts and routes for VM
    Teardown:   deletes ipv4 and ipv6 address on ptf hosts and removes routes to VM. Also removes residual static arp entries from tests
    """
    vm_host_info = {}
    vm_name, vm_info = random.choice(nbrhosts.items())
    vm_ip_with_prefix = (vm_info['conf']['interfaces']['Port-Channel1']['ipv4']).decode('utf-8')
    output = vm_info['host'].command("ip addr show dev po1")
    vm_host_info["mac"] = output['stdout_lines'][1].split()[1]
    vm_ip_intf = ipaddress.IPv4Interface(vm_ip_with_prefix).ip
    vm_host_info["ipv4"] = vm_ip_intf
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    my_cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    ptfhost_info = {}
    ip4 = None
    ip6 = None
    for a_bgp_nbr in mg_facts['minigraph_bgp']:
        # Get the bgp neighbor connected to the selected VM
        if a_bgp_nbr['name'] == vm_name and a_bgp_nbr['addr'] == str(vm_host_info['ipv4']):
            # Find the port channel that connects to the selected VM
            for intf in mg_facts['minigraph_portchannel_interfaces']:
                if intf['peer_addr'] == str(vm_host_info['ipv4']):
                    portchannel = intf['attachto']
                    vm_host_info['port_index'] = mg_facts['minigraph_ptf_indices'][mg_facts['minigraph_portchannels'][portchannel]['members'][0]]
                    break
            break

    # getting the ipv4, ipv6 and vlan id of a vlan in DUT with 2 or more vlan members
    for k, v in my_cfg_facts['VLAN'].items():
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
    rand_vlan_member_list = random.sample(my_cfg_facts['VLAN_MEMBER']['Vlan' + vlanid].keys(), 2)
    exclude_ip = []
    exclude_ip.extend(
        [ipaddress.IPv4Interface(ip4).network.network_address, ipaddress.IPv4Interface(ip4).network.broadcast_address,
         vlan_ip_address_v4]
    )

    # getting port index, mac, ipv4 and ipv6 of ptf ports into a dict
    for member in rand_vlan_member_list:
        random_ip_in_vlan = random.choice([x for x in vlan_ip_network_v4 if x not in exclude_ip])
        ptfhost_info[member] = {}
        ptfhost_info[member]["Vlanid"] = vlanid
        ptfhost_info[member]["port_index"] = mg_facts['minigraph_ptf_indices'][member]
        ptfhost_info[member]["mac"] = (ptfhost.shell(
            "ifconfig eth%d | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'" % ptfhost_info[member][
                "port_index"]))['stdout']
        ptfhost_info[member]["ipv4"] = str(random_ip_in_vlan)
        ptfhost_info[member]["ipv6"] = str(
            ipaddress.IPv6Interface(ip6).network[ptfhost_info[member]["port_index"]])

    return vm_host_info, ptfhost_info


def verify_icmp_packet(dut_mac, src_port, dst_port, ptfadapter):
    pkt = testutils.simple_icmp_packet(eth_src=str(src_port['mac']),
                                       eth_dst=str(dut_mac),
                                       ip_src=str(src_port['ipv4']),
                                       ip_dst=str(dst_port['ipv4']), ip_ttl=64)
    exptd_pkt = testutils.simple_icmp_packet(eth_src=str(dut_mac),
                                             eth_dst=str(dst_port['mac']),
                                             ip_src=str(src_port['ipv4']),
                                             ip_dst=str(dst_port['ipv4']), ip_ttl=63)
    for i in range(5):
        testutils.send_packet(ptfadapter, src_port['port_index'], pkt)
        testutils.verify_packet(ptfadapter, exptd_pkt, dst_port['port_index'])


def test_vlan_ping(vlan_ping_setup, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    """
    test for checking connectivity of statically added ipv4 and ipv6 arp entries
    """
    duthost = duthosts[rand_one_dut_hostname]
    vmhost_info, ptfhost_info = vlan_ping_setup
    device2 = dict(list(ptfhost_info.items())[1:])
    device1 = dict(list(ptfhost_info.items())[:1])

    # initial setup and checking connectivity, try to break in more chunks
    logger.info("initializing setup for ipv4 and ipv6")
    static_neighbor_entry(duthost, ptfhost_info, "add")
    logger.info("Checking connectivity to ptf ports")
    for member in ptfhost_info:
        verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member], ptfadapter)
        verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member], vmhost_info, ptfadapter)

    # flushing and re-adding ipv6 static arp entry
    static_neighbor_entry(duthost, ptfhost_info, "del", "6")
    static_neighbor_entry(duthost, dict(reversed(ptfhost_info.items())), "add", "6")

    # flushing and re-adding ipv4 static arp entry for 2nd ptf host
    static_neighbor_entry(duthost, device2, "del", "4")
    static_neighbor_entry(duthost, device2, "add", "4")

    # flushing and re-adding ipv4 static arp entry for 1st ptf host
    static_neighbor_entry(duthost, device1, "del", "4")
    static_neighbor_entry(duthost, device1, "add", "4")

    # Checking for connectivity
    logger.info("Check connectivity to both ptfhost")
    for member in ptfhost_info:
        verify_icmp_packet(duthost.facts['router_mac'], vmhost_info, ptfhost_info[member], ptfadapter)
        verify_icmp_packet(duthost.facts['router_mac'], ptfhost_info[member], vmhost_info, ptfadapter)
