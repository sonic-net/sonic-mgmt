import random
import pytest
import ipaddress
import logging

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
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
def vlan_ping_setup(duthosts, rand_one_dut_hostname, ptfhost, nbrhosts):
    """
    Setup:      adds ipv4 and ipv6 address on ptf hosts and routes for VM
    Teardown:   deletes ipv4 and ipv6 address on ptf hosts and removes routes to VM. Also removes residual static arp entries from tests
    """
    try:
        k, v = random.choice(nbrhosts.items())
        vm_host = v['host']
        vm_host_ip = (v['conf']['interfaces']['Port-Channel1']['ipv4']).decode('utf-8')
        vm_host_network = ipaddress.IPv4Interface(format(vm_host_ip)).network
        duthost = duthosts[rand_one_dut_hostname]
        my_cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        ptfhost_info = {}

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
        vlan_ip_prefixlen_v4 = ipaddress.IPv4Interface(ip4).network.prefixlen
        vlan_ip_prefixlen_v6 = ipaddress.IPv6Interface(ip6).network.prefixlen

        # selecting 2 random vlan members of DUT
        exclude_member = ["Ethernet0", "Ethernet1"]
        vlan_member_list = [ele for ele in my_cfg_facts['VLAN_MEMBER']['Vlan' + vlanid].keys() if ele not in exclude_member]
        rand_vlan_member_list = random.sample(vlan_member_list, 2)

        # getting port index, mac, ipv4 and ipv6 of ptf ports into a dict
        for member in rand_vlan_member_list:
            ptfhost_info[member] = {}
            ptfhost_info[member]["Vlanid"] = vlanid
            ptfhost_info[member]["port_index"] = my_cfg_facts['port_index_map'][member]
            ptfhost_info[member]["mac"] = (ptfhost.shell(
                "ifconfig eth%d | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'" % ptfhost_info[member][
                    "port_index"]))['stdout']
            ptfhost_info[member]["ipv4"] = str(
                ipaddress.IPv4Interface(ip4).network[ptfhost_info[member]["port_index"]])
            ptfhost_info[member]["ipv6"] = str(
                ipaddress.IPv6Interface(ip6).network[ptfhost_info[member]["port_index"]])
            # add ipv4 and v6 to randomly selected ports in ptf
            logger.info("adding ip to ptf ports")
            logger.debug("adding ipv4 of ptf port %d " % ptfhost_info[member]['port_index'])
            ptfhost.command("ip addr add {ip}/{prefix} dev eth{pi}".format(ip=ptfhost_info[member]['ipv4'],
                                                                           prefix=vlan_ip_prefixlen_v4,
                                                                           pi=ptfhost_info[member]['port_index']))
            logger.debug("adding ipv6 of ptf port %d " % ptfhost_info[member]['port_index'])
            ptfhost.command("ip addr add {ip}/{prefix} dev eth{pi}".format(ip=ptfhost_info[member]['ipv6'],
                                                                           prefix=vlan_ip_prefixlen_v6,
                                                                           pi=ptfhost_info[member]['port_index']))
        # adding route on ptf for VM for connectivity
        logger.info("adding routes for VM")
        ptfhost.command("ip route add {ip} via {id}".format(ip=vm_host_network, id=vlan_ip_address_v4))
        yield vm_host, ptfhost_info
    finally:
        # Teardown of ip addresses and static arp entries used in the test
        for member in rand_vlan_member_list:
            logger.debug("deleting ipv4 of ptf port %d " % ptfhost_info[member]['port_index'])
            ptfhost.command("ip addr del {ip}/{prefix} dev eth{pi}".format(ip=ptfhost_info[member]['ipv4'],
                                                                           prefix=vlan_ip_prefixlen_v4,
                                                                           pi=ptfhost_info[member]['port_index']))
            logger.debug("deleting ipv6 of ptf port %d " % ptfhost_info[member]['port_index'])
            ptfhost.command("ip addr del {ip}/{prefix} dev eth{pi}".format(ip=ptfhost_info[member]['ipv6'],
                                                                           prefix=vlan_ip_prefixlen_v6,
                                                                           pi=ptfhost_info[member]['port_index']))
            logger.debug("deleting ipv4 static arp entry for ip %s on DUT" % (ptfhost_info[member]['ipv4']))
            duthost.shell("sudo arp -d {0}".format(ptfhost_info[member]['ipv4']))


def test_vlan_ping(vlan_ping_setup, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts):
    """
    test for checking connectivity of statically added ipv4 and ipv6 arp entries
    """
    duthost = duthosts[rand_one_dut_hostname]
    vm_host, ptfhost_info = vlan_ping_setup
    device2 = dict(list(ptfhost_info.items())[len(ptfhost_info)//2:])
    device1 = dict(list(ptfhost_info.items())[:len(ptfhost_info) // 2])
    print (device1,device2)

    # initial setup and checking connectivity, try to break in more chunks
    logger.info("initializing setup for ipv4 and ipv6")
    static_neighbor_entry(duthost, ptfhost_info, "add")
    logger.info("Checking connectivity to ptf ports")
    for member in ptfhost_info:
        vm_host.command("ping {} -c 5".format(ptfhost_info[member]['ipv4']))

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
        vm_host.command("ping {} -c 5".format(ptfhost_info[member]['ipv4']))