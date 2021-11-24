import logging
import ptf.testutils as testutils
import pytest
import ptf.mask as mask
import ptf.packet as packet

from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, \
                      ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket
from ipaddress import ip_network, IPv6Network, IPv4Network
from tests.arp.arp_utils import clear_dut_arp_cache, increment_ipv6_addr, increment_ipv4_addr
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses

pytestmark = [
    pytest.mark.topology('t0', 'dualtor')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def ip_and_intf_info(config_facts, intfs_for_test):
    """
    Calculate IP addresses and interface to use for test
    """
    _, _, intf1_index, _, = intfs_for_test
    ptf_intf_name = "eth{}".format(intf1_index)

    # Calculate the IPv6 address to assign to the PTF port
    vlan_addrs = config_facts['VLAN_INTERFACE'].items()[0][1].keys()
    intf_ipv6_addr = None
    intf_ipv4_addr = None

    for addr in vlan_addrs:
        try:
            if type(ip_network(addr, strict=False)) is IPv6Network:
                intf_ipv6_addr = ip_network(addr, strict=False)
            elif type(ip_network(addr, strict=False)) is IPv4Network:
                intf_ipv4_addr = ip_network(addr, strict=False)
        except ValueError:
            continue

    # The VLAN interface on the DUT has an x.x.x.1 address assigned (or x::1 in the case of IPv6)
    # But the network_address property returns an x.x.x.0 address (or x::0 for IPv6) so we increment by two to avoid conflict
    if intf_ipv4_addr is not None:
        ptf_intf_ipv4_addr = increment_ipv4_addr(intf_ipv4_addr.network_address, incr=2)
    else:
        ptf_intf_ipv4_addr = None

    if intf_ipv6_addr is not None:
        ptf_intf_ipv6_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=2)
    else:
        ptf_intf_ipv6_addr = None

    logger.info("Using {}, {}, and PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    return ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name 


@pytest.fixture
def garp_enabled(rand_selected_dut, config_facts):
    """
    Tries to enable gratuitious ARP for each VLAN on the ToR in CONFIG_DB

    Also checks the kernel `arp_accept` value to see if the
    attempt was successful.

    During teardown, restores the original `grat_arp` value in 
    CONFIG_DB

    Yields:
        (bool) True if `arp_accept` was successfully set for all VLANs,
               False otherwise

    """
    duthost = rand_selected_dut

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()
    garp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|{}" grat_arp'
    garp_enable_cmd = 'sonic-db-cli CONFIG_DB HSET "VLAN_INTERFACE|{}" grat_arp enabled'
    cat_arp_accept_cmd = 'cat /proc/sys/net/ipv4/conf/{}/arp_accept'
    arp_accept_vals = []
    old_grat_arp_vals = {}

    for vlan in vlan_intfs:
        old_grat_arp_res = duthost.shell(garp_check_cmd.format(vlan))
        old_grat_arp_vals[vlan] = old_grat_arp_res['stdout']
        res = duthost.shell(garp_enable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to enable GARP for {}".format(vlan))
        else:
            logger.info("Enabled GARP for {}".format(vlan))

            # Get the `arp_accept` values for each VLAN interface
            arp_accept_res = duthost.shell(cat_arp_accept_cmd.format(vlan))
            arp_accept_vals.append(arp_accept_res['stdout'])

    yield all(int(val) == 1 for val in arp_accept_vals)

    garp_disable_cmd = 'sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|{}" grat_arp'
    for vlan in vlan_intfs:
        old_grat_arp_val = old_grat_arp_vals[vlan]

        if 'enabled' not in old_grat_arp_val:
            res = duthost.shell(garp_disable_cmd.format(vlan))

            if res['rc'] != 0:
                pytest.fail("Unable to disable GARP for {}".format(vlan))
            else:
                logger.info("GARP disabled for {}".format(vlan))

@pytest.fixture
def proxy_arp_enabled(rand_selected_dut, config_facts):
    """
    Tries to enable proxy ARP for each VLAN on the ToR

    Also checks CONFIG_DB to see if the attempt was successful

    During teardown, restores the original proxy ARP setting

    Yields:
        (bool) True if proxy ARP was enabled for all VLANs,
               False otherwise
    """
    duthost = rand_selected_dut
    pytest_require(duthost.has_config_subcommand('config vlan proxy_arp'), "Proxy ARP command does not exist on device")

    proxy_arp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|Vlan{}" proxy_arp'
    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'
    vlans = config_facts['VLAN']
    vlan_ids =[vlans[vlan]['vlanid'] for vlan in vlans.keys()]
    old_proxy_arp_vals = {}
    new_proxy_arp_vals = []

    # Enable proxy ARP/NDP for the VLANs on the DUT
    for vid in vlan_ids:
        old_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        old_proxy_arp_vals[vid] = old_proxy_arp_res['stdout']

        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))

        logger.info("Enabled proxy ARP for Vlan{}".format(vid))
        new_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        new_proxy_arp_vals.append(new_proxy_arp_res['stdout'])

    yield all('enabled' in val for val in new_proxy_arp_vals)

    for vid, proxy_arp_val in old_proxy_arp_vals.items():
        if 'enabled' not in proxy_arp_val:
            duthost.shell(proxy_arp_config_cmd.format(vid, 'disabled'))

def test_arp_garp_enabled(rand_selected_dut, garp_enabled, ip_and_intf_info, intfs_for_test, config_facts, ptfadapter):
    """
    Send a gratuitous ARP (GARP) packet from the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    duthost = rand_selected_dut
    ptf_intf_ipv4_addr, _, _ = ip_and_intf_info

    arp_request_ip = increment_ipv4_addr(ptf_intf_ipv4_addr)
    arp_src_mac = '00:00:07:08:09:0a'
    _, _, intf1_index, _, = intfs_for_test

    pkt = testutils.simple_arp_packet(pktlen=60,
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=arp_src_mac,
                                vlan_pcp=0,
                                arp_op=2,
                                ip_snd=arp_request_ip,
                                ip_tgt=arp_request_ip,
                                hw_snd=arp_src_mac,
                                hw_tgt='ff:ff:ff:ff:ff:ff'
                            )

    clear_dut_arp_cache(duthost)

    logger.info("Sending GARP for target {} from PTF interface {}".format(arp_request_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['macaddress'].lower() == arp_src_mac.lower())
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['interface'] in vlan_intfs)

def generate_link_local_addr(mac):
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::{}".format(":".join(ipv6Parts))
    return ipv6

@pytest.fixture(params=['v4', 'v6'])
def packets_for_test(request, ptfadapter, duthost, config_facts, tbinfo, ip_and_intf_info):
    ip_version = request.param
    src_addr_v4, src_addr_v6, ptf_intf = ip_and_intf_info
    ptf_intf_index = int(ptf_intf.replace('eth', ''))
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    vlans = config_facts['VLAN']
    topology = tbinfo['topo']['name']
    dut_mac = ''
    for vlan_details in vlans.values():
        if 'dualtor' in topology:
            dut_mac = vlan_details['mac'].lower()
        else:
            dut_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
        break

    if ip_version == 'v4':
        tgt_addr = increment_ipv4_addr(src_addr_v4)
        out_pkt = testutils.simple_arp_packet(
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=ptf_intf_mac,
                                ip_snd=src_addr_v4,
                                ip_tgt=tgt_addr,
                                arp_op=1,
                                hw_snd=ptf_intf_mac
                            )
        exp_pkt = testutils.simple_arp_packet(
                                eth_dst=ptf_intf_mac,
                                eth_src=dut_mac,
                                ip_snd=tgt_addr,
                                ip_tgt=src_addr_v4,
                                arp_op=2,
                                hw_snd=dut_mac,
                                hw_tgt=ptf_intf_mac
        )
    elif ip_version == 'v6':
        tgt_addr = increment_ipv6_addr(src_addr_v6)
        ll_src_addr = generate_link_local_addr(ptf_intf_mac)
        multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
        multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)
        out_pkt = Ether(src=ptf_intf_mac, dst=multicast_tgt_mac) 
        out_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=ll_src_addr)
        out_pkt /= ICMPv6ND_NS(tgt=tgt_addr) 
        out_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=ptf_intf_mac)

        exp_pkt = Ether(src=dut_mac, dst=ptf_intf_mac) 
        exp_pkt /= IPv6(dst=ll_src_addr, src=generate_link_local_addr(dut_mac))
        exp_pkt /= ICMPv6ND_NA(tgt=tgt_addr, S=1, R=1, O=0)
        exp_pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=dut_mac)
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'fl')

    return ip_version, out_pkt, exp_pkt

def test_proxy_arp(proxy_arp_enabled, ip_and_intf_info, ptfadapter, packets_for_test):
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN.

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC
    """
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')
    ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name = ip_and_intf_info
    ptf_intf_index = int(ptf_intf_name.replace('eth', ''))
    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index)
