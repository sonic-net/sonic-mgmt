import logging
import ptf.testutils as testutils
import pytest
import time

from ipaddress import ip_network, IPv6Network, IPv4Network
from tests.arp.arp_utils import clear_dut_arp_cache, increment_ipv6_addr, increment_ipv4_addr
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology('t0', 'dualtor')
]

logger = logging.getLogger(__name__)


@pytest.fixture
def setup_ptf_arp(config_facts, ptfhost, intfs_for_test):
    _, _, intf1_index, _, = intfs_for_test
    ip_addr_config_cmd = 'ip addr {} {}/{} dev {}'

    # Calculate the IPv6 address to assign to the PTF port
    vlan_addrs = config_facts['VLAN_INTERFACE'].items()[0][1].keys()
    intf_ipv6_addr = None
    intf_ipv4_addr = None

    for addr in vlan_addrs:
        if type(ip_network(addr, strict=False)) is IPv6Network:
            intf_ipv6_addr = ip_network(addr, strict=False)
        elif type(ip_network(addr, strict=False)) is IPv4Network:
            intf_ipv4_addr = ip_network(addr, strict=False)

    # The VLAN interface on the DUT has an x.x.x.1 address assigned (or x::1 in the case of IPv6)
    # But the network_address property returns an x.x.x.0 address (or x::0 for IPv6) so we increment by two to avoid conflict
    ptf_intf_name = "eth{}".format(intf1_index)

    if intf_ipv4_addr is not None:
        ptf_intf_ipv4_addr = increment_ipv4_addr(intf_ipv4_addr.network_address, incr=2)
        ptfhost.shell(ip_addr_config_cmd.format('replace', ptf_intf_ipv4_addr, intf_ipv4_addr.prefixlen, ptf_intf_name))
    else:
        ptf_intf_ipv4_addr = None

    if intf_ipv6_addr is not None:
        ptf_intf_ipv6_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=2)
        ptfhost.shell(ip_addr_config_cmd.format('replace', ptf_intf_ipv6_addr, intf_ipv6_addr.prefixlen, ptf_intf_name))
    else:
        ptf_intf_ipv6_addr = None

    logger.info("Configured {} and {} on PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    yield ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name 

    logger.info("Removing {} and {} from PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    if intf_ipv4_addr is not None:
        ptfhost.shell(ip_addr_config_cmd.format('del', ptf_intf_ipv4_addr, intf_ipv4_addr.prefixlen, ptf_intf_name))

    if intf_ipv6_addr is not None:
        ptfhost.shell(ip_addr_config_cmd.format('del', ptf_intf_ipv6_addr, intf_ipv6_addr.prefixlen, ptf_intf_name))


@pytest.fixture
def garp_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, config_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    clear_dut_arp_cache(duthost)

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()
    garp_enable_cmd = 'redis-cli -n 4 HSET "VLAN_INTERFACE|{}" grat_arp enabled'
    cat_arp_accept_cmd = 'cat /proc/sys/net/ipv4/conf/{}/arp_accept'
    arp_accept_vals = []
    for vlan in vlan_intfs:
        res = duthost.shell(garp_enable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to enable GARP for {}".format(vlan))
        else:
            logger.info("Enabled GARP for {}".format(vlan))

            # Get the `arp_accept` values for each VLAN interface and yield them
            # to the caller, who can decide how to proceed
            arp_accept_res = duthost.shell(cat_arp_accept_cmd.format(vlan))
            arp_accept_vals.append(arp_accept_res['stdout'])

    yield arp_accept_vals

    garp_disable_cmd = 'redis-cli -n 4 HDEL "VLAN_INTERFACE|{}" grat_arp'
    for vlan in vlan_intfs:
        res = duthost.shell(garp_disable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to disable GARP for {}".format(vlan))
        else:
            logger.info("GARP disabled for {}".format(vlan))


def test_arp_garp_enabled(duthosts, enum_rand_one_per_hwsku_frontend_hostname, garp_setup, setup_ptf_arp, intfs_for_test, config_facts, ptfadapter):
    '''
    Send a gratuitous ARP (GARP) packet from the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    '''
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ptf_intf_ipv4_addr, _, _ = setup_ptf_arp
    arp_accept_vals = garp_setup
    pytest_require(all(int(val) == 1 for val in arp_accept_vals), 'Gratuitous ARP not enabled for this device')

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

    logger.info("Sending GARP for target {} from PTF interface {}".format(arp_request_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['macaddress'] == arp_src_mac)
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['interface'] in vlan_intfs)


@pytest.mark.parametrize('ip_version', ['v4', 'v6'])
def test_proxy_arp(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup_ptf_arp, intfs_for_test, ptfhost, config_facts, ip_version, tbinfo):
    '''
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN.

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC
    '''
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name = setup_ptf_arp

    pytest_require(duthost.has_config_subcommand('config vlan proxy_arp'), "Proxy ARP command does not exist on device")

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'

    # We are leveraging the fact that ping will automatically send a neighbor solicitation/ARP request for us
    # However, we expect the ping itself to always fail since no interface is configured with the pinged IP, so add '|| true' so we can continue
    ping_cmd = 'ping {} -I {} -c 1 || true' 

    # Enable proxy ARP/NDP for the VLANs on the DUT
    vlans = config_facts['VLAN']
    vlan_ids =[vlans[vlan]['vlanid'] for vlan in vlans.keys()]

    for vid in vlan_ids:
        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))
        time.sleep(3)
        logger.info("Enabled proxy ARP for VLAN {}".format(vid))

    clear_dut_arp_cache(ptfhost)

    ping_addr = None
    if ip_version == 'v4':
        ping_addr = increment_ipv4_addr(ptf_intf_ipv4_addr)
    elif ip_version == 'v6':
        ping_addr = increment_ipv6_addr(ptf_intf_ipv6_addr)
    
    logger.info("Pinging {} using PTF interface {}".format(ping_addr, ptf_intf_name))
    ptfhost.shell(ping_cmd.format(ping_addr, ptf_intf_name))
    time.sleep(2)

    neighbor_table = ptfhost.switch_arptable()['ansible_facts']['arptable'][ip_version]

    topology = tbinfo['topo']['name']
    if 'dualtor' in topology:
        dut_macs = []

        for vlan_details in vlans.values():
            dut_macs.append(vlan_details['mac'])
    else:
        router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
        dut_macs = [router_mac]

    pytest_assert(ping_addr in neighbor_table.keys())
    pytest_assert(neighbor_table[ping_addr]['macaddress'] in dut_macs)
    pytest_assert(neighbor_table[ping_addr]['interface'] == ptf_intf_name)
    pytest_assert(neighbor_table[ping_addr]['state'].lower() not in ['failed', 'incomplete'])
