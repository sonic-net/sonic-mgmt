import pytest
import time

from datetime import datetime
from ipaddress import ip_network, IPv6Network
from tests.arp.arp_utils import clear_dut_arp_cache, increment_ipv6_addr
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology(('t0', 'dualtor'))
]


def test_arp_garp_enabled(intfs_for_test, ptfhost, config_facts):
    intf1, intf1_indice, intf2, intf2_indice, intf_facts, mg_facts, duthost = intfs_for_test
    params = {
        'acs_mac': intf_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }
    clear_dut_arp_cache(duthost)

    vlan_intfs = config_facts['VLAN_INTERFACE'].keys()
    garp_enable_cmd = 'redis-cli -n 4 HSET "VLAN_INTERFACE|{}" grat_arp enabled'
    for vlan in vlan_intfs:
        res = duthost.shell(garp_enable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to enable GARP for {}".format(vlan))

    log_file = "/tmp/arptest.GarpEnabledUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpEnabledUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:00:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] in vlan_intfs)


@pytest.fixture
def setup_ptf_proxy_arp(config_facts, ptfhost, intfs_for_test):
    _, intf1_indice, _, _, _, _, _ = intfs_for_test
    ip_addr_config_cmd = 'ip addr {} {}/{} dev {}'

    # Calculate the IPv6 address to assign to the PTF port
    vlan_addrs = config_facts['VLAN_INTERFACE'].items()[0][1].keys()
    intf_ipv6_addr = None

    for addr in vlan_addrs:
        if type(ip_network(addr, strict=False)) is IPv6Network:
            intf_ipv6_addr = ip_network(addr, strict=False)
            break

    ptf_intf_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=2)
    ptf_intf_name = "eth{}".format(intf1_indice)

    ptfhost.shell(ip_addr_config_cmd.format('add', ptf_intf_addr, intf_ipv6_addr.prefixlen, ptf_intf_name))

    yield ptf_intf_addr, ptf_intf_name

    ptfhost.shell(ip_addr_config_cmd.format('del', ptf_intf_addr, intf_ipv6_addr.prefixlen, ptf_intf_name))

def test_proxy_arp(setup_ptf_proxy_arp, intfs_for_test, ptfhost, config_facts):
    intf1, intf1_indice, intf2, intf2_indice, intf_facts, mg_facts, duthost = intfs_for_test
    ptf_intf_addr, ptf_intf_name = setup_ptf_proxy_arp
    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'

    # We are leveraging the fact that ping will automatically send a neighbor solicitation for us
    # However, we expect the ping itself to always fail, so add '|| true' so we can continue
    ping_cmd = 'ping {} -I {} -c 1 || true' 

    # Enable proxy ARP/NDP for the VLANs on the DUT
    vlans = config_facts['VLAN']
    vlan_ids =[vlans[vlan]['vlanid'] for vlan in vlans.keys()]

    for vid in vlan_ids:
        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))
        time.sleep(5)

    ptfhost.shell("ip neigh flush all")

    ping_addr = increment_ipv6_addr(ptf_intf_addr)
    
    ptfhost.shell(ping_cmd.format(ping_addr, ptf_intf_name))
    time.sleep(2)

    v6_neigh_table = ptfhost.switch_arptable()['ansible_facts']['arptable']['v6']
    dut_mac = intf_facts['ansible_interface_facts'][intf1]['macaddress']
    pytest_assert(ping_addr in v6_neigh_table.keys())
    pytest_assert(v6_neigh_table[ping_addr]['macaddress'] == dut_mac)
    pytest_assert(v6_neigh_table[ping_addr]['interface'] == ptf_intf_name)
    pytest_assert(v6_neigh_table[ping_addr]['state'] != 'FAILED')