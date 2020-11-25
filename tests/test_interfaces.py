from netaddr import IPAddress
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_interfaces(duthosts, enum_dut_hostname, tbinfo):
    """compare the interfaces between observed states and target state"""

    duthost    = duthosts[enum_dut_hostname]
    host_facts = duthost.setup()['ansible_facts']
    mg_facts   = duthost.get_extended_minigraph_facts(tbinfo)

    verify_port(host_facts, mg_facts['minigraph_portchannels'].keys())
    for k, v in mg_facts['minigraph_portchannels'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each port channel member
        for member in v['members']:
            ans_ifname = "ansible_%s" % member
            pytest_assert("ipv4" not in host_facts[ans_ifname],
                          "LAG member {} has IP address {}".format(ans_ifname, host_facts[ans_ifname]))

    verify_port(host_facts, mg_facts['minigraph_vlans'].keys())

    for k, v in mg_facts['minigraph_vlans'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each vlan member
        for member in v['members']:
            ans_ifname = "ansible_%s" % member
            pytest_assert("ipv4" not in host_facts[ans_ifname],
                          "vlan member {} has IP address {}".format(ans_ifname, host_facts[ans_ifname]))

    verify_ip_address(host_facts, mg_facts['minigraph_portchannel_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_vlan_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_lo_interfaces'])

def verify_port(host_facts, ports):
    for port in ports:
        ans_ifname = "ansible_%s" % port
        pytest_assert(host_facts[ans_ifname]['active'], "interface {} is not active".format(ans_ifname))

def verify_ip_address(host_facts, intfs):
    for intf in intfs:
        if intf.has_key('attachto'):
            ans_ifname = "ansible_%s" % intf['attachto']
        else:
            ans_ifname = "ansible_%s" % intf['name']

        ip = IPAddress(intf['addr'])
        if ip.version == 4:
            addrs = []
            addrs.append(host_facts[ans_ifname]['ipv4'])
            if host_facts[ans_ifname].has_key('ipv4_secondaries'):
                for addr in host_facts[ans_ifname]['ipv4_secondaries']:
                    addrs.append(addr)
        else:
            addrs = host_facts[ans_ifname]['ipv6']

        found = False
        ips_found = []
        for addr in addrs:
            ips_found.append(addr['address'])
            print addr
            if IPAddress(addr['address']) == ip:
                found = True
                break
        pytest_assert(found, "{} not found in the list {}".format(ip, ips_found))
