from netaddr import IPAddress
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_interfaces(duthosts, enum_frontend_dut_hostname, tbinfo, enum_asic_index):
    """compare the interfaces between observed states and target state"""

    duthost = duthosts[enum_frontend_dut_hostname]
    asic_host = duthost.asic_instance(enum_asic_index)
    host_facts = asic_host.interface_facts()['ansible_facts']['ansible_interface_facts']
    mg_facts = asic_host.get_extended_minigraph_facts(tbinfo)
    verify_port(host_facts, mg_facts['minigraph_portchannels'].keys())
    for k, v in mg_facts['minigraph_portchannels'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each port channel member
        for member in v['members']:
            pytest_assert("ipv4" not in host_facts[member],
                          "LAG member {} has IP address {}".format(member, host_facts[member]))

    verify_port(host_facts, mg_facts['minigraph_vlans'].keys())

    for k, v in mg_facts['minigraph_vlans'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each vlan member
        for member in v['members']:
            pytest_assert("ipv4" not in host_facts[member],
                          "vlan member {} has IP address {}".format(member, host_facts[member]))

    verify_ip_address(host_facts, mg_facts['minigraph_portchannel_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_vlan_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_lo_interfaces'])

    topo = tbinfo["topo"]["name"]
    router_mac = duthost.facts['router_mac']
    verify_mac_address(host_facts, mg_facts['minigraph_portchannel_interfaces'], router_mac)
    if "dualtor" not in topo:
        verify_mac_address(host_facts, mg_facts['minigraph_vlan_interfaces'], router_mac)
    verify_mac_address(host_facts, mg_facts['minigraph_interfaces'], router_mac)

def verify_port(host_facts, ports):
    for port in ports:
        pytest_assert(host_facts[port]['active'], "interface {} is not active".format(port))

def verify_mac_address(host_facts, intfs, router_mac):
    for intf in intfs:
        if 'attachto' in intf:
            ifname = intf['attachto']
        else:
            ifname = intf['name']

        pytest_assert(host_facts[ifname]['macaddress'].lower() == router_mac.lower(), \
                "interface {} mac address {} does not match router mac {}".format(ifname, host_facts[ifname]['macaddress'], router_mac))

def verify_ip_address(host_facts, intfs):
    for intf in intfs:
        if intf.has_key('attachto'):
            ifname = intf['attachto']
        else:
            ifname = intf['name']

        ip = IPAddress(intf['addr'])
        if ip.version == 4:
            addrs = []
            addrs.append(host_facts[ifname]['ipv4'])
            if host_facts[ifname].has_key('ipv4_secondaries'):
                for addr in host_facts[ifname]['ipv4_secondaries']:
                    addrs.append(addr)
        else:
            addrs = host_facts[ifname]['ipv6']

        found = False
        ips_found = []
        for addr in addrs:
            ips_found.append(addr['address'])
            print addr
            if IPAddress(addr['address']) == ip:
                found = True
                break
        pytest_assert(found, "{} not found in the list {}".format(ip, ips_found))
