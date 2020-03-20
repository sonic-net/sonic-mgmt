from ansible_host import AnsibleHost
from netaddr import IPAddress
import pytest

def test_interfaces(ansible_adhoc, testbed):
    """compare the interfaces between observed states and target state"""

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)

    host_facts = ans_host.setup()['ansible_facts']
    mg_facts   = ans_host.minigraph_facts(host=hostname)['ansible_facts']

    verify_port(host_facts, mg_facts['minigraph_portchannels'].keys())
    for k, v in mg_facts['minigraph_portchannels'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each port channel member
        for member in v['members']:
            ans_ifname = "ansible_%s" % member
            assert not host_facts[ans_ifname].has_key("ipv4")

    verify_port(host_facts, mg_facts['minigraph_vlans'].keys())

    for k, v in mg_facts['minigraph_vlans'].items():
        verify_port(host_facts, v['members'])
        # verify no ipv4 address for each vlan member
        for member in v['members']:
            ans_ifname = "ansible_%s" % member
            assert not host_facts[ans_ifname].has_key("ipv4")

    verify_ip_address(host_facts, mg_facts['minigraph_portchannel_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_vlan_interfaces'])
    verify_ip_address(host_facts, mg_facts['minigraph_lo_interfaces'])

def verify_port(host_facts, ports):
    for port in ports:
        ans_ifname = "ansible_%s" % port
        assert host_facts[ans_ifname]['active']
        
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
        if not found:
            pytest.fail("%s not found in the list %s" % (ip, ips_found))
