import pytest
from netaddr import *
import sys
import time
import ipaddress
import requests
from ansible_host import AnsibleHost
from ptf_runner import ptf_runner

def generate_ips(num, prefix, exclude_ips):
    """
       Generate random ips within prefix
    """
    prefix = IPNetwork(prefix)
    exclude_ips.append(prefix.broadcast)
    exclude_ips.append(prefix.network)
    available_ips = list(prefix)

    if len(available_ips) - len(exclude_ips)< num:
        raise Exception("Not enough available IPs")

    generated_ips = []
    for available_ip in available_ips:
        if available_ip not in exclude_ips:
            generated_ips.append(IPNetwork(str(available_ip) + '/' + str(prefix.prefixlen)))
        if len(generated_ips) == num:
            break

    return generated_ips

def announce_route(ptfip, neighbor, route, nexthop, port):
    url  = "http://%s:%d" % (ptfip, port)
    data = { "command": "neighbor %s announce route %s next-hop %s" % (neighbor, route, nexthop) }
    r = requests.post(url, data=data)
    assert r.status_code == 200

@pytest.mark.parametrize(
    "ipv4, ipv6, mtu",
    [	pytest.param(True, False, 1514),	],
    )
def test_bgp(localhost, ansible_adhoc, testbed, ipv4, ipv6, mtu):
    """setup bgp speaker on T0 topology and verify routes advertised
    by bgp speaker is received by T0 TOR
    """

    hostname = testbed['dut']
    ptf_hostname = testbed['ptf']
    host = AnsibleHost(ansible_adhoc, hostname)
    ptfhost = AnsibleHost(ansible_adhoc, ptf_hostname)
    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptf_hostname).vars['ansible_host']

    mg_facts = host.minigraph_facts(host=hostname)['ansible_facts']
    host_facts  = host.setup()['ansible_facts']

    res = host.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants.deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    bgp_speaker_asn = res['stdout']

    vlan_ips = generate_ips(3, \
            "%s/%s" % (mg_facts['minigraph_vlan_interfaces'][0]['addr'], mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
            [IPAddress(mg_facts['minigraph_vlan_interfaces'][0]['addr'])])

    # three speaker ips, two from peer range, another is vlan ip [0]
    speaker_ips = generate_ips(2, mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0], [])
    speaker_ips.append(vlan_ips[0])

    for ip in vlan_ips:
        host.command("ip route flush %s/32" % ip.ip)
        host.command("ip route add %s/32 dev %s" % (ip.ip, mg_facts['minigraph_vlan_interfaces'][0]['attachto']))

    root_dir   = "/root"
    port_num = [5000, 6000, 7000]

    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    lo_addr_prefixlen = int(mg_facts['minigraph_lo_interfaces'][0]['prefixlen'])

    vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']

    vlan_ports = []
    for i in range(0, 3):
        vlan_ports.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][i]])

    # setup ip/routes in ptf
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[0], vlan_ips[0]))
    ptfhost.shell("ifconfig eth%d:0 %s" % (vlan_ports[0], speaker_ips[0]))
    ptfhost.shell("ifconfig eth%d:1 %s" % (vlan_ports[0], speaker_ips[1]))

    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[1], vlan_ips[1]))
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[2], vlan_ips[2]))

    ptfhost.shell("ip route flush %s/%d" % (lo_addr, lo_addr_prefixlen))
    ptfhost.shell("ip route add %s/%d via %s" % (lo_addr, lo_addr_prefixlen, vlan_addr))

    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    for i in range(0, 3):
        local_ip = str(speaker_ips[i].ip)
        ptfhost.exabgp(name="bgps%d" % i, \
                       state="started", \
                       local_ip=local_ip,
                       router_id=local_ip,
                       peer_ip=lo_addr,
                       local_asn=bgp_speaker_asn,
                       peer_asn=mg_facts['minigraph_bgp_asn'],
                       port=str(port_num[i]))

    time.sleep(10)

    peer_range = mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0]
    prefix = '10.10.10.0/26'

    # announce route
    announce_route(ptfip, lo_addr, prefix, vlan_ips[1].ip, port_num[0])
    announce_route(ptfip, lo_addr, prefix, vlan_ips[2].ip, port_num[1])
    announce_route(ptfip, lo_addr, peer_range, vlan_ips[0].ip, port_num[2])

    # make sure routes announced to dynamic bgp neighbors
    time.sleep(60)

    bgp_facts = host.bgp_facts()['ansible_facts']

    # Verify bgp sessions are established
    for k, v in bgp_facts['bgp_neighbors'].items():
        assert v['state'] == 'established'

    # Verify accepted prefixes of the dynamic neighbors are correct
    for ip in speaker_ips:
        assert bgp_facts['bgp_neighbors'][str(ip.ip)]['accepted prefixes'] == 1
    assert bgp_facts['bgp_neighbors'][str(vlan_ips[0].ip)]['accepted prefixes'] == 1

    ## Run ptf test
    # Generate route-port map information
    extra_vars = \
                { 'announce_prefix': '10.10.10.0/26',
                  'minigraph_portchannels'  : mg_facts['minigraph_portchannels'],
                  'minigraph_vlans'  : mg_facts['minigraph_vlans'],
                  'minigraph_port_indices'  : mg_facts['minigraph_port_indices']}
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)

    ptfhost.template(src="bgp_speaker/bgp_speaker_route.j2", dest="/root/bgp_speaker_route.txt")

    ptfhost.copy(src="ptftests", dest=root_dir)

    ptf_runner(ptfhost, \
               "ptftests",
               "fib_test.FibTest",
               platform_dir="ptftests",
               params={"testbed_type": "t0",
                      "router_mac": host_facts['ansible_Ethernet0']['macaddress'],
                      "fib_info": "/root/bgp_speaker_route.txt",
                      "ipv4": ipv4,
                      "ipv6": ipv6,
                      "testbed_mtu": mtu },
               log_file="/tmp/bgp_speaker_test.FibTest.log",
               socket_recv_size=16384)

    for i in range(0, 3):
        ptfhost.exabgp(name="bgps%d" % i, state="absent")

    for ip in vlan_ips:
        host.command("ip route flush %s/32" % ip.ip)

    ptfhost.shell("ip addr flush dev eth{}".format(mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][0]]))
