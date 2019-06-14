from netaddr import *
import sys
import time
import ipaddress
from ansible_host import ansible_host
from ptf import ptf_runner

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

def test_bgp_speaker(localhost, ansible_adhoc, testbed):
    """setup bgp speaker on T0 topology and verify routes advertised
    by bgp speaker is received by T0 TOR
    """

    hostname = testbed['dut']
    ptf_hostname = testbed['ptf']
    host = ansible_host(ansible_adhoc, hostname)
    ptfhost = ansible_host(ansible_adhoc, ptf_hostname)

    mg_facts = host.minigraph_facts(host=hostname)['ansible_facts']
    host_facts  = host.setup()['ansible_facts']

    res = host.shell("sonic-cfggen -m -d -y /etc/sonic/deployment_id_asn_map.yml -v \"deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
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
    exabgp_dir = "/root/exabgp"
    helper_dir = "/root/helpers"
    port_num = [5000, 6000, 7000]
    cfnames = ["config_1.ini", "config_2.ini", "config_3.ini"]
    vlan_ports = []
    for i in range(0, 3):
        vlan_ports.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][i]])

    ptfhost.file(path=exabgp_dir, state="directory")
    ptfhost.file(path=helper_dir, state="directory")
    ptfhost.copy(src="bgp_speaker/dump.py", dest=helper_dir)
    ptfhost.copy(src="bgp_speaker/http_api.py", dest=helper_dir)
    ptfhost.copy(src="bgp_speaker/announce_routes.py", dest=helper_dir)

    # deploy config file
    extra_vars = \
                { 'helper_dir': helper_dir,
                  'exabgp_dir': exabgp_dir,
                  'lo_addr'   : mg_facts['minigraph_lo_interfaces'][0]['addr'],
                  'lo_addr_prefixlen' : mg_facts['minigraph_lo_interfaces'][0]['prefixlen'],
                  'vlan_addr' : mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                  'peer_range': mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0],
                  'announce_prefix': '10.10.10.0/26',
                  'minigraph_portchannels'  : mg_facts['minigraph_portchannels'],
                  'minigraph_vlans'  : mg_facts['minigraph_vlans'],
                  'minigraph_port_indices'  : mg_facts['minigraph_port_indices'],
                  'peer_asn'  : mg_facts['minigraph_bgp_asn'],
                  'peer_asn'  : mg_facts['minigraph_bgp_asn'],
                  'my_asn'    : bgp_speaker_asn,
                  'vlan_ports' : vlan_ports,
                  'port_num'  : port_num,
                  'speaker_ips': [str(ip) for ip in speaker_ips],
                  'vlan_ips': [str(ip) for ip in vlan_ips],
                  'cfnames': cfnames }

    for i in range(0, 3):
        extra_vars.update({ 'cidx':i })
        extra_vars.update({ 'speaker_ip': str(speaker_ips[i].ip) })
        ptfhost.host.options['variable_manager'].extra_vars = extra_vars
        ptfhost.template(src="bgp_speaker/config.j2", dest="%s/%s" % (exabgp_dir, cfnames[i]))

    # deploy routes
    ptfhost.template(src="bgp_speaker/routes.j2", dest="%s/%s" % (exabgp_dir, "routes"))

    # deploy start script
    ptfhost.template(src="bgp_speaker/start.j2", dest="%s/%s" % (exabgp_dir, "start.sh"), mode="u+rwx")
    # kill exabgp
    res = ptfhost.shell("pkill exabgp || true")
    print res

    # start exabgp instance
    res = ptfhost.shell("bash %s/start.sh" % exabgp_dir)
    print res

    time.sleep(10)

    # announce route
    res = ptfhost.shell("nohup python %s/announce_routes.py %s/routes >/dev/null 2>&1 &" % (helper_dir, exabgp_dir))
    print res

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


    # Generate route-port map information
    ptfhost.template(src="bgp_speaker/bgp_speaker_route.j2", dest="/root/bgp_speaker_route.txt")

    ptfhost.copy(src="ptftests", dest=root_dir)

    ptf_runner(ptfhost, \
               "ptftests",
               "fib_test.FibTest",
               platform_dir="ptftests",
               params={"testbed_type": "t0",
                      "router_mac": host_facts['ansible_Ethernet0']['macaddress'],
                      "fib_info": "/root/bgp_speaker_route.txt",
                      "ipv4": True,
                      "ipv6": False },
               log_file="/tmp/bgp_speaker_test.FibTest.log")

    res = ptfhost.shell("pkill exabgp || true")

    for ip in vlan_ips:
        host.command("ip route flush %s/32" % ip.ip)

    # ptfhost.shell("ip addr flush dev eth{{ '%d' % (minigraph_vlans[minigraph_vlan_interfaces[0]['attachto']]['members'][0] | replace("Ethernet", "") | int / 4)}}
