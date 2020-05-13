import pytest
from netaddr import *
import time
import logging
import requests
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
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s announce route %s next-hop %s" % (neighbor, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost):

    logging.info("########### Setup for bgp speaker testing ###########")

    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
    logging.info("ptfip=%s" % ptfip)

    ptfhost.script("./scripts/remove_ip.sh")
    ptfhost.script("./scripts/change_mac.sh")

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    interface_facts = duthost.interface_facts()['ansible_facts']

    res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants.deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    bgp_speaker_asn = res['stdout']

    vlan_ips = generate_ips(3, "%s/%s" % (mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                                          mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
                            [IPAddress(mg_facts['minigraph_vlan_interfaces'][0]['addr'])])
    logging.info("Generated vlan_ips: %s" % str(vlan_ips))

    speaker_ips = generate_ips(2, mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0], [])
    speaker_ips.append(vlan_ips[0])
    logging.info("speaker_ips: %s" % str(speaker_ips))

    for ip in vlan_ips:
        duthost.command("ip route flush %s/32" % ip.ip)
        duthost.command("ip route add %s/32 dev %s" % (ip.ip, mg_facts['minigraph_vlan_interfaces'][0]['attachto']))

    port_num = [7000, 8000, 9000]

    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    lo_addr_prefixlen = int(mg_facts['minigraph_lo_interfaces'][0]['prefixlen'])

    vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']

    vlan_ports = []
    for i in range(0, 3):
        vlan_ports.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][i]])
    logging.info("vlan_ports: %s" % str(vlan_ports))

    logging.info("setup ip/routes in ptf")
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[0], vlan_ips[0]))
    ptfhost.shell("ifconfig eth%d:0 %s" % (vlan_ports[0], speaker_ips[0]))
    ptfhost.shell("ifconfig eth%d:1 %s" % (vlan_ports[0], speaker_ips[1]))

    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[1], vlan_ips[1]))
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[2], vlan_ips[2]))

    ptfhost.shell("ip route flush %s/%d" % (lo_addr, lo_addr_prefixlen))
    ptfhost.shell("ip route add %s/%d via %s" % (lo_addr, lo_addr_prefixlen, vlan_addr))

    logging.info("Start exabgp on ptf")
    for i in range(0, 3):
        local_ip = str(speaker_ips[i].ip)
        ptfhost.exabgp(name="bgps%d" % i,
                       state="started",
                       local_ip=local_ip,
                       router_id=local_ip,
                       peer_ip=lo_addr,
                       local_asn=bgp_speaker_asn,
                       peer_asn=mg_facts['minigraph_bgp_asn'],
                       port=str(port_num[i]))

    logging.info("########### Done setup for bgp speaker testing ###########")

    yield ptfip, mg_facts, interface_facts, vlan_ips, speaker_ips, port_num

    logging.info("########### Teardown for bgp speaker testing ###########")

    for i in range(0, 3):
        ptfhost.exabgp(name="bgps%d" % i, state="absent")

    for ip in vlan_ips:
        duthost.command("ip route flush %s/32" % ip.ip, module_ignore_errors=True)

    ptfhost.script("./scripts/remove_ip.sh")

    logging.info("########### Done teardown for bgp speaker testing ###########")


def test_bgp_speaker_bgp_sessions(common_setup_teardown, duthost, ptfhost, collect_techsupport):
    """Setup bgp speaker on T0 topology and verify bgp sessions are established
    """
    ptfip, mg_facts, interface_facts, vlan_ips, speaker_ips, port_num = common_setup_teardown

    logging.info("Wait some time to verify that bgp sessions are established")
    time.sleep(20)
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    assert all([v["state"] == "established" for _, v in bgp_facts["bgp_neighbors"].items()]), \
        "Not all bgp sessions are established"
    assert str(speaker_ips[2].ip) in bgp_facts["bgp_neighbors"], "No bgp session with PTF"


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, False, 1514)])
def test_bgp_speaker_announce_routes(common_setup_teardown, testbed, duthost, ptfhost, ipv4, ipv6, mtu, collect_techsupport):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    ptfip, mg_facts, interface_facts, vlan_ips, speaker_ips, port_num = common_setup_teardown

    logging.info("announce route")
    peer_range = mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0]
    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    lo_addr_prefixlen = int(mg_facts['minigraph_lo_interfaces'][0]['prefixlen'])
    prefix = '10.10.10.0/26'
    announce_route(ptfip, lo_addr, prefix, vlan_ips[1].ip, port_num[0])
    announce_route(ptfip, lo_addr, prefix, vlan_ips[2].ip, port_num[1])
    announce_route(ptfip, lo_addr, peer_range, vlan_ips[0].ip, port_num[2])

    logging.info("Wait some time to make sure routes announced to dynamic bgp neighbors")
    time.sleep(30)

    # The ping here is workaround for known issue:
    #     https://github.com/Azure/SONiC/issues/387 Pre-ARP support for static route config
    # When there is no arp entry for next hop, routes learnt from exabgp will not be set down to ASIC
    # Traffic to prefix 10.10.10.0 will be routed to vEOS VMs via default gateway.
    duthost.shell("ping %s -c 3" % vlan_ips[1].ip)
    duthost.shell("ping %s -c 3" % vlan_ips[2].ip)
    time.sleep(5)

    logging.info("Verify accepted prefixes of the dynamic neighbors are correct")
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    for ip in speaker_ips:
        assert bgp_facts['bgp_neighbors'][str(ip.ip)]['accepted prefixes'] == 1

    logging.info("Generate route-port map information")
    extra_vars = {'announce_prefix': '10.10.10.0/26',
                  'minigraph_portchannels': mg_facts['minigraph_portchannels'],
                  'minigraph_vlans': mg_facts['minigraph_vlans'],
                  'minigraph_port_indices': mg_facts['minigraph_port_indices']}
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    logging.info("extra_vars: %s" % str(ptfhost.host.options['variable_manager'].extra_vars))

    ptfhost.template(src="bgp_speaker/bgp_speaker_route.j2", dest="/root/bgp_speaker_route.txt")

    ptfhost.copy(src="ptftests", dest="/root")

    logging.info("run ptf test")

    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"testbed_type": testbed['topo']['name'],
                        "router_mac": interface_facts['ansible_interface_facts']['Ethernet0']['macaddress'],
                        "fib_info": "/root/bgp_speaker_route.txt",
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu },
                log_file="/tmp/bgp_speaker_test.FibTest.log",
                socket_recv_size=16384)
