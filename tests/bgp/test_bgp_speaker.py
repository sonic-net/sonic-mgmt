import pytest
from netaddr import *
import time
import logging
import requests
import ipaddress
import json

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_tcp_connection
from tests.common.dualtor.mux_simulator_control import mux_server_url     # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports
from tests.common.dualtor.dual_tor_utils import map_hostname_to_tor_side

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)
PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'


def generate_ips(num, prefix, exclude_ips):
    """
       Generate random ips within prefix
    """
    prefix = IPNetwork(prefix)
    exclude_ips.append(prefix.broadcast)
    exclude_ips.append(prefix.network)

    generated_ips = []
    for available_ip in prefix:
        if available_ip not in exclude_ips:
            generated_ips.append(IPNetwork(str(available_ip) + '/' + str(prefix.prefixlen)))
        if len(generated_ips) == num:
            break
    else:
        raise Exception("Not enough available IPs")

    return generated_ips

def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)

def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)

def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200

@pytest.fixture(scope="module")
def common_setup_teardown(duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo, toggle_all_simulator_ports):

    logger.info("########### Setup for bgp speaker testing ###########")

    duthost = duthosts[rand_one_dut_hostname]

    if 'dualtor' in tbinfo['topo']['name']:
        toggle_all_simulator_ports(map_hostname_to_tor_side(tbinfo, rand_one_dut_hostname))

    ptfip = ptfhost.mgmt_ip
    logger.info("ptfip=%s" % ptfip)

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    interface_facts = duthost.interface_facts()['ansible_facts']

    constants_stat = duthost.stat(path="/etc/sonic/constants.yml")
    if constants_stat["stat"]["exists"]:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants.deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    else:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/deployment_id_asn_map.yml -v \"deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    bgp_speaker_asn = res['stdout']

    vlan_ips = generate_ips(3, "%s/%s" % (mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                                          mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
                            [IPAddress(mg_facts['minigraph_vlan_interfaces'][0]['addr'])])
    logger.info("Generated vlan_ips: %s" % str(vlan_ips))

    speaker_ips = generate_ips(2, mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0], [])
    speaker_ips.append(vlan_ips[0])
    logger.info("speaker_ips: %s" % str(speaker_ips))

    port_num = [7000, 8000, 9000]

    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']
    lo_addr_prefixlen = int(mg_facts['minigraph_lo_interfaces'][0]['prefixlen'])

    vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']

    vlan_ports = []
    for i in range(0, 3):
        vlan_ports.append(mg_facts['minigraph_ptf_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][i]])
    logger.info("vlan_ports: %s" % str(vlan_ports))

    # Generate ipv6 nexthops
    vlan_ipv6_entry = mg_facts['minigraph_vlan_interfaces'][1]
    vlan_ipv6_prefix = "%s/%s" % (vlan_ipv6_entry["addr"], vlan_ipv6_entry["prefixlen"])
    vlan_ipv6_address = vlan_ipv6_entry["addr"]
    vlan_if_name = vlan_ipv6_entry['attachto']
    nexthops_ipv6 = generate_ips(3, vlan_ipv6_prefix, [IPAddress(vlan_ipv6_address)])
    logger.info("Generated nexthops_ipv6: %s" % str(nexthops_ipv6))
    logger.info("setup ip/routes in ptf")
    for i in [0, 1, 2]:
        ptfhost.shell("ip -6 addr add %s dev eth%d:%d" % (nexthops_ipv6[i], vlan_ports[0], i))

    # Issue a ping command to populate entry for next_hop
    for nh in nexthops_ipv6:
        duthost.shell("ping6 %s -c 3" % nh.ip)

    logger.info("setup ip/routes in ptf")
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[0], vlan_ips[0]))
    ptfhost.shell("ifconfig eth%d:0 %s" % (vlan_ports[0], speaker_ips[0]))
    ptfhost.shell("ifconfig eth%d:1 %s" % (vlan_ports[0], speaker_ips[1]))

    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[1], vlan_ips[1]))
    ptfhost.shell("ifconfig eth%d %s" % (vlan_ports[2], vlan_ips[2]))

    ptfhost.shell("ip route flush %s/%d" % (lo_addr, lo_addr_prefixlen))
    ptfhost.shell("ip route add %s/%d via %s" % (lo_addr, lo_addr_prefixlen, vlan_addr))

    logger.info("clear ARP cache on DUT")
    duthost.command("sonic-clear arp")
    for ip in vlan_ips:
        duthost.command("ip route flush %s/32" % ip.ip)
        # The ping here is workaround for known issue:
        # https://github.com/Azure/SONiC/issues/387 Pre-ARP support for static route config
        # When there is no arp entry for next hop, routes learnt from exabgp will not be set down to ASIC
        # Also because of issue https://github.com/Azure/sonic-buildimage/issues/5185 ping is done before route addition.
        duthost.shell("ping %s -c 3" % ip.ip)
        time.sleep(2)
        duthost.command("ip route add %s/32 dev %s" % (ip.ip, mg_facts['minigraph_vlan_interfaces'][0]['attachto']))

    logger.info("Start exabgp on ptf")
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

    # check exabgp http_api port is ready
    http_ready = True
    for i in range(0, 3):
        http_ready = wait_tcp_connection(localhost, ptfip, port_num[i])
        if not http_ready:
            break

    logger.info("########### Done setup for bgp speaker testing ###########")

    yield ptfip, mg_facts, interface_facts, vlan_ips, nexthops_ipv6, vlan_if_name, speaker_ips, port_num, http_ready

    logger.info("########### Teardown for bgp speaker testing ###########")

    for i in range(0, 3):
        ptfhost.exabgp(name="bgps%d" % i, state="absent")
    logger.info("exabgp stopped")

    for ip in vlan_ips:
        duthost.command("ip route flush %s/32" % ip.ip, module_ignore_errors=True)

    duthost.command("sonic-clear arp")
    duthost.command("sonic-clear fdb all")
    duthost.command("ip -6 neigh flush all")

    logger.info("########### Done teardown for bgp speaker testing ###########")


def test_bgp_speaker_bgp_sessions(common_setup_teardown, duthosts, rand_one_dut_hostname):
    """Setup bgp speaker on T0 topology and verify bgp sessions are established
    """
    duthost = duthosts[rand_one_dut_hostname]
    ptfip, mg_facts, interface_facts, vlan_ips, _, _, speaker_ips, port_num, http_ready = common_setup_teardown
    assert http_ready

    logger.info("Wait some time to verify that bgp sessions are established")
    time.sleep(20)
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    assert all([v["state"] == "established" for _, v in bgp_facts["bgp_neighbors"].items()]), \
        "Not all bgp sessions are established"
    assert str(speaker_ips[2].ip) in bgp_facts["bgp_neighbors"], "No bgp session with PTF"


# For dualtor
@pytest.fixture(scope='module')
def vlan_mac(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']
    dut_vlan_mac = None
    for vlan in config_facts.get('VLAN', {}).values():
        if 'mac' in vlan:
            logger.debug('Found VLAN mac')
            dut_vlan_mac = vlan['mac']
            break
    if not dut_vlan_mac:
        logger.debug('No VLAN mac, use default router_mac')
        dut_vlan_mac = duthost.facts['router_mac']
    return dut_vlan_mac


# For dualtor
def get_dut_enabled_ptf_ports(tbinfo, hostname):
    dut_index = str(tbinfo['duts_map'][hostname])
    ptf_ports = set(tbinfo['topo']['ptf_map'][dut_index].values())
    disabled_ports = set()
    if dut_index in tbinfo['topo']['ptf_map_disabled']:
        disabled_ports = set(tbinfo['topo']['ptf_map_disabled'][dut_index].values())
    return ptf_ports - disabled_ports


# For dualtor
def get_dut_vlan_ptf_ports(mg_facts):
    ports = set()
    for vlan in mg_facts['minigraph_vlans']:
        for member in mg_facts['minigraph_vlans'][vlan]['members']:
            ports.add(mg_facts['minigraph_port_indices'][member])
    return ports


def bgp_speaker_announce_routes_common(common_setup_teardown,
                                       tbinfo, duthost, ptfhost, ipv4, ipv6, mtu,
                                       family, prefix, nexthop_ips, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    ptfip, mg_facts, interface_facts, vlan_ips, _, vlan_if_name, speaker_ips, port_num, http_ready = common_setup_teardown
    assert http_ready

    logger.info("announce route")
    peer_range = mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0]
    lo_addr = mg_facts['minigraph_lo_interfaces'][0]['addr']

    logger.info("Announce ip%s prefixes over ipv4 bgp sessions" % family)
    announce_route(ptfip, lo_addr, prefix, nexthop_ips[1].ip, port_num[0])
    announce_route(ptfip, lo_addr, prefix, nexthop_ips[2].ip, port_num[1])
    announce_route(ptfip, lo_addr, peer_range, vlan_ips[0].ip, port_num[2])

    logger.info("Wait some time to make sure routes announced to dynamic bgp neighbors")
    time.sleep(30)

    logger.info("Verify accepted prefixes of the dynamic neighbors are correct")
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    for ip in speaker_ips:
        assert bgp_facts['bgp_neighbors'][str(ip.ip)]['accepted prefixes'] == 1

    logger.info("Verify nexthops and nexthop interfaces for accepted prefixes of the dynamic neighbors")
    rtinfo = duthost.get_ip_route_info(ipaddress.ip_network(unicode(prefix)))
    nexthops_ip_set = { str(nexthop.ip) for nexthop in nexthop_ips }
    assert len(rtinfo["nexthops"]) == 2
    for i in [0,1]:
        assert str(rtinfo["nexthops"][i][0]) in nexthops_ip_set
        assert rtinfo["nexthops"][i][1] == unicode(vlan_if_name)

    logger.info("Generate route-port map information")
    extra_vars = {'announce_prefix': prefix,
                  'minigraph_portchannels': mg_facts['minigraph_portchannels'],
                  'minigraph_vlans': mg_facts['minigraph_vlans'],
                  'minigraph_port_indices': mg_facts['minigraph_ptf_indices']}
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    logger.info("extra_vars: %s" % str(ptfhost.host.options['variable_manager'].extra_vars))

    ptfhost.template(src="bgp/templates/bgp_speaker_route.j2", dest="/root/bgp_speaker_route_%s.txt" % family)

    # For fib PTF testing, including dualtor
    ptf_test_port_map = {}
    enabled_ptf_ports = get_dut_enabled_ptf_ports(tbinfo, duthost.hostname)
    vlan_ptf_ports = get_dut_vlan_ptf_ports(mg_facts)
    logger.debug('enabled_ptf_ports={}, vlan_ptf_ports={}, vlan_mac={}'\
        .format(enabled_ptf_ports, vlan_ptf_ports, vlan_mac))
    for port in enabled_ptf_ports:
        if port in vlan_ptf_ports:
            target_mac = vlan_mac
        else:
            target_mac = duthost.facts['router_mac']
        ptf_test_port_map[str(port)] = {
            'target_dut': 0,
            'target_mac': target_mac
        }
    ptfhost.copy(content=json.dumps(ptf_test_port_map), dest=PTF_TEST_PORT_MAP)

    logger.info("run ptf test")

    ptf_runner(ptfhost,
                "ptftests",
                "fib_test.FibTest",
                platform_dir="ptftests",
                params={"router_macs": [duthost.facts['router_mac']],
                        "ptf_test_port_map": PTF_TEST_PORT_MAP,
                        "fib_info_files": ["/root/bgp_speaker_route_%s.txt" % family],
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "testbed_mtu": mtu,
                        "test_balancing": False},
                log_file="/tmp/bgp_speaker_test.FibTest.log",
                socket_recv_size=16384)

    logger.info("Withdraw routes")
    withdraw_route(ptfip, lo_addr, prefix, nexthop_ips[1].ip, port_num[0])
    withdraw_route(ptfip, lo_addr, prefix, nexthop_ips[2].ip, port_num[1])
    withdraw_route(ptfip, lo_addr, peer_range, vlan_ips[0].ip, port_num[2])

    logger.info("Nexthop ip%s tests are done" % family)


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(True, False, 1514)])
def test_bgp_speaker_announce_routes(common_setup_teardown, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[3]
    bgp_speaker_announce_routes_common(common_setup_teardown, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v4", "10.10.10.0/26", nexthops, vlan_mac)


@pytest.mark.parametrize("ipv4, ipv6, mtu", [pytest.param(False, True, 1514)])
def test_bgp_speaker_announce_routes_v6(common_setup_teardown, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[4]
    bgp_speaker_announce_routes_common(common_setup_teardown, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v6", "fc00:10::/64", nexthops, vlan_mac)
