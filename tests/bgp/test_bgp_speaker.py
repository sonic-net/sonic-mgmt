import pytest
from netaddr import *
import time
import logging
import requests
import ipaddress
import json

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_tcp_connection
from tests.common.helpers.assertions import pytest_require
from tests.common import constants


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


@pytest.fixture(scope="module", autouse=True)
def skip_dualtor(tbinfo):
    """Skip running `test_bgp_speaker` over dualtor."""
    pytest_require("dualtor" not in tbinfo["topo"]["name"], "Skip 'test_bgp_speaker over dualtor.'")

def dut_bgp_asn_update_status(duthost, bgp_speaker_asn, dut_asn, Asntype):
    bgpvacstatus = "default"
    if Asntype == "2byte" or Asntype == "4byte":
        logger.info("Updating BGPVac ASN to 4 byte")
        logger.info("Bgp_speaker_asn =%s" % bgp_speaker_asn)
        logger.info("T0 ASN = %s" % dut_asn)
        bgpvacstatus = "fourbyte"
    duthost.command("vtysh -c \"conf t\" \
            -c \"router bgp %s\" i\
            -c \"neighbor BGPSLBPassive remote-as %s\" \
            -c \"neighbor BGPSLBPassive activate\" \
            -c \"neighbor BGPVac remote-as %s\" \
            -c \"neighbor BGPVac activate\" \
            -c \"exit\"" % (dut_asn, bgp_speaker_asn, bgp_speaker_asn))
    
    return bgpvacstatus

def dut_config_change(duthost, dut_4basn):
    duthost.shell("sudo cp /etc/sonic/config_db.json /etc/sonic/config_db_org.json")
    bgp_config = duthost.shell("sonic-cfggen -d  --var-json 'DEVICE_METADATA'")['stdout']
    bgp_config_json = json.loads(bgp_config)
    for _, config in bgp_config_json.items():
        config['bgp_asn'] = dut_4basn
    bgp_config_json = {"DEVICE_METADATA": bgp_config_json}
    logger.info(bgp_config_json)
    TMP_FILE = "/tmp/bgp_config.json"
    with open(TMP_FILE, "w") as f:
        json.dump(bgp_config_json, f)

    duthost.copy(src=TMP_FILE, dest=TMP_FILE)
    duthost.shell("sonic-cfggen -j {} -w".format(TMP_FILE))
    time.sleep(10)
    duthost.shell("config save -y")
    time.sleep(10)
    is_config_applied=duthost.shell("sudo config reload -y")
    time.sleep(20)
    logger.info(is_config_applied)
    logger.info("wait for configuration to be applied")
    time.sleep(30)
    updated_asn=duthost.shell("show ip bgp sum")
    logger.info("New T0 ASN = %s" % updated_asn)
    result="false"
    for item in updated_asn['stdout_lines']:
        if dut_4basn in item:
            result= "true"
            break

    return result

def dut_config_reset(duthost, dut_asn_default):
    duthost.shell("sudo cp /etc/sonic/config_db_org.json /etc/sonic/config_db.json")
    duthost.shell("sudo config reload -y")
    time.sleep(10)
    logger.info("wait for configuration to be applied")
    time.sleep(40)
    updated_asn=duthost.shell("show ip bgp sum")
    logger.info(updated_asn)
    logger.info(updated_asn['stdout_lines'])
    result="false"
    for item in updated_asn['stdout_lines']:
        if str(dut_asn_default) in item:
            result="true"
            break
    return result

@pytest.fixture
def common_setup_teardown(duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo, request):

    logger.info("########### Setup for bgp speaker testing ###########")
    logger.info(request.param)

    duthost = duthosts[rand_one_dut_hostname]

    ptfip = ptfhost.mgmt_ip
    logger.info("ptfip=%s" % ptfip)

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    interface_facts = duthost.interface_facts()['ansible_facts']

    constants_stat = duthost.stat(path="/etc/sonic/constants.yml")
    if constants_stat["stat"]["exists"]:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/constants.yml -v \"constants.deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    else:
        res = duthost.shell("sonic-cfggen -m -d -y /etc/sonic/deployment_id_asn_map.yml -v \"deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")
    bgp_speaker_asn_default = res['stdout']
    bgp_dut_asn = mg_facts['minigraph_bgp_asn']
    bgp_dut_asn_default = mg_facts['minigraph_bgp_asn']
    bgp_speaker_4byteasn=bgp_speaker_asn_default
    bgp_speaker_asn=bgp_speaker_asn_default
    if "4byte" in request.param:
        bgp_dut_asn = "65538"
        dut_4basn_status=dut_config_change(duthost, bgp_dut_asn)
        assert dut_4basn_status=="true"


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
    if "backend" in tbinfo["topo"]["name"]:
        vlan_id = mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['vlanid']
        ptf_ports = [("eth%s" % _) + constants.VLAN_SUB_INTERFACE_SEPARATOR + vlan_id for _ in vlan_ports]
    else:
        ptf_ports = ["eth%s" % _ for _ in vlan_ports]
    logger.info("vlan_ports: %s" % str(vlan_ports))
    logger.info("ptf_ports: %s" % ptf_ports)

    # Generate ipv6 nexthops
    vlan_ipv6_entry = mg_facts['minigraph_vlan_interfaces'][1]
    vlan_ipv6_prefix = "%s/%s" % (vlan_ipv6_entry["addr"], vlan_ipv6_entry["prefixlen"])
    vlan_ipv6_address = vlan_ipv6_entry["addr"]
    vlan_if_name = vlan_ipv6_entry['attachto']
    nexthops_ipv6 = generate_ips(3, vlan_ipv6_prefix, [IPAddress(vlan_ipv6_address)])
    logger.info("Generated nexthops_ipv6: %s" % str(nexthops_ipv6))
    logger.info("setup ip/routes in ptf")
    
    ptf_interfaces = ptfhost.shell("ip -6 addr")
    

    for i in [0, 1, 2]:
        #logger.info(nexthops_ipv6[i])
        if str(nexthops_ipv6[i]) in ptf_interfaces['stdout']:
            ptfhost.shell("ip -6 addr del %s dev %s:%d" % (nexthops_ipv6[i], ptf_ports[0], i))

    for i in [0, 1, 2]:
        ptfhost.shell("ip -6 addr add %s dev %s:%d" % (nexthops_ipv6[i], ptf_ports[0], i))

    # Issue a ping command to populate entry for next_hop
    for nh in nexthops_ipv6:
        duthost.shell("ping6 %s -c 3" % nh.ip)

    logger.info("setup ip/routes in ptf")
    ptfhost.shell("ifconfig %s %s" % (ptf_ports[0], vlan_ips[0]))
    ptfhost.shell("ifconfig %s:0 %s" % (ptf_ports[0], speaker_ips[0]))
    ptfhost.shell("ifconfig %s:1 %s" % (ptf_ports[0], speaker_ips[1]))

    ptfhost.shell("ifconfig %s %s" % (ptf_ports[1], vlan_ips[1]))
    ptfhost.shell("ifconfig %s %s" % (ptf_ports[2], vlan_ips[2]))

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

    if ("2byte" in request.param) or ("4byte" in request.param):
        bgp_speaker_4byteasn="65536"
        bgp_speaker_asn=bgp_speaker_4byteasn
        logger.info("bgpasn={}".format(bgp_speaker_4byteasn))

        bgpvacstatus = dut_bgp_asn_update_status(duthost, bgp_speaker_4byteasn, bgp_dut_asn, request.param)

        logger.info("bgpvacstatus=%s"%bgpvacstatus)


    logger.info("Bgp Speaker ASN={}".format(bgp_speaker_asn))
    logger.info("Sonic device ASN={}".format(bgp_dut_asn))


    logger.info("Start exabgp on ptf")
    for i in range(0, 3):
        local_ip = str(speaker_ips[i].ip)
        ptfhost.exabgp(name="bgps%d" % i,
                       state="started",
                       local_ip=local_ip,
                       router_id=local_ip,
                       peer_ip=lo_addr,
                       local_asn=bgp_speaker_asn,
                       peer_asn=bgp_dut_asn,
                       port=str(port_num[i]))

    # check exabgp http_api port is ready
    http_ready = True
    for i in range(0, 3):
        http_ready = wait_tcp_connection(localhost, ptfip, port_num[i])
        if not http_ready:
            break

    logger.info("########### Done setup for bgp speaker testing ###########")

    yield ptfip, mg_facts, interface_facts, vlan_ips, nexthops_ipv6, vlan_if_name, speaker_ips, port_num, http_ready, bgp_dut_asn, bgp_speaker_4byteasn, bgp_speaker_asn_default

    logger.info("########### Teardown for bgp speaker testing ###########")

    for i in range(0, 3):
        ptfhost.exabgp(name="bgps%d" % i, state="absent")
    logger.info("exabgp stopped")

    for ip in vlan_ips:
        duthost.command("ip route flush %s/32" % ip.ip, module_ignore_errors=True)

    duthost.command("sonic-clear arp")
    duthost.command("sonic-clear fdb all")
    duthost.command("ip -6 neigh flush all")

    if "4byte" in request.param:
        dut_config_reset(duthost, bgp_dut_asn_default)
        bgp_dut_asn=bgp_dut_asn_default
        logger.info("resetting bgpvac")
        dut_bgp_asn_update_status(duthost, bgp_speaker_asn_default, bgp_dut_asn, "default")

    if "2byte" in request.param:
        bgp_dut_asn=bgp_dut_asn_default
        logger.info("resetting bgpvac")
        dut_bgp_asn_update_status(duthost, bgp_speaker_asn_default, bgp_dut_asn, "default")


    logger.info("########### Done teardown for bgp speaker testing ###########")

@pytest.mark.parametrize('common_setup_teardown', [
      ['']
   ], indirect = True)
@pytest.mark.parametrize("Asntype", [pytest.param("")])
def test_bgp_speaker_bgp_sessions(common_setup_teardown, Asntype, duthosts, rand_one_dut_hostname, ptfhost):
    """Setup bgp speaker on T0 topology and verify bgp sessions are established
    """
    duthost = duthosts[rand_one_dut_hostname]
    ptfip, mg_facts, interface_facts, vlan_ips, _, _, speaker_ips, port_num, http_ready, _, _, _ = common_setup_teardown
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


def bgp_speaker_announce_routes_common(common_setup_teardown, Asntype,
                                       tbinfo, duthost, ptfhost, ipv4, ipv6, mtu,
                                       family, prefix, nexthop_ips, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    ptfip, mg_facts, interface_facts, vlan_ips, _, vlan_if_name, speaker_ips, port_num, http_ready, bgp_dut_asn, neighbor_asn, neighbor_default_asn = common_setup_teardown
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

    bgp_facts = duthost.bgp_facts()['ansible_facts']
    logger.info(bgp_facts)
    cnt=0
    flag="false"
    for v in  bgp_facts["bgp_neighbors"].items():
        logger.info("bgp neighbor={}".format(v))
        if v[1]["state"] == "established":
            flag = "true"
            cnt+=1
        logger.info("flag=%s"%flag)
    logger.info(cnt)
    assert cnt>=3, "Not All BGP sessions eastablished."
    
    logger.info("Verify accepted prefixes of the dynamic neighbors are correct")
    bgp_facts = duthost.bgp_facts()['ansible_facts']


    if (Asntype=="2byte" or Asntype=="4byte"):
        assert bgp_facts['bgp_neighbors'][str(speaker_ips[2].ip)]['accepted prefixes'] == 1
    else:
        for ip in speaker_ips:
            assert bgp_facts['bgp_neighbors'][str(ip.ip)]['accepted prefixes'] == 1

    logger.info("Verify nexthops and nexthop interfaces for accepted prefixes of the dynamic neighbors")
    rtinfo = duthost.get_ip_route_info(ipaddress.ip_network(unicode(prefix)))
    nexthops_ip_set = { str(nexthop.ip) for nexthop in nexthop_ips }
    logger.info(rtinfo)
    assert len(rtinfo["nexthops"]) == 2

    if (Asntype=="2byte" or Asntype=="4byte"):
        assert str(rtinfo["nexthops"][0][0]) in nexthops_ip_set
        assert rtinfo["nexthops"][0][1] == unicode(vlan_if_name)
    else:
        for i in [0,1]:
            assert str(rtinfo["nexthops"][i][0]) in nexthops_ip_set
            assert rtinfo["nexthops"][i][1] == unicode(vlan_if_name)


    logger.info("Generate route-port map information")
    extra_vars = {'announce_prefix': prefix,
                  'is_backend': 'backend' in tbinfo['topo']['name'],
                  'minigraph_portchannels': mg_facts['minigraph_portchannels'],
                  'minigraph_vlans': mg_facts['minigraph_vlans'],
                  'minigraph_port_indices': mg_facts['minigraph_ptf_indices']}
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    logger.info("extra_vars: %s" % str(ptfhost.host.options['variable_manager'].extra_vars))

    if Asntype=="2byte" or Asntype=="4byte":
        ptfhost.template(src="bgp/templates/bgp_speaker_route_4bASN.j2", dest="/root/bgp_speaker_route_%s.txt" % family)
        logger.info("Copied route information for %s" % Asntype)
    else:
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

    #To verify that AS_PATH has valid ASN for prefix 
    if family == "v4":
        bgp_table_output = duthost.shell("vtysh -c \"show ip bgp {} longer-prefixes\" -c \"exit\"".format(prefix))
        assert len(bgp_table_output) >= 5
        for values in bgp_table_output["stdout_lines"]:
            if prefix in values:
                if nexthop_ips[1].ip and nexthop_ips[2].ip and neighbor_asn in values:
                    logger.info("Bgp AS Path for {} is {}".format(prefix,values))
                    assert "true"
            if peer_range in values:
                if nexthop_ips[0].ip and neighbor_asn in values:
                    logger.info("Bgp AS Path for {} is {}".format(peer_range,values))
                    assert "true"
    elif family == "v6":
        bgp_table_output = duthost.shell("vtysh -c \"show ip bgp ipv6\" -c \"exit\"")
        for values in bgp_table_output["stdout_lines"]:
            if prefix in values:
                if bgp_dut_asn and neighbor_asn in values:
                    logger.info("Bgp AS Path for {} is {}".format(prefix,values))
                    assert "true"

    logger.info("Withdraw routes")
    withdraw_route(ptfip, lo_addr, prefix, nexthop_ips[1].ip, port_num[0])
    withdraw_route(ptfip, lo_addr, prefix, nexthop_ips[2].ip, port_num[1])
    withdraw_route(ptfip, lo_addr, peer_range, vlan_ips[0].ip, port_num[2])

    logger.info("Nexthop ip%s tests are done for test %s" % (family, Asntype))

@pytest.mark.parametrize('common_setup_teardown', [
      ['']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(True, False, 1514, "")])
def test_bgp_speaker_announce_routes(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[3]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v4", "10.10.10.0/26", nexthops, vlan_mac)


@pytest.mark.parametrize('common_setup_teardown', [
      ['']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(False, True, 1514, "")])
def test_bgp_speaker_announce_routes_v6(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[4]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v6", "fc00:10::/64", nexthops, vlan_mac)

@pytest.mark.parametrize('common_setup_teardown', [
      ['2byte']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(True, False, 1514, "2byte")])
def test_bgp_speaker_2byteasn_announce_routes(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR with 2 byte bgp speaker and 4 byte T0 ASN

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[3]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v4", "10.10.10.0/26", nexthops, vlan_mac)

@pytest.mark.parametrize('common_setup_teardown', [
      ['4byte']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(True, False, 1514, "4byte")])
def test_bgp_speaker_4byteasn_announce_routes(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR with 4 byte ASN

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[3]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v4", "10.10.10.0/26", nexthops, vlan_mac)

@pytest.mark.parametrize('common_setup_teardown', [
      ['2byte']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(False, True, 1514, "2byte")])
def test_bgp_speaker_2byteasn_announce_routes_v6(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR with 2 byte bgp speaker and 4 byte T0 ASN

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[4]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v6", "fc00:10::/64", nexthops, vlan_mac)

@pytest.mark.parametrize('common_setup_teardown', [
      ['4byte']
   ], indirect = True)
@pytest.mark.parametrize("ipv4, ipv6, mtu, Asntype", [pytest.param(False, True, 1514, "4byte")])
def test_bgp_speaker_4byteasn_announce_routes_v6(common_setup_teardown, Asntype, tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ipv4, ipv6, mtu, vlan_mac):
    """Setup bgp speaker on T0 topology and verify routes advertised by bgp speaker is received by T0 TOR with 4 byte ASN

    """
    duthost = duthosts[rand_one_dut_hostname]
    nexthops = common_setup_teardown[4]
    bgp_speaker_announce_routes_common(common_setup_teardown, Asntype, tbinfo, duthost, ptfhost, ipv4, ipv6, mtu, "v6", "fc00:10::/64", nexthops, vlan_mac)

