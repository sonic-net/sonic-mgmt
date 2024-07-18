import re
import json
import time
import yaml
import pytest
import logging
import requests
import ipaddress
from jinja2 import Template
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, wait_tcp_connection
from bgp_helpers import CONSTANTS_FILE, BGPSENTINEL_CONFIG_FILE
from bgp_helpers import BGP_SENTINEL_PORT_V4, BGP_SENTINEL_NAME_V4
from bgp_helpers import BGP_SENTINEL_PORT_V6, BGP_SENTINEL_NAME_V6
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME


pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs'),
]

BGP_SENTINEL_TMPL = '''\
{
    "BGP_SENTINELS": {
        "BGPSentinel": {
            "ip_range": {{ v4_listen_range }},
            "name": "BGPSentinel",
            "src_address": "{{ v4_src_address }}"
        },
        "BGPSentinelV6": {
            "ip_range": {{ v6_listen_range }},
            "name": "BGPSentinelV6",
            "src_address": "{{ v6_src_address }}"
        }
    }
}'''


logger = logging.getLogger(__name__)


def is_bgp_sentinel_supported(duthost):
    """ Get bgp sentinel config that contains src_address and ip_range

    Sample output in t1:
    ['\n neighbor BGPSentinel peer-group,
     '\n neighbor BGPSentinel remote-as 65100,
     '\n neighbor BGPSentinel update-source 10.1.0.32,
     '\n neighbor BGPSentinelV6 peer-group,
     '\n neighbor BGPSentinelV6 remote-as 65100,
     '\n neighbor BGPSentinelV6 update-source fc00:1::32,
     '\n bgp listen range 100.1.0.0/24 peer-group BGPSentinel,
     '\n bgp listen range 2064:100::/59 peer-group BGPSentinelV6']
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # As long as BGPSentinel exist in the output, it means bgp sentinel is supported
    bgp_sentinel_pattern = r"\s+neighbor BGPSentinel\s+"
    return False if re.search(bgp_sentinel_pattern, output['stdout']) is None else True


def is_bgp_monv6_supported(duthost):
    """ Get bgp monv6 config that contains src_address and ip_range

    Sample output in t1:
    ['\n neighbor BGPMON_V6 peer-group,
     '\n neighbor BGPMON_V6 passive,
     '\n neighbor fc00:1::32 peer-group BGPMON_V6,
     '\n neighbor BGPMON_V6 activate,
     '\n neighbor BGPMON_V6 addpath-tx-all-paths,
     '\n neighbor BGPMON_V6 soft-reconfiguration inbound,
     '\n neighbor BGPMON_V6 route-map FROM_BGPMON_V6 in,
     '\n neighbor BGPMON_V6 route-map TO_BGPMON_V6 out,]
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # As long as BGPMON_V6 exist in the output, it means BGPMON_V6 is supported
    bgp_sentinel_pattern = r"\s+neighbor BGPMON_V6\s+"
    return False if re.search(bgp_sentinel_pattern, output['stdout']) is None else True


def get_dut_listen_range(tbinfo):
    # Find spine route and get the bp_interface's network
    ipv4_subnet, ipv6_subnet, = None, None
    spine_bp_addr = {}
    for k, v in tbinfo['topo']['properties']['configuration'].items():
        if 'spine' in v['properties']:
            ipv4_addr = ipaddress.ip_interface(v['bp_interface']['ipv4'].encode().decode())
            ipv6_addr = ipaddress.ip_interface(v['bp_interface']['ipv6'].encode().decode())
            ipv4_subnet = str(ipv4_addr.network)
            ipv6_subnet = str(ipv6_addr.network)
            spine_bp_addr[k] = {'ipv4': str(ipv4_addr.ip), 'ipv6': str(ipv6_addr.ip)}
    return ipv4_subnet, ipv6_subnet, spine_bp_addr


def is_bgp_sentinel_session_established(duthost, ibgp_sessions):
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    if set(ibgp_sessions) <= set(bgp_facts['bgp_neighbors'].keys()):
        for nbr in ibgp_sessions:
            if bgp_facts['bgp_neighbors'][nbr]['state'] != 'established':
                return False
        return True
    return False


def is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions):
    """ Check if the route is advertised to peers
    """
    ip_family = None
    network = ipaddress.ip_network(route.encode().decode())
    if network.version == 4:
        ip_family = 'ipv4'
    elif network.version == 6:
        ip_family = 'ipv6'
    else:
        pytest.fail("Invalid route {}".format(route))

    cmd = "vtysh -c \'show bgp {} {} json\'".format(ip_family, route)
    output = json.loads(duthost.shell(cmd)['stdout'])
    if 'paths' in output.keys():
        for path in output['paths']:
            if 'advertisedTo' in path:
                peer_info = list(path['advertisedTo'].keys())
                for item in ibgp_sessions:
                    peer_info.remove(item) if item in peer_info else None
                if len(peer_info) > 0:
                    return True
    return False


def add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr):
    ipv4_nh, ipv6_nh = None, None
    for _, v in spine_bp_addr.items():
        # Add ptf route to dut lo address
        if ipv4_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            time.sleep(5)
            ipv4_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv4_addr), module_ignore_errors=True)
            if ipv4_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            else:
                ipv4_nh = v['ipv4']

        if ipv6_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            time.sleep(5)
            ipv6_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv6_addr), module_ignore_errors=True)
            if ipv6_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            else:
                ipv6_nh = v['ipv6']

    return ipv4_nh, ipv6_nh


@pytest.fixture(scope="module")
def dut_lo_addr(rand_selected_dut):
    duthost = rand_selected_dut
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr, lo_ipv6_addr = lo_facts['ipv4']['address'], None
    for item in lo_facts['ipv6']:
        if item['address'].startswith('fe80'):
            continue
        lo_ipv6_addr = item['address']
        break
    return lo_ipv4_addr, lo_ipv6_addr


@pytest.fixture(scope="module", params=['BGPSentinel', 'BGPMonV6'])
def dut_setup_teardown(rand_selected_dut, tbinfo, dut_lo_addr, request):
    duthost = rand_selected_dut
    lo_ipv4_addr, lo_ipv6_addr = dut_lo_addr
    ipv4_subnet, ipv6_subnet, spine_bp_addr = get_dut_listen_range(tbinfo)
    ptf_bp_v4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    ptf_bp_v6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6'].lower()
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    if request.param == 'BGPSentinel':
        # render template and write to DB, check running configuration for BGP_sentinel
        bgp_sentinelv4_tmpl = Template(BGP_SENTINEL_TMPL)
        duthost.copy(content=bgp_sentinelv4_tmpl.render(v4_listen_range=json.dumps([ipv4_subnet, ptf_bp_v4 + '/32']),
                                                        v4_src_address=lo_ipv4_addr,
                                                        v6_listen_range=json.dumps([ipv6_subnet, ptf_bp_v6 + '/128']),
                                                        v6_src_address=lo_ipv6_addr),
                     dest=BGPSENTINEL_CONFIG_FILE)
        duthost.shell("sonic-cfggen -j {} -w".format(BGPSENTINEL_CONFIG_FILE))

    elif request.param == 'BGPMonV6':
        # render template and write to DB, check running configuration for BGPMonV6
        bgpmon_args = {
            'db_table_name': 'BGP_MONITORS',
            'peer_addr': ptf_bp_v6,
            'asn': dut_asn,
            'local_addr': "fc00:1::32",
            'peer_name': BGP_MONITOR_NAME
        }
        bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
        duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                     dest=BGPMON_CONFIG_FILE)
        duthost.shell("sonic-cfggen -j {} -w".format(BGPMON_CONFIG_FILE))

    duthost.shell("vtysh -c \"configure terminal\" -c \"ipv6 nht resolve-via-default\"")

    yield lo_ipv4_addr, lo_ipv6_addr, spine_bp_addr, ptf_bp_v4, ptf_bp_v6, request.param

    if request.param == 'BGPSentinel':
        # Cleanup bgp sentinel configuration
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')
        duthost.file(path=BGPSENTINEL_CONFIG_FILE, state='absent')
    elif request.param == 'BGPMonV6':
        # Cleanup bgp monitorV6 configuration
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(ptf_bp_v6), asic_index='all')
        duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


@pytest.fixture(scope="module")
def ptf_setup_teardown(dut_setup_teardown, rand_selected_dut, ptfhost, tbinfo):
    duthost = rand_selected_dut
    lo_ipv4_addr, lo_ipv6_addr, spine_bp_addr, ptf_bp_v4, ptf_bp_v6, case_type = dut_setup_teardown

    if case_type == 'BGPSentinel':
        if not is_bgp_sentinel_supported(duthost):
            pytest.skip("BGP sentinel is not supported on this image")
    elif case_type == 'BGPMonV6':
        if not is_bgp_monv6_supported(duthost):
            pytest.skip("BGPMonV6 is not supported on this image")

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    # Start exabgp process to simulate bgp sentinel
    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V4,
                   state="started",
                   local_ip=ptf_bp_v4,
                   router_id=ptf_bp_v4,
                   peer_ip=lo_ipv4_addr,
                   local_asn=dut_asn,
                   peer_asn=dut_asn,
                   port=BGP_SENTINEL_PORT_V4)

    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V6,
                   state="started",
                   local_ip=ptf_bp_v6,
                   router_id=ptf_bp_v4,
                   peer_ip=lo_ipv6_addr,
                   local_asn=dut_asn,
                   peer_asn=dut_asn,
                   port=BGP_SENTINEL_PORT_V6)

    if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V4, timeout_s=60):
        raise RuntimeError("Failed to start BGPSentinel neighbor %s" % lo_ipv4_addr)

    if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V6, timeout_s=60):
        raise RuntimeError("Failed to start BGPSentinelV6 neighbor %s" % lo_ipv6_addr)

    ipv4_nh, ipv6_nh = add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr)
    if case_type == 'BGPMonV6':
        ipv4_nh = None

    yield lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ptf_bp_v4, ptf_bp_v6

    # Remove ptf route to dut lo address
    if ipv4_nh is not None:
        ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, ipv4_nh), module_ignore_errors=True)
    if ipv6_nh is not None:
        ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, ipv6_nh), module_ignore_errors=True)

    # Stop exabgp process
    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V4, state="absent")
    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V6, state="absent")


@pytest.fixture(scope="module")
def common_setup_teardown(rand_selected_dut, ptf_setup_teardown, ptfhost):
    ptfip = ptfhost.mgmt_ip
    duthost = rand_selected_dut
    logger.info("ptfip=%s" % ptfip)

    lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ptf_bp_v4, ptf_bp_v6 = ptf_setup_teardown

    if ipv4_nh is None and ipv6_nh is None:
        pytest.skip("Failed to add route to dut lo address")

    ibgp_sessions = []
    if ipv4_nh is not None:
        ibgp_sessions.append(ptf_bp_v4)
    if ipv6_nh is not None:
        ibgp_sessions.append(ptf_bp_v6)

    # wait for bgp sentinel and dut to establish ibgp session
    pytest_assert(wait_until(30, 5, 5, is_bgp_sentinel_session_established, duthost, ibgp_sessions),
                  "BGP Sentinel session has not setup successfully")

    yield ptfip, lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ibgp_sessions, ptf_bp_v4, ptf_bp_v6


@pytest.fixture(scope="module")
def sentinel_community(duthost):
    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No file {} on DUT, BGP Sentinel is not supported' % CONSTANTS_FILE)

    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
    return constants['constants']['bgp']['sentinel_community']


def announce_route(ptfip, neighbor, route, nexthop, port, community):
    change_route("announce", ptfip, neighbor, route, nexthop, port, community)


def withdraw_route(ptfip, neighbor, route, nexthop, port, community):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port, community)


def change_route(operation, ptfip, neighbor, route, nexthop, port, community):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s local-preference 10000 community [%s]"
            % (neighbor, operation, route, nexthop, community)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def get_target_routes(duthost):
    v4_peer, v6_peer = None, None
    bgp_summary = json.loads(duthost.shell("vtysh -c \"show bgp summary json\"")['stdout'])
    for k, v in bgp_summary['ipv4Unicast']['peers'].items():
        if 'desc' in v and 'T0' in v['desc'] and v['pfxRcd'] != 0:
            v4_peer = k
            break

    for k, v in bgp_summary['ipv6Unicast']['peers'].items():
        if 'desc' in v and 'T0' in v['desc'] and v['pfxRcd'] != 0:
            v6_peer = k
            break

    if v4_peer is None or v6_peer is None:
        pytest.skip("No bgp session to T0")

    bgp_v4_routes = json.loads(duthost.shell(
        "vtysh -c \'show bgp ipv4 neighbors {} received-routes json\'".format(v4_peer))['stdout'])
    bgp_v6_routes = json.loads(duthost.shell(
        "vtysh -c \'show bgp ipv6 neighbors {} received-routes json\'".format(v6_peer))['stdout'])

    target_v6_routes = [route for route in bgp_v6_routes['receivedRoutes'].keys() if '/128' not in route]
    return list(bgp_v4_routes['receivedRoutes'].keys()), target_v6_routes


@pytest.fixture(scope="module", params=['no-export', None])
def bgp_community(sentinel_community, request):
    if request.param is None:
        community = sentinel_community
    else:
        community = "{} {}".format(sentinel_community, request.param)
    yield community


@pytest.fixture(scope="module", params=['IPv4', 'IPv6'])
def prepare_bgp_sentinel_routes(rand_selected_dut, common_setup_teardown, bgp_community, request):
    duthost = rand_selected_dut
    ptfip, lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ibgp_sessions, ptf_bp_v4, ptf_bp_v6 = common_setup_teardown

    if ipv4_nh is None and request.param == "IPv4":
        pytest.skip("IPv4 IBGP session is not established")

    if ipv6_nh is None and request.param == "IPv6":
        pytest.skip("IPv6 IBGP session is not established")

    ipv4_routes, ipv6_routes = get_target_routes(duthost)

    # Check if the routes are announced to peers
    for route in ipv4_routes + ipv6_routes:
        pytest_assert(is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                      "Route {} is not advertised to bgp peers".format(route))

    community = bgp_community

    # Announce routes from bgp sentinel
    if request.param == "IPv4":
        for route in ipv4_routes:
            announce_route(ptfip, lo_ipv4_addr, route, ptf_bp_v4, BGP_SENTINEL_PORT_V4, community)

        for route in ipv6_routes:
            announce_route(ptfip, lo_ipv4_addr, route, ptf_bp_v6, BGP_SENTINEL_PORT_V4, community)
    else:
        for route in ipv4_routes:
            announce_route(ptfip, lo_ipv6_addr, route, ptf_bp_v4, BGP_SENTINEL_PORT_V6, community)

        for route in ipv6_routes:
            announce_route(ptfip, lo_ipv6_addr, route, ptf_bp_v6, BGP_SENTINEL_PORT_V6, community)

    time.sleep(10)
    # Check if the routes are not announced to ebgp peers with no-export community
    # or w/o no-export, routes announced to ebgp peers
    for route in ipv4_routes + ipv6_routes:
        if 'no-export' in community:
            pytest_assert(not is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                          "Route {} should not be advertised to bgp peers".format(route))
        else:
            pytest_assert(is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                          "Route {} is not advertised to bgp peers".format(route))

    if request.param == "IPv4":
        yield ptf_bp_v4, ipv4_routes + ipv6_routes, ibgp_sessions, community
    else:
        yield ptf_bp_v6, ipv4_routes + ipv6_routes, ibgp_sessions, community

    # Withdraw routes from bgp sentinel
    if request.param == "IPv4":
        for route in ipv4_routes:
            withdraw_route(ptfip, lo_ipv4_addr, route, ptf_bp_v4, BGP_SENTINEL_PORT_V4, community)

        for route in ipv6_routes:
            withdraw_route(ptfip, lo_ipv4_addr, route, ptf_bp_v6, BGP_SENTINEL_PORT_V4, community)
    else:
        for route in ipv4_routes:
            withdraw_route(ptfip, lo_ipv6_addr, route, ptf_bp_v4, BGP_SENTINEL_PORT_V6, community)

        for route in ipv6_routes:
            withdraw_route(ptfip, lo_ipv6_addr, route, ptf_bp_v6, BGP_SENTINEL_PORT_V6, community)

    time.sleep(10)
    # Check if the routes are announced to ebgp peers
    for route in ipv4_routes + ipv6_routes:
        pytest_assert(is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                      "Route {} is not advertised to bgp peers".format(route))


@pytest.mark.parametrize("reset_type", ["none", "soft", "hard"])
def test_bgp_sentinel(rand_selected_dut, prepare_bgp_sentinel_routes, reset_type):
    duthost = rand_selected_dut
    ibgp_nbr, target_routes, ibgp_sessions, community = prepare_bgp_sentinel_routes

    if reset_type == "none":
        return
    elif reset_type == "soft":
        cmd = "vtysh -c \'clear bgp {} soft \'".format(ibgp_nbr)
    elif reset_type == "hard":
        cmd = "vtysh -c \'clear bgp {} \'".format(ibgp_nbr)
    duthost.shell(cmd)

    # wait for bgp sentinel and dut to establish ibgp session
    pytest_assert(wait_until(30, 5, 5, is_bgp_sentinel_session_established, duthost, [ibgp_nbr]),
                  "BGP Sentinel session has not setup successfully")

    # Check if the routes are not announced to ebgp peers
    for route in target_routes:
        if 'no-export' in community:
            pytest_assert(not is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                          "Route {} should not be advertised to bgp peers".format(route))
        else:
            pytest_assert(is_route_advertised_to_ebgp_peers(duthost, route, ibgp_sessions),
                          "Route {} is not advertised to bgp peers".format(route))
    return
