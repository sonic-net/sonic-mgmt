'''This script is to test the BGP Bounce Back Routing (BBR) feature of SONiC.
'''
import json
import logging
import time

from collections import namedtuple

import pytest
import requests
import ipaddr as ipaddress

from jinja2 import Template
from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.parallel import parallel_run

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000


BBR_PREFIX = '172.16.10.0/24'
BBR_PREFIX_V6 = '2000:0:172:16:10::/96'

DUMMY_ASN1 = 64101
DUMMY_ASN2 = 64102


@pytest.fixture
def disable_enable_bbr(duthost):
    bgp_bbr_config = Template(open("./bgp/templates/bgp_bbr_config.json.j2").read())

    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='disabled'), dest='/tmp/disable_bbr.json')
    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='enabled'), dest='/tmp/enable_bbr.json')

    logger.info('Disable BGP_BBR')
    duthost.shell('sonic-cfggen -j /tmp/disable_bbr.json -w ')
    time.sleep(3)
    yield

    logger.info('Enable BGP_BBR')
    duthost.shell('sonic-cfggen -j /tmp/enable_bbr.json -w')


@pytest.fixture(scope='module')
def setup(duthost, tbinfo, nbrhosts):
    if tbinfo['topo']['type'] != 't1':
        pytest.skip('Unsupported topology type: {}, supported: {}'.format(tbinfo['topo']['type'], 't1'))

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    setup_info = {}

    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    t2_neighbors = [neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T2')]
    tor1 = tor_neighbors[0]
    other_vms = tor_neighbors[1:] + t2_neighbors

    neigh_peer_map = {}
    for bgp_neigh in mg_facts['minigraph_bgp']:
        name = bgp_neigh['name']
        peer_addr = bgp_neigh['peer_addr']
        if name not in neigh_peer_map:
            neigh_peer_map[name] = {}
        if ipaddress.IPAddress(peer_addr).version == 4:
            neigh_peer_map[name].update({'peer_addr': peer_addr})
        else:
            neigh_peer_map[name].update({'peer_addr_v6': peer_addr})

    # Announce route to one of the T0 VM
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    tor1_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + tor1_offset

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    tor1_asn = nbrhosts[tor1]['conf']['bgp']['asn']
    aspath = '{} {}'.format(dut_asn, DUMMY_ASN1)
    aspath_dual_dut_asn = '{} {} {} {}'.format(dut_asn, DUMMY_ASN1, dut_asn, DUMMY_ASN2)

    Route = namedtuple('Route', ['prefix', 'nexthop', 'aspath'])

    bbr_route = Route(BBR_PREFIX, neigh_peer_map[tor1]['peer_addr'], aspath)
    bbr_route_v6 = Route(BBR_PREFIX_V6, neigh_peer_map[tor1]['peer_addr_v6'], aspath)

    bbr_route_dual_dut_asn = Route(BBR_PREFIX, neigh_peer_map[tor1]['peer_addr'], aspath_dual_dut_asn)
    bbr_route_v6_dual_dut_asn = Route(BBR_PREFIX_V6, neigh_peer_map[tor1]['peer_addr_v6'], aspath_dual_dut_asn)

    setup_info = {
        'tor1': tor1,
        'other_vms': other_vms,
        'tor1_offset': tor1_offset,
        'tor1_exabgp_port': tor1_exabgp_port,
        'tor1_exabgp_port_v6': tor1_exabgp_port_v6,
        'dut_asn': dut_asn,
        'tor1_asn': tor1_asn,
        'bbr_route': bbr_route,
        'bbr_route_v6': bbr_route_v6,
        'bbr_route_dual_dut_asn': bbr_route_dual_dut_asn,
        'bbr_route_v6_dual_dut_asn': bbr_route_v6_dual_dut_asn
    }

    logger.info('setup_info: {}'.format(json.dumps(setup_info, indent=2)))

    return setup_info


def update_routes(action, ptfip, port, route):
    if action == 'announce':
        msg = '{} route {} next-hop {} as-path [ {} ]'.format(action, route.prefix, route.nexthop, route.aspath)
    elif action == 'withdraw':
        msg = '{} route {} next-hop {}'.format(action, route.prefix, route.nexthop)
    else:
        logger.error('Unsupported route update operation.')
        return
    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg }
    r = requests.post(url, data=data)
    assert r.status_code == 200


@pytest.fixture
def announce_withdraw_route(setup, ptfhost):
    tor1_exabgp_port = setup['tor1_exabgp_port']
    tor1_exabgp_port_v6 = setup['tor1_exabgp_port_v6']
    bbr_route = setup['bbr_route']
    bbr_route_v6 = setup['bbr_route_v6']

    logger.info('Announce route {} and {} to the first T0'.format(str(bbr_route), str(bbr_route_v6)))
    update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, bbr_route)
    update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, bbr_route_v6)
    time.sleep(3)

    yield bbr_route, bbr_route_v6

    logger.info('Withdraw route {} and {} from the first T0'.format(str(bbr_route), str(bbr_route_v6)))
    update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port, bbr_route)
    update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port_v6, bbr_route_v6)


@pytest.fixture
def announce_withdraw_dual_dut_asn_route(setup, ptfhost):
    tor1_exabgp_port = setup['tor1_exabgp_port']
    tor1_exabgp_port_v6 = setup['tor1_exabgp_port_v6']
    bbr_route_dual_dut_asn = setup['bbr_route_dual_dut_asn']
    bbr_route_v6_dual_dut_asn = setup['bbr_route_v6_dual_dut_asn']

    logger.info('Announce route {} and {} to the first T0'\
        .format(str(bbr_route_dual_dut_asn), str(bbr_route_v6_dual_dut_asn)))
    update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, bbr_route_dual_dut_asn)
    update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, bbr_route_v6_dual_dut_asn)

    yield bbr_route_dual_dut_asn, bbr_route_v6_dual_dut_asn

    logger.info('Withdraw route {} and {} from the first T0'\
        .format(str(bbr_route_dual_dut_asn), str(bbr_route_v6_dual_dut_asn)))
    update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port, bbr_route_dual_dut_asn)
    update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port_v6, bbr_route_v6_dual_dut_asn)


def eos_get_route(eoshost, prefix):
    cmd = 'show ip bgp' if ipaddress.IPNetwork(prefix).version == 4 else 'show ipv6 bgp'
    return eoshost.eos_command(commands=[{
        'command': '{} {}'.format(cmd, prefix),
        'output': 'json'
    }])['stdout'][0]


def dut_get_route(duthost, prefix):
    cmd = 'show bgp ipv4' if ipaddress.IPNetwork(prefix).version == 4 else 'show bgp ipv6'
    return json.loads(duthost.shell('vtysh -c "{} {} json"'.format(cmd, prefix))['stdout'])


def check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=True):

    tor1 = setup['tor1']
    tor1_asn = setup['tor1_asn']
    other_vms = setup['other_vms']

    # Check route on tor1
    logger.info('Check route for prefix {} on {}'.format(route.prefix, tor1))
    tor1_route = eos_get_route(nbrhosts[tor1]['host'], route.prefix)
    pytest_assert(route.prefix in tor1_route['vrfs']['default']['bgpRouteEntries'].keys(),
        'No route for {} found on {}'.format(route.prefix, tor1))
    tor1_route_aspath = tor1_route['vrfs']['default']['bgpRouteEntries'][route.prefix]['bgpRoutePaths'][0]\
        ['asPathEntry']['asPath']
    pytest_assert(tor1_route_aspath==route.aspath,
        'On {} expected aspath: {}, actual aspath: {}'.format(tor1, route.aspath, tor1_route_aspath))

    # Check route on DUT
    logger.info('Check route on DUT')
    dut_route = dut_get_route(duthost, route.prefix)
    if accepted:
        pytest_assert(dut_route, 'No route for {} found on DUT'.format(route.prefix))
        dut_route_aspath = dut_route['paths'][0]['aspath']['string']
        # Route path from DUT: -> TOR1 -> aspath(other T1 -> DUMMY_ASN1)
        dut_route_aspath_expected = '{} {}'.format(tor1_asn, route.aspath)
        pytest_assert(dut_route_aspath==dut_route_aspath_expected,
            'On DUT expected aspath: {}, actual aspath: {}'.format(dut_route_aspath_expected, dut_route_aspath))
    else:
        pytest_assert(not dut_route, 'Prefix {} should not be accepted by DUT'.format(route.prefix))

    # Check route on other VMs
    @reset_ansible_local_tmp
    def check_other_vms(nbrhosts, setup, route, accepted=True, node=None, results=None):
        logger.info('Check route {} on {}'.format(str(route), node))

        dut_asn = setup['dut_asn']
        tor1_asn = setup['tor1_asn']

        vm_route = eos_get_route(nbrhosts[node]['host'], route.prefix)
        vm_route = {'failed': False}
        vm_route['tor_route'] = vm_route
        if accepted:
            if route.prefix not in vm_route['vrfs']['default']['bgpRouteEntries'].keys():
                vm_route['failed'] = True
                vm_route['message'] = 'No route for {} found on {}'.format(route.prefix, node)
            else:
                tor_route_aspath = vm_route['vrfs']['default']['bgpRouteEntries'][route.prefix]['bgpRoutePaths'][0]\
                    ['asPathEntry']['asPath']
                # Route path from other VMs: -> DUT(T1) -> TOR1 -> aspath(other T1 -> DUMMY_ASN1)
                tor_route_aspath_expected = '{} {} {}'.format(dut_asn, tor1_asn, route.aspath)
                if tor_route_aspath != tor_route_aspath_expected:
                    vm_route['failed'] = True
                    vm_route['message'] = 'On {} expected aspath: {}, actual aspath: {}'\
                        .format(node, tor_route_aspath_expected, tor_route_aspath)
        else:
            if route.prefix in vm_route['vrfs']['default']['bgpRouteEntries'].keys():
                vm_route['failed'] = True
                vm_route['message'] = 'No route {} expected on {}'.format(route.prefix, node)
        vm_route['message'] = 'Checking route {} on {} passed'.format(str(route), node)
        results[node] = vm_route

    results = parallel_run(check_other_vms, (nbrhosts, setup, route), {'accepted': accepted}, other_vms, timeout=120)

    failed_results = {}
    for node, result in results.items():
        if result['failed']:
            failed_results[node] = result

    pytest_assert(not failed_results, 'Checking route {} failed, failed_results: {}'\
        .format(str(route), json.dumps(failed_results, indent=2)))


def test_bbr_enabled_dut_asn_in_aspath(duthost, nbrhosts, setup, announce_withdraw_route):
    bbr_route, bbr_route_v6 = announce_withdraw_route
    for route in (bbr_route, bbr_route_v6):
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=True)


def test_bbr_enabled_dual_dut_asn_in_aspath(duthost, nbrhosts, setup, announce_withdraw_dual_dut_asn_route):
    bbr_route_dual_dut_asn, bbr_route_v6_dual_dut_asn = announce_withdraw_dual_dut_asn_route
    for route in (bbr_route_dual_dut_asn, bbr_route_v6_dual_dut_asn):
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=False)


def test_bbr_disabled_dut_asn_in_aspath(duthost, nbrhosts, disable_enable_bbr, setup, announce_withdraw_route):
    bbr_route, bbr_route_v6 = announce_withdraw_route
    for route in (bbr_route, bbr_route_v6):
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=False)
