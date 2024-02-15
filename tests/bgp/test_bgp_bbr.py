'''This script is to test the BGP Bounce Back Routing (BBR) feature of SONiC.
'''
import json
import logging
import time

from collections import defaultdict
from collections import namedtuple

import pytest
import requests
import yaml
import ipaddr as ipaddress

from jinja2 import Template
from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until, delete_running_config
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile


pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

CONSTANTS_FILE = '/etc/sonic/constants.yml'

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

BBR_PREFIX = '172.16.10.0/24'
BBR_PREFIX_V6 = '2000:172:16:10::/64'

DUMMY_ASN1 = 64101
DUMMY_ASN2 = 64102


@pytest.fixture(scope='module', autouse=True)
def prepare_bbr_config_files(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    bgp_bbr_config = Template(open("./bgp/templates/bgp_bbr_config.json.j2").read())

    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='disabled'), dest='/tmp/disable_bbr.json')
    duthost.copy(content=bgp_bbr_config.render(BGP_BBR_STATUS='enabled'), dest='/tmp/enable_bbr.json')

    yield

    del_bbr_json = [{"BGP_BBR": {}}]
    delete_running_config(del_bbr_json, duthost)


@pytest.fixture(scope='module')
def bbr_default_state(setup):
    return setup['bbr_default_state']


def add_bbr_config_to_running_config(duthost, status):
    logger.info('Add BGP_BBR config to running config')
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_BBR",
            "value": {
                "all": {
                    "status": "{}".format(status)
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    time.sleep(3)


def config_bbr_by_gcu(duthost, status):
    logger.info('Config BGP_BBR by GCU cmd')
    json_patch = [
        {
            "op": "replace",
            "path": "/BGP_BBR/all/status",
            "value": "{}".format(status)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    time.sleep(3)


def enable_bbr(duthost, namespace):
    logger.info('Enable BGP_BBR')
    # gcu doesn't support multi-asic for now, use sonic-cfggen instead
    if namespace:
        logger.info('Enable BGP_BBR in namespace {}'.format(namespace))
        duthost.shell('sonic-cfggen {} -j /tmp/enable_bbr.json -w '.format('-n ' + namespace))
        time.sleep(3)
    else:
        config_bbr_by_gcu(duthost, "enabled")


def disable_bbr(duthost, namespace):
    logger.info('Disable BGP_BBR')
    # gcu doesn't support multi-asic for now, use sonic-cfggen instead
    if namespace:
        logger.info('Disable BGP_BBR in namespace {}'.format(namespace))
        duthost.shell('sonic-cfggen {} -j /tmp/disable_bbr.json -w '.format('-n ' + namespace))
        time.sleep(3)
    else:
        config_bbr_by_gcu(duthost, "disabled")


@pytest.fixture
def restore_bbr_default_state(duthosts, setup, rand_one_dut_hostname, bbr_default_state):
    yield
    duthost = duthosts[rand_one_dut_hostname]
    if bbr_default_state == 'enabled':
        enable_bbr(duthost, setup['tor1_namespace'])
    else:
        disable_bbr(duthost, setup['tor1_namespace'])


@pytest.fixture
def config_bbr_disabled(duthosts, setup, rand_one_dut_hostname, restore_bbr_default_state):
    duthost = duthosts[rand_one_dut_hostname]
    disable_bbr(duthost, setup['tor1_namespace'])


@pytest.fixture
def config_bbr_enabled(duthosts, setup, rand_one_dut_hostname, restore_bbr_default_state):
    duthost = duthosts[rand_one_dut_hostname]
    enable_bbr(duthost, setup['tor1_namespace'])


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, tbinfo, nbrhosts):
    duthost = duthosts[rand_one_dut_hostname]

    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No file {} on DUT, BBR is not supported')

    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
    bbr_default_state = 'disabled'
    try:
        bbr_enabled = constants['constants']['bgp']['bbr']['enabled']
        if not bbr_enabled:
            pytest.skip('BGP BBR is not enabled')
        bbr_default_state = constants['constants']['bgp']['bbr']['default_state']
    except KeyError:
        pytest.skip('No BBR configuration in {}, BBR is not supported.'.format(CONSTANTS_FILE))

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    tor_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]

    neigh_peer_map = defaultdict(dict)
    for bgp_neigh in mg_facts['minigraph_bgp']:
        name = bgp_neigh['name']
        peer_addr = bgp_neigh['peer_addr']
        if ipaddress.IPAddress(peer_addr).version == 4:
            neigh_peer_map[name].update({'peer_addr': peer_addr})
        else:
            neigh_peer_map[name].update({'peer_addr_v6': peer_addr})

    tor1_namespace = DEFAULT_NAMESPACE
    for dut_port, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if tor1 == neigh['name']:
            tor1_namespace = neigh['namespace']
            break

    # Modifying other_vms for multi-asic, check bgps on asic of tor1_namespace
    other_vms = []
    for dut_port, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if neigh['name'] == tor1:
            continue
        if neigh['namespace'] == tor1_namespace:
            other_vms.append(neigh['name'])

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
        'bbr_default_state': bbr_default_state,
        'tor1': tor1,
        'other_vms': other_vms,
        'tor1_offset': tor1_offset,
        'tor1_namespace': tor1_namespace,
        'tor1_exabgp_port': tor1_exabgp_port,
        'tor1_exabgp_port_v6': tor1_exabgp_port_v6,
        'dut_asn': dut_asn,
        'tor1_asn': tor1_asn,
        'bbr_route': bbr_route,
        'bbr_route_v6': bbr_route_v6,
        'bbr_route_dual_dut_asn': bbr_route_dual_dut_asn,
        'bbr_route_v6_dual_dut_asn': bbr_route_v6_dual_dut_asn
    }

    if not setup_info['tor1_namespace']:
        logger.info('non multi-asic environment, add bbr config to running config using gcu cmd')
        add_bbr_config_to_running_config(duthost, bbr_default_state)

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
    data = {'commands': msg}
    r = requests.post(url, data=data)
    assert r.status_code == 200


@pytest.fixture
def prepare_routes(setup, ptfhost):
    tor1_exabgp_port = setup['tor1_exabgp_port']
    tor1_exabgp_port_v6 = setup['tor1_exabgp_port_v6']

    bbr_routes = []

    def announce_routes(routes):
        logger.info('Announce routes {} to the first T0'.format(str(routes)))
        for route in routes:
            bbr_routes.append(route)
            if ipaddress.IPNetwork(route.prefix).version == 4:
                update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, route)
            else:
                update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)
        time.sleep(3)

    yield announce_routes

    logger.info('Withdraw routes {} from the first T0'.format(str(bbr_routes)))
    for route in bbr_routes:
        if ipaddress.IPNetwork(route.prefix).version == 4:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port, route)
        else:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)


def check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=True):

    def check_tor1(nbrhosts, setup, route):
        tor1 = setup['tor1']
        # Check route on tor1
        logger.info('Check route for prefix {} on {}'.format(route.prefix, tor1))
        tor1_route = nbrhosts[tor1]['host'].get_route(route.prefix)
        if route.prefix not in list(tor1_route['vrfs']['default']['bgpRouteEntries'].keys()):
            logging.warn('No route for {} found on {}'.format(route.prefix, tor1))
            return False
        tor1_route_aspath = tor1_route['vrfs']['default']['bgpRouteEntries'][route.prefix]['bgpRoutePaths'][0]\
            ['asPathEntry']['asPath']   # noqa E211
        if not tor1_route_aspath == route.aspath:
            logging.warn('On {} expected aspath: {}, actual aspath: {}'.format(tor1, route.aspath, tor1_route_aspath))
            return False
        return True

    def check_dut(duthost, other_vms, bgp_neighbors, setup, route, accepted=True):
        tor1_asn = setup['tor1_asn']
        # Check route on DUT
        logger.info('Check route on DUT')
        dut_route = duthost.get_route(route.prefix, setup['tor1_namespace'])

        if accepted:
            if not dut_route:
                logging.warn('No route for {} found on DUT'.format(route.prefix))
                return False
            dut_route_aspath = dut_route['paths'][0]['aspath']['string']
            # Route path from DUT: -> TOR1 -> aspath(other T1 -> DUMMY_ASN1)
            dut_route_aspath_expected = '{} {}'.format(tor1_asn, route.aspath)
            if not dut_route_aspath == dut_route_aspath_expected:
                logging.warn('On DUT expected aspath: {}, actual aspath: {}'
                             .format(dut_route_aspath_expected, dut_route_aspath))
                return False
            if 'advertisedTo' not in dut_route:
                logging.warn("DUT didn't advertise the route")
                return False
            advertised_to = set()
            for _ in dut_route['advertisedTo']:
                # For multi-asic dut, dut_route included duthost which is not a BGP neighbor
                if _ in list(bgp_neighbors.keys()):
                    advertised_to.add(bgp_neighbors[_]['name'])
            for vm in other_vms:
                if vm not in advertised_to:
                    logging.warn("DUT didn't advertise route to neighbor %s" % vm)
                    return False
        else:
            if dut_route:
                logging.warn('Prefix {} should not be accepted by DUT'.format(route.prefix))
        return True

    # Check route on other VMs
    @reset_ansible_local_tmp
    def check_other_vms(nbrhosts, setup, route, accepted=True, node=None, results=None):
        logger.info('Check route {} on {}'.format(str(route), node))

        dut_asn = setup['dut_asn']
        tor1_asn = setup['tor1_asn']

        vm_route = nbrhosts[node]['host'].get_route(route.prefix)
        if not isinstance(vm_route, dict):
            logging.warn("DEBUG: unexpected vm_route type {}, {}".format(type(vm_route), vm_route))
        vm_route['failed'] = False
        vm_route['message'] = 'Checking route {} on {} passed'.format(str(route), node)
        if accepted:
            if route.prefix not in list(vm_route['vrfs']['default']['bgpRouteEntries'].keys()):
                vm_route['failed'] = True
                vm_route['message'] = 'No route for {} found on {}'.format(route.prefix, node)
            else:
                tor_route_aspath = vm_route['vrfs']['default']['bgpRouteEntries'][route.prefix]['bgpRoutePaths'][0]\
                    ['asPathEntry']['asPath']   # noqa E211
                # Route path from other VMs: -> DUT(T1) -> TOR1 -> aspath(other T1 -> DUMMY_ASN1)
                tor_route_aspath_expected = '{} {} {}'.format(dut_asn, tor1_asn, route.aspath)
                if tor_route_aspath != tor_route_aspath_expected:
                    vm_route['failed'] = True
                    vm_route['message'] = 'On {} expected aspath: {}, actual aspath: {}'\
                        .format(node, tor_route_aspath_expected, tor_route_aspath)
        else:
            if route.prefix in list(vm_route['vrfs']['default']['bgpRouteEntries'].keys()):
                vm_route['failed'] = True
                vm_route['message'] = 'No route {} expected on {}'.format(route.prefix, node)
        results[node] = vm_route

    other_vms = setup['other_vms']
    bgp_neighbors = json.loads(duthost.shell("sonic-cfggen -d --var-json 'BGP_NEIGHBOR'")['stdout'])

    # check tor1
    pytest_assert(wait_until(5, 1, 0, check_tor1, nbrhosts, setup, route), 'tor1 check failed')

    # check DUT
    pytest_assert(wait_until(5, 1, 0, check_dut, duthost, other_vms, bgp_neighbors,
                  setup, route, accepted=accepted), 'DUT check failed')

    results = parallel_run(check_other_vms, (nbrhosts, setup, route), {'accepted': accepted},
                           other_vms, timeout=120, concurrent_tasks=6)

    failed_results = {}
    for node, result in list(results.items()):
        if result['failed']:
            failed_results[node] = result

    pytest_assert(not failed_results, 'Checking route {} failed, failed_results: {}'
                  .format(str(route), json.dumps(failed_results, indent=2)))


def test_bbr_enabled_dut_asn_in_aspath(duthosts, rand_one_dut_hostname, nbrhosts,
                                       config_bbr_enabled, setup, prepare_routes):
    duthost = duthosts[rand_one_dut_hostname]
    bbr_route = setup['bbr_route']
    bbr_route_v6 = setup['bbr_route_v6']
    prepare_routes([bbr_route, bbr_route_v6])
    for route in [bbr_route, bbr_route_v6]:
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=True)


def test_bbr_enabled_dual_dut_asn_in_aspath(duthosts, rand_one_dut_hostname, nbrhosts,
                                            config_bbr_enabled, setup, prepare_routes):
    duthost = duthosts[rand_one_dut_hostname]
    bbr_route_dual_dut_asn = setup['bbr_route_dual_dut_asn']
    bbr_route_v6_dual_dut_asn = setup['bbr_route_v6_dual_dut_asn']
    prepare_routes([bbr_route_dual_dut_asn, bbr_route_v6_dual_dut_asn])
    for route in [bbr_route_dual_dut_asn, bbr_route_v6_dual_dut_asn]:
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=False)


def test_bbr_disabled_dut_asn_in_aspath(duthosts, rand_one_dut_hostname, nbrhosts,
                                        config_bbr_disabled, setup, prepare_routes):
    duthost = duthosts[rand_one_dut_hostname]
    bbr_route = setup['bbr_route']
    bbr_route_v6 = setup['bbr_route_v6']
    prepare_routes([bbr_route, bbr_route_v6])
    for route in (bbr_route, bbr_route_v6):
        check_bbr_route_propagation(duthost, nbrhosts, setup, route, accepted=False)
