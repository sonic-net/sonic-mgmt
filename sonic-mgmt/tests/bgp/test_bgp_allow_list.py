'''This script is to test the BGP Allow List feature of SONiC.
'''
import json
import logging
import time
import yaml

import pytest
import requests
import ipaddr as ipaddress

from jinja2 import Template
from natsort import natsorted
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.parallel import parallel_run

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

CONSTANTS_FILE = '/etc/sonic/constants.yml'

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

PREFIX_LISTS = {
    'ALLOWED': ['172.16.10.0/24'],
    'ALLOWED_WITH_COMMUNITY': ['172.16.30.0/24'],
    'ALLOWED_V6': ['2000:172:16:10::/64'],
    'ALLOWED_WITH_COMMUNITY_V6': ['2000:172:16:30::/64'],
    'DISALLOWED': ['172.16.50.0/24'],
    'DISALLOWED_V6': ['2000:172:16:50::/64']
}

TEST_COMMUNITY = '1010:1010'
DROP_COMMUNITY = '5060:12345'
DEPLOYMENT_ID = '0'

ALLOW_LIST = {
    'BGP_ALLOWED_PREFIXES': {
        'DEPLOYMENT_ID|{}|{}'.format(DEPLOYMENT_ID, TEST_COMMUNITY): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY_V6']
        },
        'DEPLOYMENT_ID|{}'.format(DEPLOYMENT_ID): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_V6']
        }
    }
}


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    if tbinfo['topo']['type'] != 't1':
        pytest.skip('Unsupported topology type: {}, supported: {}'.format(tbinfo['topo']['type'], 't1'))

    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.skip('No file {} on DUT, BGP Allow List is not supported')

    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
    try:
        constants['constants']['bgp']['allow_list']['default_action']
    except KeyError as e:
        pytest.skip('No BGP Allow List configuration in {}, BGP Allow List is not supported.'.format(CONSTANTS_FILE))

    setup_info = {}

    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]
    spine_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T2')])
    other_neighbors = tor_neighbors[1:3] + spine_neighbors[0:2]  # Only check a few neighbors to save time

    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    tor1_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + tor1_offset

    setup_info = {
        'tor1': tor1,
        'tor1_exabgp_port': tor1_exabgp_port,
        'tor1_exabgp_port_v6': tor1_exabgp_port_v6,
        'other_neighbors': other_neighbors,
    }

    logger.info('setup_info: {}'.format(json.dumps(setup_info, indent=2)))

    return setup_info


def update_routes(action, ptfip, port, route):
    if action not in ['announce', 'withdraw']:
        logger.error('Unsupported route update operation: {}'.format(action))
        return
    msg = '{} route {} next-hop {}'.format(action, route['prefix'], route['nexthop'])
    if 'community' in route:
        msg += ' community {}'.format(route['community'])

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg }
    logger.info('Post url={}, data={}'.format(url, data))
    r = requests.post(url, data=data)
    assert r.status_code == 200


@pytest.fixture(scope='module', autouse=True)
def prepare_allow_list(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]
    duthost.copy(content=json.dumps(ALLOW_LIST, indent=2), dest='/tmp/allow_list.json')


@pytest.fixture
def load_remove_allow_list(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sonic-cfggen -j /tmp/allow_list.json -w')
    time.sleep(3)

    yield

    allow_list_keys = duthost.shell('redis-cli --raw -n 4 keys "BGP_ALLOWED_PREFIXES*"')['stdout_lines']
    for key in allow_list_keys:
        duthost.shell('redis-cli -n 4 del "{}"'.format(key))


@pytest.fixture(scope='module')
def build_routes(tbinfo):
    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    routes = []
    for list_name, prefixes in PREFIX_LISTS.items():
        logger.info('list_name: {}, prefixes: {}'.format(list_name, str(prefixes)))
        for prefix in prefixes:
            route = {}
            route['prefix'] = prefix
            if ipaddress.IPNetwork(prefix).version == 4:
                route['nexthop'] = nhipv4
            else:
                route['nexthop'] = nhipv6
            if 'COMMUNITY' in list_name:
                route['community'] = TEST_COMMUNITY
            routes.append(route)

    yield routes


@pytest.fixture(scope='module', autouse=True)
def prepare_eos_routes(setup, ptfhost, build_routes, nbrhosts, tbinfo):
    tor1 = setup['tor1']
    tor1_exabgp_port = setup['tor1_exabgp_port']
    tor1_exabgp_port_v6 = setup['tor1_exabgp_port_v6']
    tor1_asn = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['asn']
    tor1_peers = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers']
    routes = build_routes

    # By default, EOS does not send community, this is to config EOS to send community
    cmds = []
    for peer_ips in tor1_peers.values():
        for peer_ip in peer_ips:
            cmds.append('neighbor {} send-community'.format(peer_ip))
    nbrhosts[tor1]['host'].eos_config(lines=cmds, parents='router bgp {}'.format(tor1_asn))

    for route in routes:
        if ipaddress.IPNetwork(route['prefix']).version == 4:
            update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, route)
        else:
            update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)
    time.sleep(3)

    yield

    for route in routes:
        if ipaddress.IPNetwork(route['prefix']).version == 4:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port, route)
        else:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)

    # Restore EOS config
    no_cmds = ['no {}'.format(cmd) for cmd in cmds]
    nbrhosts[tor1]['host'].eos_config(lines=no_cmds, parents='router bgp {}'.format(tor1_asn))


class BGPAllowListBase(object):

    def bgp_started(self, duthost, tbinfo):
        try:
            bgp_summary = json.loads(duthost.shell('vtysh -c "show bgp summary json"')['stdout'])
            peer_num = len(tbinfo['topo']['properties']['configuration'].keys())
            if bgp_summary['ipv4Unicast']['failedPeers'] == 0 and \
                bgp_summary['ipv6Unicast']['failedPeers'] == 0 and \
                bgp_summary['ipv4Unicast']['totalPeers'] == peer_num and \
                bgp_summary['ipv6Unicast']['totalPeers'] == peer_num:
                return True
            else:
                return False
        except Exception as e:
            logger.info('Unable to get bgp status')
            return False

    def check_routes_on_tor1(self, setup, nbrhosts):
        tor1 = setup['tor1']
        for prefixes in PREFIX_LISTS.values():
            for prefix in prefixes:
                tor1_route = nbrhosts[tor1]['host'].get_route(prefix)
                route_entries = tor1_route['vrfs']['default']['bgpRouteEntries']
                pytest_assert(prefix in route_entries, 'Announced route {} not found on {}'.format(prefix, tor1))

    def check_routes_on_dut(self, duthost):
        for prefixes in PREFIX_LISTS.values():
            for prefix in prefixes:
                dut_route = duthost.get_route(prefix)
                pytest_assert(dut_route, 'Route {} is not found on DUT'.format(prefix))

    def check_results(self, results):
        pytest_assert(len(results.keys())>0, 'No result on neighbors')
        failed_results = {}
        for node, node_prefix_results in results.items():
            failed_results[node] = [r for r in node_prefix_results if r['failed']]

        pytest_assert(all([len(r) == 0 for r in failed_results.values()]), \
            'Unexpected routes on neighbors, failed_results={}'.format(json.dumps(failed_results, indent=2)))

    def check_routes_on_neighbors(self, nbrhosts, setup, permit=True):
        other_neighbors = setup['other_neighbors']

        @reset_ansible_local_tmp
        def check_other_neigh(nbrhosts, permit, node=None, results=None):
            logger.info('Checking routes on {}'.format(node))

            prefix_results = []
            for list_name, prefixes in PREFIX_LISTS.items():
                for prefix in prefixes:
                    prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                    neigh_route = nbrhosts[node]['host'].get_route(prefix)['vrfs']['default']['bgpRouteEntries']

                    if permit:  # default_action=='permit'
                        # All routes should be forwarded
                        if prefix not in neigh_route:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('Route {} not found on {}'.format(prefix, node))
                        else:
                            communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']

                            if 'DISALLOWED' in list_name:
                                # Should add drop_community to routes not on allow list
                                if DROP_COMMUNITY not in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons']\
                                        .append('When default_action="permit", should add drop_community to routes not '
                                            'on allow list. route={}, node={}'.format(prefix, node))
                            else:
                                # Should not add drop_community to routes on allow list
                                if DROP_COMMUNITY in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons']\
                                        .append('When default_action="permit", should not add drop_community to routes '
                                            'on allow listroute in allow list with community, route={}, node={}'
                                            .format(prefix, node))

                                # Should keep original route community
                                if 'COMMUNITY' in list_name:
                                    if TEST_COMMUNITY not in communityList:
                                        prefix_result['failed'] = True
                                        prefix_result['reasons']\
                                            .append('When default_action="permit", route on allow list with community '
                                                'should keep its original community {}, route={}, node={}'
                                                .format(TEST_COMMUNITY, prefix, node))
                    else:   # default_action=='deny'
                        if 'DISALLOWED' in list_name:
                            # Routes not on allow list should not be forwarded
                            if prefix in neigh_route:
                                prefix_result['failed'] = True
                                prefix_result['reasons'].append('When default_action="deny", route NOT on allow list '
                                    'should not be forwarded. route={}, node={}'.format(prefix, node))
                        else:
                            # Routes on allow list should be forwarded
                            if prefix not in neigh_route:
                                prefix_result['failed'] = True
                                prefix_result['reasons'].append('When default_action="deny", route on allow list '
                                    'should be forwarded. route={}, node={}'.format(prefix, node))
                            else:
                                communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']
                                # Forwarded route should not have DROP_COMMUNITY
                                if DROP_COMMUNITY in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons']\
                                        .append('When default_action="deny", route on allow list with community '
                                            'should not have drop_community. route={}, node={}'\
                                            .format(prefix, node))

                                # Should keep original route community
                                if 'COMMUNITY' in list_name:
                                    if TEST_COMMUNITY not in communityList:
                                        prefix_result['failed'] = True
                                        prefix_result['reasons'].\
                                            append('When default_action="deny", route on allow list with community '
                                                'should keep its original community {}. route={}, node={}'
                                                .format(TEST_COMMUNITY, prefix, node))
                    prefix_results.append(prefix_result)
            results[node] = prefix_results

        results = parallel_run(check_other_neigh, (nbrhosts, permit), {}, other_neighbors, timeout=180)
        self.check_results(results)

    def check_routes_on_neighbors_empty_allow_list(self, nbrhosts, setup, permit=True):
        other_neighbors = setup['other_neighbors']

        @reset_ansible_local_tmp
        def check_other_neigh(nbrhosts, permit, node=None, results=None):
            logger.info('Checking routes on {}'.format(node))

            prefix_results = []
            for list_name, prefixes in PREFIX_LISTS.items():
                for prefix in prefixes:
                    prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                    neigh_route = nbrhosts[node]['host'].get_route(prefix)['vrfs']['default']['bgpRouteEntries']

                    if permit:  # default_action=='permit'
                        # All routes should be forwarded
                        if prefix not in neigh_route:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('Route {} not found on {}'.format(prefix, node))
                        else:
                            communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']

                            # Should add drop_community to all routes
                            if DROP_COMMUNITY not in communityList:
                                prefix_result['failed'] = True
                                prefix_result['reasons']\
                                    .append('When default_action="permit" and allow list is empty, should add '
                                        'drop_community to all routes. route={}, node={}'.format(prefix, node))

                            # Should keep original route community
                            if 'COMMUNITY' in list_name:
                                if TEST_COMMUNITY not in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons']\
                                        .append('When default_action="permit" and allow list is empty, should keep '
                                            'the original community {}, route={}, node={}'
                                            .format(TEST_COMMUNITY, prefix, node))

                    else:   # default_action=='deny'
                        # All routes should be dropped
                        if prefix in neigh_route:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('When default_action="deny" and allow list is empty, '
                                'all routes should be dropped. route={}, node={}'.format(prefix, node))
                    prefix_results.append(prefix_result)
            results[node] = prefix_results

        results = parallel_run(check_other_neigh, (nbrhosts, permit), {}, other_neighbors, timeout=180)
        self.check_results(results)


class TestBGPAllowListPermit(BGPAllowListBase):

    @pytest.fixture(scope='class', autouse=True)
    def default_action_permit(self, duthosts, rand_one_dut_hostname, tbinfo):
        duthost = duthosts[rand_one_dut_hostname]
        constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
        default_action = constants['constants']['bgp']['allow_list']['default_action']

        if default_action != 'permit':
            logger.info('Set constants.bgp.allow_list.default_action to permit')
            constants['constants']['bgp']['allow_list']['default_action'] = 'permit'
            duthost.copy(content=yaml.safe_dump(constants), dest=CONSTANTS_FILE)

            logger.info('Restart BGP for default_action permit to take effect')
            duthost.shell('systemctl reset-failed bgp')  # Workaround for issue 'Start request repeated too quickly'
            duthost.shell('systemctl restart bgp')
            pytest_assert(wait_until(300, 30, self.bgp_started, duthost, tbinfo), 'Service bgp not started')

        return

    def test_empty_allow_list_permit(self, duthosts, rand_one_dut_hostname, setup, nbrhosts):
        duthost = duthosts[rand_one_dut_hostname]
        self.check_routes_on_tor1(setup, nbrhosts)
        self.check_routes_on_dut(duthost)
        self.check_routes_on_neighbors_empty_allow_list(nbrhosts, setup, permit=True)

    def test_allow_list_permit(self, duthosts, rand_one_dut_hostname, setup, nbrhosts, load_remove_allow_list):
        duthost = duthosts[rand_one_dut_hostname]
        self.check_routes_on_tor1(setup, nbrhosts)
        self.check_routes_on_dut(duthost)
        self.check_routes_on_neighbors(nbrhosts, setup, permit=True)


class TestBGPAllowListDeny(BGPAllowListBase):

    @pytest.fixture(scope='class', autouse=True)
    def default_action_deny(self, duthosts, rand_one_dut_hostname, tbinfo):
        duthost=duthosts[rand_one_dut_hostname]
        constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
        default_action = constants['constants']['bgp']['allow_list']['default_action']

        if default_action != 'deny':
            logger.info('Set constants.bgp.allow_list.default_action to deny')
            constants['constants']['bgp']['allow_list']['default_action'] = 'deny'
            duthost.copy(content=yaml.safe_dump(constants), dest=CONSTANTS_FILE)

            logger.info('Restart BGP for default_action deny to take effect')
            duthost.shell('systemctl reset-failed bgp')  # Workaround for issue 'Start request repeated too quickly'
            duthost.shell('systemctl restart bgp')
            pytest_assert(wait_until(300, 30, self.bgp_started, duthost, tbinfo), 'Service bgp not started')

        yield

        logger.info('Set constants.bgp.allow_list.default_action to permit')
        constants['constants']['bgp']['allow_list']['default_action'] = 'permit'
        duthost.copy(content=yaml.safe_dump(constants), dest=CONSTANTS_FILE)

        logger.info('Restart BGP for default_action deny to take effect')
        duthost.shell('systemctl reset-failed bgp')  # Workaround for issue 'Start request repeated too quickly'
        duthost.shell('systemctl restart bgp')
        wait_until(300, 20, self.bgp_started, duthost, tbinfo)

    def test_empty_allow_list_deny(self, duthosts, rand_one_dut_hostname, setup, nbrhosts):
        duthost = duthosts[rand_one_dut_hostname]
        self.check_routes_on_tor1(setup, nbrhosts)
        self.check_routes_on_dut(duthost)
        self.check_routes_on_neighbors_empty_allow_list(nbrhosts, setup, permit=False)

    def test_allow_list_deny(self, duthosts, rand_one_dut_hostname, setup, nbrhosts, load_remove_allow_list):
        duthost = duthosts[rand_one_dut_hostname]
        self.check_routes_on_tor1(setup, nbrhosts)
        self.check_routes_on_dut(duthost)
        self.check_routes_on_neighbors(nbrhosts, setup, permit=False)
