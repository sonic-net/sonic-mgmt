import logging
import time
import pytest
import requests
import ipaddr as ipaddress

from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t1')
]

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000

@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, tbinfo, nbrhosts):
    """
    Collect data about DUT and T2 neighbors.
    Args:
        duthosts: DUT host object
        rand_one_dut_hostname: Random hostname belonging to one of the DUT instances
        tbinfo: DUT info
        nbrhosts: VM's object

    Returns: DUT and T2 neighbors info
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    t2_neighbors = [neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T2')]
    tor1 = tor_neighbors[0]
    tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]['vm_offset']
    tor1_exabgp_port = EXABGP_BASE_PORT + tor1_offset
    tor1_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + tor1_offset

    setup_info = {
        'tor1': tor1,
        't2_neighbors' : t2_neighbors,
        'tor1_exabgp_port': tor1_exabgp_port,
        'tor1_exabgp_port_v6': tor1_exabgp_port_v6,
    }

    return setup_info

def update_routes(action, ptfip, port, route):
    """
    Announce and withdraw routes (used in prepare_routes)
    Args:
        action: Announce or withdraw
        ptfip: ptfhost IP address
        port: Port number
        route: Route to update
    """
    if action not in ['announce', 'withdraw']:
        logger.error('Unsupported route update operation: {}'.format(action))
        return
    msg = '{} route {} next-hop {}'.format(action, route['prefix'], route['nexthop'])

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg }
    r = requests.post(url, data=data)
    pytest_assert(r.status_code == 200, 'Status code is not successful')

@pytest.fixture
def access_list(duthost, build_routes):
    """
    Create and remove IP access lists on DUT
    Args:
        duthost: DUT host object
        build_routes: Routes for test
    """
    routes = build_routes
    ipaddr = routes[0]['prefix']
    def create_access_list(duthost, ipaddr):
        duthost.shell("vtysh -c 'configure terminal' -c 'access-list permit-list permit {}' -c 'end'".format(ipaddr))

    yield create_access_list

    duthost.shell("vtysh -c 'configure terminal' -c 'no access-list permit-list permit {}' -c 'end'".format(ipaddr))

@pytest.fixture
def prepare_routes(setup, ptfhost, build_routes):
    """
    Announce and withdraw routes from T0 (ptf) to DUT
    Args:
        setup: Configuration data
        ptfhost: PTF host object
        build_routes: Routes for test
    """
    tor1_exabgp_port = setup['tor1_exabgp_port']
    tor1_exabgp_port_v6 = setup['tor1_exabgp_port_v6']
    routes_to_remove = []
    def announce_routes(routes):
        for route in routes:
            routes_to_remove.append(route)
            if ipaddress.IPNetwork(route['prefix']).version == 4:
                update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port, route)
            else:
                update_routes('announce', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)

    yield announce_routes

    for route in routes_to_remove:
        if ipaddress.IPNetwork(route['prefix']).version == 4:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port, route)
        else:
            update_routes('withdraw', ptfhost.mgmt_ip, tor1_exabgp_port_v6, route)

@pytest.fixture()
def apply_route_map(duthost):
    """
    Create and remove route-map
    Args:
        duthost: DUT host object
    """
    def create_route_map(duthost):
        duthost.shell("vtysh -c 'configure terminal' -c 'route-map test_access_list permit 1' -c 'match ip address permit-list' -c 'end'")
        duthost.shell("vtysh -c 'configure terminal' -c 'route-map FROM_BGP_PEER_V4 permit 10' -c 'call test_access_list' -c 'end'")
        time.sleep(3)

    yield create_route_map

    duthost.shell("vtysh -c 'configure terminal' -c 'route-map FROM_BGP_PEER_V4 permit 10' -c 'no call test_access_list' -c 'end'")
    duthost.shell("vtysh -c 'configure terminal' -c 'no route-map test_access_list' -c 'end'")

def verify_dut_routes(duthost, setup, build_routes):
    """
    Verify that route from range of IP access-list announced to DUT
    and other route are not announced.
    Args:
        duthost: DUT host object
        setup: Configuration data
        build_routes: Routes for test
    """
    routes = build_routes
    dut_route_1 = duthost.get_route(routes[0]['prefix'])
    dut_route_2 = duthost.get_route(routes[1]['prefix'])
    pytest_assert(dut_route_1, 'Route {} is not found on DUT'.format(routes[0]['prefix']))
    pytest_assert(not dut_route_2, 'Route {} is announced to DUT'.format(routes[1]['prefix']))

def verify_t2_routes(setup, nbrhosts, build_routes):
    """
    Verify that route from range of IP access-list announced to all T2 peers
    and other route are not announced.
    Args:
        setup: Configuration data
        nbrhosts: VM's object
        build_routes: Routes for test
    """
    t2_neighbors = setup['t2_neighbors']
    routes = build_routes
    for t2_neighbor in t2_neighbors:
        vm_route_1 = nbrhosts[t2_neighbor]['host'].get_route(routes[0]['prefix'])
        vm_route_2 = nbrhosts[t2_neighbor]['host'].get_route(routes[1]['prefix'])
        pytest_assert(routes[0]['prefix'] in vm_route_1['vrfs']['default']['bgpRouteEntries'].keys(),
         'Route {} is not announced to {}'.format(routes[0]['prefix'], t2_neighbor))
        pytest_assert(routes[1]['prefix'] not in vm_route_2['vrfs']['default']['bgpRouteEntries'].keys(),
         'Route {} is announced to {}'.format(routes[1]['prefix'], t2_neighbor))


def test_access_list(setup, nbrhosts, duthost, build_routes, prepare_routes, apply_route_map, access_list):
    """
        Verify that Route-map can permit and deny routes, based on IP access-list. 
        Test steps:
            1) Set route-map entry with permit rule that filter IP access-list.  
            2) Announce predefined ipv4 routes that in/out of range of created IP access-lists 
               from one of the T0s to DUT. 
            3) Check that routes from range of IP access-list announced to DUT and T2 peer, 
               and other routes are not announced. 
            4) Remove created route maps, IP access-list and withdraw announced routes. 
        Pass Criteria: routes from range of IP access-list announced to DUT and T2 peer, 
               and other routes are not announced.
    """
    routes = build_routes
    # create permit access list
    access_list(duthost, routes[0]['prefix'])
    # create route-map
    apply_route_map(duthost)
    # Announce predefined ipv4 routes that in/out of range of created IP access-list from one of the T0s to DUT.
    prepare_routes(routes)
    # verify that routes in range of created IP access-list, announced to DUT, and other routes are not announced.
    verify_dut_routes(duthost, setup, build_routes)
    # verify that routes in range of created IP access-list, announced to T2, and other routes are not announced.
    verify_t2_routes(setup, nbrhosts, build_routes)
