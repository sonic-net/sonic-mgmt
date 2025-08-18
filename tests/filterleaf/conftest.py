import pytest
import yaml
import logging
import ipaddress
import requests
import time
from natsort import natsorted
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP, DEFAULT_NAMESPACE
CONSTANTS_FILE = '/etc/sonic/constants.yml'
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
TEST_COMMUNITY = '1010:1010'
PREFIX_LISTS = {
    'ALLOWED': ['172.16.10.0/24'],
    'ALLOWED_WITH_COMMUNITY': ['172.16.20.0/24'],
    'ALLOWED_V6': ['2000:172:16:10::/64'],
    'ALLOWED_WITH_COMMUNITY_V6': ['2000:172:16:20::/64'],
    'DISALLOWED': ['172.16.30.0/24'],
    'DISALLOWED_V6': ['2000:172:16:30::/64']
}


def build_routes(tbinfo, prefix_list, expected_community):
    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    routes = []
    for list_name, prefixes in list(prefix_list.items()):
        logging.info('list_name: {}, prefixes: {}'.format(list_name, str(prefixes)))
        for prefix in prefixes:
            route = {}
            route['prefix'] = prefix
            if ipaddress.ip_network(prefix).version == 4:
                route['nexthop'] = nhipv4
            else:
                route['nexthop'] = nhipv6
            if 'COMMUNITY' in list_name:
                route['community'] = expected_community
            routes.append(route)

    return routes


def update_routes(action, ptfip, port, route):
    if action not in ['announce', 'withdraw']:
        logging.error('Unsupported route update operation: {}'.format(action))
        return
    msg = '{} route {} next-hop {}'.format(action, route['prefix'], route['nexthop'])
    if 'community' in route:
        msg += ' community {}'.format(route['community'])

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg}
    logging.info('Post url={}, data={}'.format(url, data))
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
    assert r.status_code == 200


@pytest.fixture(scope='module')
def bgp_allow_list_setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname):
    """
    Get bgp_allow_list related information
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo_type = tbinfo["topo"]["type"]
    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    if not constants_stat['stat']['exists']:
        pytest.fail(f"No file {CONSTANTS_FILE} on DUT, BGP Allow List is not supported")

    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])

    global DEFAULT_ACTION
    try:
        DEFAULT_ACTION = constants['constants']['bgp']['allow_list']['default_action']
    except KeyError:
        pytest.skip('No BGP Allow List configuration in {}, BGP Allow List is not supported.'.format(CONSTANTS_FILE))

    global DROP_COMMUNITY
    try:
        DROP_COMMUNITY = constants['constants']['bgp']['allow_list']['drop_community']
    except KeyError:
        pytest.skip('No BGP Allow List Drop Commnity define in {}, BGP Allow List is not supported.'
                    .format(CONSTANTS_FILE))

    setup_info = {}

    upstream_type = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()
    downstream_type = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    downstream_neighbors = \
        natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(downstream_type)])
    downstream = downstream_neighbors[0]
    upstream_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(upstream_type)])
    other_neighbors = downstream_neighbors[1:3]    # Only check a few neighbors to save time
    if upstream_neighbors:
        other_neighbors = upstream_neighbors[0:2]

    downstream_offset = tbinfo['topo']['properties']['topology']['VMs'][downstream]['vm_offset']
    downstream_exabgp_port = EXABGP_BASE_PORT + downstream_offset
    downstream_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + downstream_offset

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    downstream_namespace = DEFAULT_NAMESPACE

    for _, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if downstream == neigh['name'] and neigh['namespace']:
            downstream_namespace = neigh['namespace']
            break

    setup_info = {
        'downstream': downstream,
        'downstream_namespace': downstream_namespace,
        'downstream_exabgp_port': downstream_exabgp_port,
        'downstream_exabgp_port_v6': downstream_exabgp_port_v6,
        'other_neighbors': other_neighbors,
    }
    yield setup_info


@pytest.fixture(scope='module', autouse=True)
def prepare_eos_routes(bgp_allow_list_setup, ptfhost, nbrhosts, tbinfo):
    routes = build_routes(tbinfo, PREFIX_LISTS, TEST_COMMUNITY)
    downstream = bgp_allow_list_setup['downstream']
    downstream_exabgp_port = bgp_allow_list_setup['downstream_exabgp_port']
    downstream_exabgp_port_v6 = bgp_allow_list_setup['downstream_exabgp_port_v6']
    downstream_asn = tbinfo['topo']['properties']['configuration'][downstream]['bgp']['asn']
    downstream_peers = tbinfo['topo']['properties']['configuration'][downstream]['bgp']['peers']

    # By default, EOS does not send community, this is to config EOS to send community
    cmds = []
    for peer_ips in list(downstream_peers.values()):
        for peer_ip in peer_ips:
            cmds.append('neighbor {} send-community'.format(peer_ip))
    nbrhosts[downstream]['host'].eos_config(lines=cmds, parents='router bgp {}'.format(downstream_asn))

    for route in routes:
        if ipaddress.ip_network(route['prefix']).version == 4:
            update_routes('announce', ptfhost.mgmt_ip, downstream_exabgp_port, route)
        else:
            update_routes('announce', ptfhost.mgmt_ip, downstream_exabgp_port_v6, route)
    time.sleep(3)

    yield

    for route in routes:
        if ipaddress.ip_network(route['prefix']).version == 4:
            update_routes('withdraw', ptfhost.mgmt_ip, downstream_exabgp_port, route)
        else:
            update_routes('withdraw', ptfhost.mgmt_ip, downstream_exabgp_port_v6, route)
    # Restore EOS config
    no_cmds = ['no {}'.format(cmd) for cmd in cmds]
    nbrhosts[downstream]['host'].eos_config(lines=no_cmds, parents='router bgp {}'.format(downstream_asn))
