'''

This script is to verify DUT's ability to carry both IPv4 and IPv6
Network Layer Reachability Information (NLRI) over a single IPv4 BGP session.

'''
import logging

import pytest
import time
from tests.common.config_reload import config_reload
from natsort import natsorted

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname, enum_rand_one_frontend_asic_index, request):
    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[rand_one_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    tor_neighbors = dict()
    tor1 = natsorted(nbrhosts.keys())[0]
    logger.debug("tor1: {}".format(tor1))

    skip_hosts = duthost.get_asic_namespace_list()
    logger.debug("Skip hosts: {}".format(skip_hosts))

    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['ip_version'] == 4:
                neigh_ip_v4 = k
                peer_group_v4 = v['peer group']
                assert v['state'] == 'established'
            elif v['ip_version'] == 6:
                neigh_ip_v6 = k
                peer_group_v6 = v['peer group']
                assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            tor_neighbors[v['description']] = nbrhosts[v['description']]["host"]
            logger.debug(v['description'])

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][1].lower()

    logger.info(duthost.shell('show ip bgp summary')['stdout'])
    logger.info(duthost.shell('show ipv6 bgp summary')['stdout'])

    cmd = "show ipv6 bgp neighbor {} received-routes".format(neigh_ip_v6)
    dut_nlri_routes = duthost.shell(cmd, module_ignore_errors=True)['stdout'].split('\n')
    dut_nlri_route = dut_nlri_routes[12].split()[1]

    cmd = "show ipv6 bgp neighbor {} received-routes".format(dut_ip_v6)
    neigh_nlri_routes = tor_neighbors[tor1].shell(cmd, module_ignore_errors=True)['stdout'].split('\n')
    neigh_nlri_route = neigh_nlri_routes[len(neigh_nlri_routes) - 3].split()[1]

    setup_info = {
        'duthost': duthost,
        'neighhost': tor_neighbors[tor1],
        'tor1': tor1,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[tor1],
        'asn_dict':  neigh_asn,
        'neighbors': tor_neighbors,
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'dut_nlri_route': dut_nlri_route,
        'neigh_nlri_route': neigh_nlri_route
    }

    logger.info("DUT BGP Config: {}".format(duthost.shell('show run bgp')['stdout']))
    logger.info("Neighbor BGP Config: {}".format(
        nbrhosts[tor1]["host"].shell("show run bgp")['stdout']))
    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost, wait=60)
    config_reload(tor_neighbors[tor1], wait=60, is_dut=False)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def test_nlri(setup):
    # show current adjacancies
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    logger.info("DUT Route from neighbor: {}".format(setup['duthost'].shell(cmd)['stdout']))
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    logger.info("Neighbor Route from DUT: {}".format(setup['neighhost'].shell(cmd)['stdout']))

    # remove current neighbor adjacancy
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" \
        -c "no neighbor {} peer-group {}"'\
        .format(setup['namespace'], setup['dut_asn'], setup['neigh_ip_v4'], setup['peer_group_v4'],
                setup['neigh_ip_v6'], setup['peer_group_v6'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.info("DUT BGP Config After Neighbor Removal: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" \
        -c "no neighbor {} peer-group {}"'.format(setup['namespace'], setup['neigh_asn'], setup['dut_ip_v4'],
                                                  setup['peer_group_v4'], setup['dut_ip_v6'], setup['peer_group_v6'])
    setup['neighhost'].shell(cmd, module_ignore_errors=True)
    logger.info("Neighbor BGP Config After Neighbor Removal: {}".format(setup['neighhost']
                                                                        .shell(cmd="show run bgp")['stdout']))
    logger.info("Neighbor BGP IPv4 Summary: {}".format(setup['neighhost'].shell(cmd="show ip bgp summary")[u'stdout']))
    logger.info("Neighbor BGP IPv6 Summary: {}".format(setup['neighhost']
                                                       .shell(cmd="show ipv6 bgp summary")[u'stdout']))
    time.sleep(30)

    # clear BGP table
    cmd = 'vtysh -n {} -c "clear ip bgp * soft"'.format(setup['namespace'])
    setup['duthost'].shell(cmd)
    cmd = 'vtysh -c "clear ip bgp * soft"'
    setup['neighhost'].shell(cmd)

    # verify route is no longer shared
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    dut_route_out = setup['duthost'].shell(cmd)['stdout']
    assert setup['neigh_ip_v6'] not in dut_route_out
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    assert setup['dut_ip_v6'] not in neigh_route_out

    # configure IPv4 peer config on DUT
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor NLRI peer-group" -c "address-family ipv4 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
        -c "neighbor NLRI soft-reconfiguration inbound" -c "exit-address-family" -c "address-family ipv6 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
            -c "neighbor NLRI soft-reconfiguration inbound"'.format(setup['namespace'], setup['dut_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} peer-group NLRI" -c "neighbor {} remote-as {}"\
        -c "address-family ipv4 unicast" -c "neighbor NLRI activate" -c "exit-address-family" \
        -c "address-family ipv6 unicast" -c "neighbor NLRI activate"'\
            .format(setup['namespace'], setup['dut_asn'], setup['neigh_ip_v4'], setup['neigh_ip_v4'],
                    setup['neigh_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.info("DUT BGP Config After Peer Config: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

    # configure IPv4 peer on neighbor
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor NLRI peer-group" -c "address-family ipv4 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
            -c "neighbor NLRI soft-reconfiguration inbound" -c "address-family ipv6 unicast" \
                -c "neighbor NLRI activate" -c "neighbor NLRI allowas-in" \
         -c "neighbor NLRI soft-reconfiguration inbound"'\
            .format(setup['neigh_asn'])
    setup['neighhost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} peer-group NLRI" -c "neighbor {} remote-as {}"\
        -c "address-family ipv4 unicast" -c "neighbor NLRI activate"'.format(setup['neigh_asn'], setup['dut_ip_v4'],
                                                                             setup['dut_ip_v4'], setup['dut_asn'])
    setup['neighhost'].shell(cmd, module_ignore_errors=True)
    logger.info("Neighbor BGP Config After Peer Config: {}".format(setup['neighhost'].shell('show run bgp')['stdout']))

    time.sleep(30)

    logger.info("Neighbor BGP IPv4 Summary: {}".format(setup['neighhost'].shell("show ip bgp summary")['stdout']))
    logger.info("Neighbor BGP IPv6 Summary: {}".format(setup['neighhost'].shell("show ipv6 bgp summary")['stdout']))

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'

    # verify route is shared
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    dut_route_out = setup['duthost'].shell(cmd)['stdout']
    assert "Routing entry for {}".format(setup['dut_nlri_route']) in dut_route_out
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    assert "Routing entry for {}".format(setup['neigh_nlri_route']) in neigh_route_out
