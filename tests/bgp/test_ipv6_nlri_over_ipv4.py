'''

This script is to verify DUT's ability to carry both IPv4 and IPv6
Network Layer Reachability Information (NLRI) over a single IPv4 BGP session.

'''
import logging

import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, request):
    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_frontend_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    neigh_name = lldp_table[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = None

    if nbrhosts[neigh_name]["host"].is_multi_asic:
        neigh_asic_index = nbrhosts[neigh_name]["host"].get_port_asic_instance(neigh_int).asic_index
    else:
        neigh_asic_index = None

    namespace = duthost.get_namespace_from_asic_id(asic_index)

    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh_name:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                    assert v['state'] == 'established'
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
                    assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            logger.debug(v['description'])

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][1].lower()

    neigh_namespace = DEFAULT_NAMESPACE
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if neigh_name == neigh['name']:
            neigh_namespace = neigh['namespace']
            break

    logger.debug(duthost.shell('show ip bgp summary')['stdout'])
    logger.debug(duthost.shell('show ipv6 bgp summary')['stdout'])

    cmd = "show ipv6 bgp neighbor {} received-routes".format(neigh_ip_v6)
    dut_nlri_routes = duthost.shell(cmd, module_ignore_errors=True)['stdout'].split('\n')
    logger.debug("DUT routes: {}".format(dut_nlri_routes[9]))
    dut_nlri_route = dut_nlri_routes[9].split()[1]

    logger.debug(nbrhosts[neigh_name]["host"].shell('vtysh -n {} vtysh -c "clear bgp * soft"'.format(neigh_namespace)))

    cmd = "show ipv6 bgp neighbor {} received-routes".format(dut_ip_v6)
    neigh_nlri_routes = nbrhosts[neigh_name]["host"].shell(cmd, module_ignore_errors=True)['stdout'].split('\n')
    logger.debug("neighbor routes: {}".format(neigh_nlri_routes[len(neigh_nlri_routes) - 3]))
    neigh_nlri_route = neigh_nlri_routes[len(neigh_nlri_routes) - 3].split()[1]

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[neigh_name]["host"],
        'neigh_name': neigh_name,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh_name],
        'asn_dict':  neigh_asn,
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'dut_nlri_route': dut_nlri_route,
        'neigh_nlri_route': neigh_nlri_route,
        'neigh_namespace': neigh_namespace,
        'dut_namespace': namespace,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell('show run bgp')['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(
        nbrhosts[neigh_name]["host"].shell("show run bgp")['stdout']))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost, wait=60)
    config_reload(nbrhosts[neigh_name]["host"], wait=60, is_dut=False)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def check_bgp_summary(host, neighbor, present):
    ipv4_sum = host.shell(cmd="show ip bgp summary")[u'stdout']
    isPresent = neighbor in ipv4_sum
    if isPresent != present:
        return False

    ipv6_sum = host.shell(cmd="show ipv6 bgp summary")[u'stdout']
    isPresent = neighbor in ipv6_sum
    if isPresent != present:
        return False
    return True


def test_nlri(setup):
    # show current adjacancies
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    logger.debug("DUT Route from neighbor: {}".format(setup['duthost'].shell(cmd)['stdout']))
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    logger.debug("Neighbor Route from DUT: {}".format(setup['neighhost'].shell(cmd)['stdout']))

    # remove current neighbor adjacancy
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" \
        -c "no neighbor {} peer-group {}"'\
        .format(setup['asic_index'], setup['dut_asn'], setup['neigh_ip_v4'], setup['peer_group_v4'],
                setup['neigh_ip_v6'], setup['peer_group_v6'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.debug("DUT BGP Config After Neighbor Removal: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" \
        -c "no neighbor {} peer-group {}"'.format(setup['asic_index'], setup['neigh_asn'], setup['dut_ip_v4'],
                                                  setup['peer_group_v4'], setup['dut_ip_v6'], setup['peer_group_v6'])
    setup['neighhost'].shell(cmd, module_ignore_errors=True)
    logger.debug("Neighbor BGP Config After Neighbor Removal: {}".format(setup['neighhost']
                                                                         .shell(cmd="show run bgp")['stdout']))

    wait_until(90, 10, 0, check_bgp_summary, setup['neighhost'], setup['dut_ip_v4'], False)

    # clear BGP table
    cmd = 'vtysh -n {} -c "clear ip bgp * soft"'.format(setup['asic_index'])
    setup['duthost'].shell(cmd)
    cmd = 'vtysh -c "clear ip bgp * soft"'
    setup['neighhost'].shell(cmd)

    # verify route is no longer shared
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    dut_route_out = setup['duthost'].shell(cmd)['stdout']
    pytest_assert(setup['neigh_ip_v6'] not in dut_route_out, "No route to IPv6 neighbor.")
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    pytest_assert(setup['dut_ip_v6'] not in neigh_route_out, "No route to IPv6 DUT.")

    # configure IPv4 peer config on DUT
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor NLRI peer-group" -c "address-family ipv4 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
        -c "neighbor NLRI soft-reconfiguration inbound" -c "exit-address-family" -c "address-family ipv6 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
            -c "neighbor NLRI soft-reconfiguration inbound"'.format(setup['asic_index'], setup['dut_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} peer-group NLRI" -c "neighbor {} remote-as {}"\
        -c "address-family ipv4 unicast" -c "neighbor NLRI activate" -c "exit-address-family" \
        -c "address-family ipv6 unicast" -c "neighbor NLRI activate"'\
            .format(setup['asic_index'], setup['dut_asn'], setup['neigh_ip_v4'], setup['neigh_ip_v4'],
                    setup['neigh_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.debug("DUT BGP Config After Peer Config: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

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
    logger.debug("Neighbor BGP Config After Peer Config: {}".format(setup['neighhost'].shell('show run bgp')['stdout']))

    wait_until(90, 10, 0, check_bgp_summary, setup['neighhost'], setup['dut_ip_v4'], True)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    pytest_assert(bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established',
                  "Neighbor IPv4 state is no established.")

    # verify route is shared
    cmd = "show ipv6 route {}".format(setup['dut_nlri_route'])
    dut_route_out = setup['duthost'].shell(cmd)['stdout']
    pytest_assert("Routing entry for {}".format(setup['dut_nlri_route']) in dut_route_out,
                  "Routing entry for DUT not established.")
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    pytest_assert("Routing entry for {}".format(setup['neigh_nlri_route']) in neigh_route_out,
                  "Routing entry for neighbor not established.")
