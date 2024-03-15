"""
Test BGP Route Aggregation

Step 1: Ensure EBGP neighborship between DUT and NEI_DUT
Step 2: Capture the route summary advertized on NEI_DUT
Step 3: Aggregate EBGP routes
Step 4: Verify aggregated EBGP routes on NEI_DUT
Step 5: Aggregate EBGP routes with 'as-set'
Step 6: Verify aggregated EBGP routes on NEI_DUT include AS-path

Pass/Fail Criteria:
An aggregate route is generated in all cases, a CLI knob option controls whether or not the specifics
are sent or not.  No as-set information is generated in the AS_PATH of the aggregate route
(or a knob exists that disables the generation of as-set).
"""

import pytest
import time
import logging
import re
from tests.common.config_reload import config_reload

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

NEI_IPv4_AGG_ROUTE = "192.168.0.0/16"
NEI_IPv6_AGG_ROUTE = "20c0:a800::/24"
establish_bgp_session_time = 60
nei_ipv4_route_1 = "192.168.96.0/25"
nei_ipv4_route_2 = "192.168.97.0/25"
nei_ipv6_route_1 = "20c0:a851::/64"
nei_ipv6_route_2 = "20c0:a852::/64"


@pytest.fixture(scope='module')
def setup(tbinfo, duthosts, enum_frontend_dut_hostname, nbrhosts, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    neigh = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()[1]
    logger.debug("neigh: {}".format(neigh))
    skip_hosts = duthost.get_asic_namespace_list()

    # verify bgp neighbor relationship is established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
            assert v['state'] == 'established'

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][1].lower()

    # capture route summary on neighbor
    cmd = 'vtysh -c "show bgp ipv4 all neighbors {} advertised-routes" -c "show bgp ipv6 all neighbors {} \
        advertised-routes" -c "show ip bgp summary" -c "show ip bgp neighbors {}" \
        -c "show bgp ipv6 neighbors {}"'.format(dut_ip_v4, dut_ip_v6, dut_ip_v4, dut_ip_v6)
    logger.debug(nbrhosts[neigh]["host"].shell(cmd, module_ignore_errors=True)['stdout'])

    ipv4_sum = duthost.shell("show ip bgp summary", module_ignore_errors=True)['stdout']
    ipv6_sum = duthost.shell("show ipv6 bgp summary", module_ignore_errors=True)['stdout']
    ipv4_num_neigh = re.findall("Total number of neighbors (\\d+)", ipv4_sum)[0]
    ipv6_num_neigh = re.findall("Total number of neighbors (\\d+)", ipv6_sum)[0]

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[neigh]["host"],
        'neigh': neigh,
        'dut_asn': dut_asn,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'cli_options': cli_options,
        'asic_index': asic_index,
        'base_v4_neigh': ipv4_num_neigh,
        'base_v6_neigh': ipv6_num_neigh
    }

    logger.debug("DUT Config After Setup: {}".format(duthost.shell("show run bgp",
                 module_ignore_errors=True)['stdout']))

    yield setup_info

    # restore config to original state
    config_reload(duthost, wait=60)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'] == neigh:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def test_ebgp_route_aggregation(setup):
    # aggregate directly connected routes
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
        -c "aggregate-address {} summary-only" -c "address-family ipv6 unicast" \
        -c "aggregate-address {} summary-only"'.format(setup['cli_options'], setup['dut_asn'], NEI_IPv4_AGG_ROUTE,
                                                       NEI_IPv6_AGG_ROUTE)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh{} -c "clear bgp * soft"'.format(setup['cli_options'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(establish_bgp_session_time)

    logger.debug("DUT Config After Aggregation: {}".format(setup['duthost'].shell("show run bgp",
                 module_ignore_errors=True)['stdout']))

    cmd = "show ip bgp neighbors {} received-routes".format(setup['dut_ip_v4'])
    nei_show_neigh_v4 = setup['neighhost'].shell(cmd, module_ignore_errors=True)['stdout']
    cmd = "show ipv6 bgp neighbors {} received-routes".format(setup['dut_ip_v6'])
    nei_show_neigh_v6 = setup['neighhost'].shell(cmd, module_ignore_errors=True)['stdout']
    logger.debug("BGP Neighbors IPv4: {}\n\nBGP Neighbors IPv6: {}".format(nei_show_neigh_v4, nei_show_neigh_v6))
    ipv4_agg_route_present = False
    ipv6_agg_route_present = False
    if NEI_IPv4_AGG_ROUTE in nei_show_neigh_v4:
        ipv4_agg_route_present = True
    if NEI_IPv6_AGG_ROUTE in nei_show_neigh_v6:
        ipv6_agg_route_present = True
    assert ipv4_agg_route_present is True
    assert ipv6_agg_route_present is True

    # verify individual routes are not being received
    ipv4_route_present = False
    ipv6_route_present = False
    if nei_ipv4_route_1 in nei_show_neigh_v4:
        ipv4_route_present = True
    if nei_ipv6_route_1 in nei_show_neigh_v6:
        ipv6_route_present = True
    if nei_ipv4_route_2 in nei_show_neigh_v4:
        ipv4_route_present = True
    if nei_ipv6_route_2 in nei_show_neigh_v6:
        ipv6_route_present = True
    assert ipv4_route_present is False
    assert ipv6_route_present is False

    # aggregate directly connected routes with as-set
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
        -c "no aggregate-address {} summary-only" -c "aggregate-address {} as-set summary-only" \
        -c "address-family ipv6 unicast" -c "no aggregate-address {} summary-only" \
        -c "aggregate-address {} as-set summary-only"'.format(setup['cli_options'], setup['dut_asn'],
                                                              NEI_IPv4_AGG_ROUTE, NEI_IPv4_AGG_ROUTE,
                                                              NEI_IPv6_AGG_ROUTE, NEI_IPv6_AGG_ROUTE)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh{} -c "clear bgp * soft"'.format(setup['cli_options'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(establish_bgp_session_time)

    logger.info("DUT Config After Aggregation With AS-set: {}".format(setup['duthost'].shell("show run bgp",
                module_ignore_errors=True)['stdout']))

    # verify routes are shared as expected
    cmd = "show ip bgp neighbors {} received-routes".format(setup['dut_ip_v4'])
    nei_show_neigh_v4 = setup['neighhost'].shell(cmd, module_ignore_errors=True)['stdout']
    cmd = "show ipv6 bgp neighbors {} received-routes".format(setup['dut_ip_v6'])
    nei_show_neigh_v6 = setup['neighhost'].shell(cmd, module_ignore_errors=True)['stdout']
    logger.debug("BGP Neighbors IPv4: {}\n\nBGP Neighbors IPv6: {}".format(nei_show_neigh_v4, nei_show_neigh_v6))
    ipv4_agg_route_present = False
    ipv6_agg_route_present = False
    if NEI_IPv4_AGG_ROUTE in nei_show_neigh_v4:
        ipv4_agg_route_present = True
    if NEI_IPv6_AGG_ROUTE in nei_show_neigh_v6:
        ipv6_agg_route_present = True
    assert ipv4_agg_route_present is True
    assert ipv6_agg_route_present is True

    # verify individual routes are not being received
    ipv4_route_present = False
    ipv6_route_present = False
    if nei_ipv4_route_1 in nei_show_neigh_v4:
        ipv4_route_present = True
    if nei_ipv6_route_1 in nei_show_neigh_v6:
        ipv6_route_present = True
    if nei_ipv4_route_2 in nei_show_neigh_v4:
        ipv4_route_present = True
    if nei_ipv6_route_2 in nei_show_neigh_v6:
        ipv6_route_present = True
    assert ipv4_route_present is False
    assert ipv6_route_present is False
