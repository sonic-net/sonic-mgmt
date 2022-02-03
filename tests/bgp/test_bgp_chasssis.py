import logging

import copy
import ipaddress
import pytest
import requests

from natsort import natsorted
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.voq.voq_helpers import get_vm_with_ip
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t2'),
]

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
DUMMY_ASN1 = 64101
IPV4 = 4
IPV6 = 6
IFUP = 1
IFDOWN = 0

def update_route(action, ptfip, port, route, asn=None):
    if action not in ['announce', 'withdraw']:
        logger.error('Unsupported route update operation: %s', action)
        return

    aspath = ''
    if asn and action != 'withdraw':
        aspath = 'as-path [ {} ]'.format(asn)

    msg = '{} route {} next-hop {} {}'.format(action, route['prefix'], route['nexthop'],
                                              aspath)

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg}
    logger.info('Post url=%s, data=%s', url, data)
    request = requests.post(url, data=data)
    assert request.status_code == 200

@pytest.fixture(scope='module')
def build_routes(tbinfo):
    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    prefix_list = ['172.16.10.0/24', '172.16.11.0/24']
    prefix6_list = ['2000:172:16:10::/64', '2000:172:16:11::/64']
    routes = []
    route6s = []
    def add_route(prefix, nexthop, rts):
        route = {}
        route['prefix'] = prefix
        route['nexthop'] = nexthop
        rts.append(route)

    for prefix in prefix_list:
        add_route(prefix, nhipv4, routes)

    for prefix in prefix6_list:
        add_route(prefix, nhipv6, route6s)

    yield (routes, route6s)

class TestBGPChassis(object):

    @pytest.mark.parametrize('ipversions', [[IPV4], [IPV6], [IPV4, IPV6]])
    def test_bgp_chassis(self, duthosts, nbrhosts, ptfhost, tbinfo, build_routes,
                         all_cfg_facts, fanouthosts, ipversions):

        t1_exabgp_ports = {IPV4:{}, IPV6:{}}
        bgp_neighbors = {IPV4:{}, IPV6:{}}

        def build_bgp_info():
            t1_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() \
                                      if neighbor.endswith('T1')])
            for nbr in t1_neighbors:
                nbr_offset = tbinfo['topo']['properties']['topology']['VMs'][nbr]['vm_offset']
                t1_exabgp_ports[IPV4][nbr] = EXABGP_BASE_PORT + nbr_offset
                t1_exabgp_ports[IPV6][nbr] = EXABGP_BASE_PORT_V6 + nbr_offset

            for dut in duthosts:
                if dut.is_supervisor_node():
                    continue
                cfg_facts = all_cfg_facts[dut.hostname][0]['ansible_facts']
                neighbors = cfg_facts['BGP_NEIGHBOR']
                bgp_neighbors[IPV4][dut] = []
                bgp_neighbors[IPV6][dut] = []
                for neigh in neighbors.keys():
                    ipversion = ipaddress.ip_address(neigh).version
                    bgp_neighbors[ipversion][dut].append(neigh)
                pytest_assert(len(bgp_neighbors[IPV4][dut]) >= 2,
                              "Need atleast two v4 neighbors for the test")
                pytest_assert(len(bgp_neighbors[IPV6][dut]) >= 2,
                              "Need atleast two v6 neighbors for the test")

        def verify_nexthops(nexthops, expected_nexhops):
            nexthops.sort()
            expected_nexhops.sort()
            return nexthops == expected_nexhops

        def verify_ip_route(duthost, prefix, expected_nexhops=None):
            ip_route = duthost.get_ip_route(prefix)
            if expected_nexhops is None:
                if ip_route.keys():
                    return True
                return False

            nexthops = []
            for _, routes in ip_route.items():
                for route in routes:
                    for nexthop in route['nexthops']:
                        nexthops.append(nexthop['ip'])

            return verify_nexthops(nexthops, expected_nexhops)

        def verify_bgp_route(duthost, prefix, expected_nexhops=None,
                             nexthops_with_inferior_paths=None):
            route = duthost.get_bgp_route_info(prefix)
            if expected_nexhops is None:
                if route.keys():
                    return True
                return False

            nexthops = []
            inferior_nexthops = []
            if 'paths' not in route:
                return False
            for path in route['paths']:
                if not path['valid'] or 'bestpath' not in path or \
                    'nexthops' not in path:
                    if 'nexthops' in path and path['valid']:
                        for nexthop in path['nexthops']:
                            inferior_nexthops.append(nexthop['ip'])
                    continue
                for nexthop in path['nexthops']:
                    nexthops.append(nexthop['ip'])

            if nexthops_with_inferior_paths:
                return (verify_nexthops(nexthops, expected_nexhops) and
                        verify_nexthops(inferior_nexthops,
                                        nexthops_with_inferior_paths))
            return verify_nexthops(nexthops, expected_nexhops)

        def get_exabpg_port(duthost, ipversion, neigh_index=0):
            neigh_ip_address = bgp_neighbors[ipversion][duthost][neigh_index]
            vminfo = get_vm_with_ip(neigh_ip_address, nbrhosts)
            route = duthost.get_ip_route(neigh_ip_address)
            pytest_assert(len(route) == 1 and len(route.values()) == 1,
                          "Neighbour must be a directly connected neighbour")
            nexthops = route.values()[0][0]['nexthops']
            pytest_assert(len(nexthops) == 1 and nexthops[0]['directlyConnected'],
                          "Neighbour must be directly connected neighbour")
            neigh_intf = nexthops[0]['interfaceName']
            return (t1_exabgp_ports[ipversion][vminfo['vm']], neigh_ip_address, neigh_intf)

        def verify_nexthop_interface(duthost, prefix, internal=False,
                                     expected_external_intfs=None,
                                     num_internal_paths=1):
            ip_route = duthost.get_ip_route(prefix)
            cfg_facts = all_cfg_facts[duthost.hostname][0]['ansible_facts']
            expected_intfs = []
            if expected_external_intfs:
                expected_intfs = copy.deepcopy(expected_external_intfs)
            pytest_assert(len(cfg_facts['VOQ_INBAND_INTERFACE']) == 1,
                          "Only one Inband interface is supported")
            if internal:
                expected_intfs += cfg_facts['VOQ_INBAND_INTERFACE'].keys()
                expected_intfs *= num_internal_paths

            intfs = []
            for _, routes in ip_route.items():
                for route in routes:
                    for nexthop in route['nexthops']:
                        if 'recursive' in nexthop and nexthop['recursive']:
                            continue
                        intfs += [nexthop['interfaceName']]

            intfs.sort()
            expected_intfs.sort()
            pytest_assert(intfs == expected_intfs, "Route is not learned over expected interfaces")

        routes = {}
        routes[IPV4], routes[IPV6] = build_routes

        def update_routes(exabgp_port, routes, asn=None, withdraw=False):
            action = 'withdraw' if withdraw else 'announce'
            for route in routes:
                update_route(action, ptfhost.mgmt_ip, exabgp_port, route, asn)

        def verify_routes(duthost, routes, neigh_ip_addrs, neigh_intfs,
                          nexthops_with_inferior_paths, deleted):
            nexthops = None if deleted else neigh_ip_addrs
            num_internal_paths = 0
            if neigh_intfs:
                num_internal_paths = len(neigh_ip_addrs) - len(neigh_intfs)
            else:
                num_internal_paths = len(neigh_ip_addrs)

            internal = bool(num_internal_paths)
            for route in routes:
                wait_until(30, 2, verify_bgp_route, duthost, route['prefix'], nexthops,
                           nexthops_with_inferior_paths)
                wait_until(30, 2, verify_ip_route, duthost, route['prefix'], nexthops)
                if not deleted:
                    verify_nexthop_interface(duthost, route['prefix'],
                                             expected_external_intfs=neigh_intfs,
                                             internal=internal,
                                             num_internal_paths=num_internal_paths)

        def get_neigh_info(dut, exabgp_ports, neigh_ip_addrs, neigh_intfs_by_dut,
                           ipversion, neigh_index=0):
            exabgp_port, neigh_ip_address, neigh_intf = \
                                           get_exabpg_port(dut, ipversion, neigh_index)
            exabgp_ports.append(exabgp_port)
            neigh_ip_addrs.append(neigh_ip_address)
            if not dut in neigh_intfs_by_dut:
                neigh_intfs_by_dut[dut] = []

            neigh_intfs_by_dut[dut].append(neigh_intf)

        def update_routes_af(duthosts, ipversion, num_nexthops_per_dut, withdraw=False):
            exabgp_ports = []
            neigh_ip_addrs = []
            neigh_intfs_by_dut = {}

            for dut in duthosts:
                num_nexthops = 1
                if num_nexthops_per_dut and dut in num_nexthops_per_dut:
                    num_nexthops = num_nexthops_per_dut[dut]
                for neigh_index in range(num_nexthops):
                    get_neigh_info(dut, exabgp_ports, neigh_ip_addrs,
                                   neigh_intfs_by_dut, ipversion, neigh_index)

            for exabgp_port in exabgp_ports:
                update_routes(exabgp_port, routes[ipversion], withdraw=withdraw)

            return (neigh_ip_addrs, neigh_intfs_by_dut)

        def verify_routes_af(duthosts, allduts, ipversion,
                             neigh_ip_addrs, neigh_intfs_by_dut,
                             deleted=False):
            for dut in duthosts:
                verify_routes(dut, routes[ipversion], neigh_ip_addrs, neigh_intfs_by_dut[dut],
                              nexthops_with_inferior_paths=None,
                              deleted=deleted)

            otherduts = [dut for dut in allduts
                         if dut not in duthosts and not dut.is_supervisor_node()]

            for dut in otherduts:
                intfs = neigh_intfs_by_dut[dut] if dut in neigh_intfs_by_dut else None
                verify_routes(dut, routes[ipversion], neigh_ip_addrs, intfs,
                              nexthops_with_inferior_paths=None,
                              deleted=deleted)

        def update_and_verify_routes_af(duts, allduts, num_nexthops_per_dut,
                                        ipversion, withdraw):
            neigh_ip_addrs, neigh_intfs_by_dut = \
                  update_routes_af(duts, ipversion, num_nexthops_per_dut, withdraw)
            verify_routes_af(duts, allduts, ipversion, neigh_ip_addrs,
                             neigh_intfs_by_dut, deleted=withdraw)
            return (neigh_intfs_by_dut, neigh_ip_addrs)

        def update_and_verify_routes(duts, allduts, num_nexthops_per_dut=None,
                                     skip_v6=False, withdraw=False):
            for ipversion in ipversions:
                if skip_v6 and ipversion == IPV6:
                    continue
                update_and_verify_routes_af(duts, allduts, num_nexthops_per_dut,
                                            ipversion, withdraw)

        def check_intf_status(dut, dut_intf, exp_status):
            status = dut.show_interface(command='status',
                                        interfaces=[dut_intf])['ansible_facts']['int_status']
            logging.info("status: %s", status)
            return status[dut_intf]['oper_state'] == exp_status

        def set_peerintf_state(dut, intf, intfstate):
            cfg_facts = all_cfg_facts[dut.hostname][0]['ansible_facts']
            intflist = []
            if "portchannel" in intf.lower():
                pc_cfg = cfg_facts['PORTCHANNEL_MEMBER']
                pc_members = pc_cfg[intf]
                intflist = pc_members.keys()
            else:
                intflist = [intf]

            for lport in intflist:
                fanout, fanport = fanout_switch_port_lookup(fanouthosts, dut.hostname, lport)
                if intfstate == 'down':
                    fanout.shutdown(fanport)
                else:
                    fanout.no_shutdown(fanport)

                pytest_assert(wait_until(90, 1, check_intf_status, dut, intf, intfstate),
                              "dut port {} didn't change state to {} as " \
                              "expected".format(intf, intfstate))

        def verify_bgp_inferior_path_propagation(dut, duthosts):
            def verify_bgp_inferior_path_propagation_af(ipversion):
                exabgp_ports = []
                neigh_ip_addrs = []
                neigh_intfs_by_dut = {}
                num_paths = 2
                for neigh_index in range(num_paths):
                    get_neigh_info(dut, exabgp_ports, neigh_ip_addrs,
                                   neigh_intfs_by_dut, ipversion, neigh_index)
                # Adverties two path, one inferior to the other. Verify both paths
                # are propagated and the bext path is chosen.
                bestpath_index = 0
                inferior_path_index = 1
                inferior_paths_nexthops = [neigh_ip_addrs[inferior_path_index]]
                update_routes(exabgp_ports[bestpath_index], routes[ipversion])
                update_routes(exabgp_ports[inferior_path_index], routes[ipversion],
                              asn=str(DUMMY_ASN1))
                otherduts = [d for d in duthosts if d != dut and not d.is_supervisor_node()]
                verify_routes(dut, routes[ipversion], [neigh_ip_addrs[bestpath_index]],
                              [neigh_intfs_by_dut[dut][bestpath_index]],
                              nexthops_with_inferior_paths=inferior_paths_nexthops,
                              deleted=False)
                for otherdut in otherduts:
                    verify_routes(otherdut, routes[ipversion], [neigh_ip_addrs[bestpath_index]], [],
                                  nexthops_with_inferior_paths=inferior_paths_nexthops,
                                  deleted=False)

                # Withdraw the bestpath and verify the alternate inferior path is chosen.
                update_routes(exabgp_ports[bestpath_index], routes[ipversion], withdraw=True)
                verify_routes(dut, routes[ipversion], inferior_paths_nexthops,
                              [neigh_intfs_by_dut[dut][inferior_path_index]],
                              nexthops_with_inferior_paths=None,
                              deleted=False)
                for otherdut in otherduts:
                    verify_routes(otherdut, routes[ipversion], inferior_paths_nexthops, [],
                                  nexthops_with_inferior_paths=None,
                                  deleted=False)

                # Withdraw the alternate path and verify the route is fully withdrawn from all
                # the linecards.
                update_routes(exabgp_ports[inferior_path_index], routes[ipversion], withdraw=True)
                verify_routes(dut, routes[ipversion], [], [], nexthops_with_inferior_paths=None,
                              deleted=True)
                for duthost in duthosts:
                    if duthost.is_supervisor_node():
                        continue
                    verify_routes(duthost, routes[ipversion], [], [],
                                  nexthops_with_inferior_paths=None, deleted=True)

            for ipversion in ipversions:
                verify_bgp_inferior_path_propagation_af(ipversion)

        def test_bgp_convergence_on_linkflap(dut, allduts):
            neigh_intfs_by_dut = {IPV4:{}, IPV6:{}}
            neigh_ip_addrs = {IPV4:{}, IPV6:{}}
            def set_neigh_intfs_state(ifstate):
                for ipversion in ipversions:
                    for intf in neigh_intfs_by_dut[ipversion][dut]:
                        set_peerintf_state(dut, intf, ifstate)

            def verify_all_routes(deleted=False):
                for ipversion in ipversions:
                    verify_routes_af([dut], allduts, ipversion, neigh_ip_addrs[ipversion],
                                     neigh_intfs_by_dut[ipversion], deleted=deleted)

            for ipversion in ipversions:
                neigh_intfs_by_dut[ipversion], neigh_ip_addrs[ipversion] = \
                      update_and_verify_routes_af([dut], allduts, None, ipversion, False)

            set_neigh_intfs_state('down')
            verify_all_routes(deleted=True)
            set_neigh_intfs_state('up')
            verify_all_routes(deleted=False)

        build_bgp_info()

        def clear_all_routes():
            for ipversion in [IPV4, IPV6]:
                for _, exabgp_port in t1_exabgp_ports[ipversion].items():
                    for route in routes[ipversion]:
                        update_route('withdraw', ptfhost.mgmt_ip, exabgp_port, route)

        clear_all_routes()
        t1_linecards = [duthosts[1], duthosts[2]]

        # Publish routes to one t1_linecard and verify all the linecards learns the route.
        update_and_verify_routes(t1_linecards[0:1], duthosts)

        # Withdram the route from the t1_linecard and verify the route is withdrawn from
        # all the linecards.
        update_and_verify_routes(t1_linecards[0:1], duthosts, withdraw=True)

        # Publish routes to both the  t1_linecards and verify all the linecards learns the route.
        # The t1 linecards will have a ecmp one with one path through the inband port and other
        # through the front panl ports.
        update_and_verify_routes(t1_linecards, duthosts, skip_v6=True)

        # Withdram the route from both the t1_linecard and verify the route is withdrawn from
        # all the linecards.
        update_and_verify_routes(t1_linecards, duthosts, skip_v6=True,
                                 withdraw=True)

        # Pick a t1 line card and advertise a route from two neighbors. Verify that the route
        # is learnt from both the neighbors on the seclected t1 linecard. Also verify the
        # other linecards learn thr route from both the neighbors over the inband port.
        duts = t1_linecards[0:1]
        num_nexthops_per_dut = {t1_linecards[0]:2}
        update_and_verify_routes(duts, duthosts, num_nexthops_per_dut)

        # Withdram the route from the t1_linecard from both the neighbors and verify the route
        # is withdrawn from all the linecards.
        update_and_verify_routes(duts, duthosts, num_nexthops_per_dut, withdraw=True)

        # Verify non equal cost BGP paths are propagated to all linecards and all the linecards
        # converge on the best BGP path and install the route that provides the best BGP path.
        verify_bgp_inferior_path_propagation(t1_linecards[0], duthosts)

        # Verify eBGP session is reestablished and routes relearnt on a link flap.
        test_bgp_convergence_on_linkflap(duthosts[1], duthosts)

        # cleanup the routes.
        clear_all_routes()
