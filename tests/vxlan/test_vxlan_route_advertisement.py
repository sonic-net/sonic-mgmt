#! /usr/bin/env python3
'''
    These tests check the Vxlan ecmp Route advertisement. Further details are
    provided with each test.
'''

from collections.abc import Mapping
import json
import logging
import re
import time

import pytest
from tests.common.devices.csonic import CsonicHost
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until
from tests.common.vxlan_ecmp_utils import Ecmp_Utils

Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()
WAIT_TIME = 2
WAIT_TIME_EXTRA = 5
ROUTE_CONVERGENCE_TIMEOUT = 30
ROUTE_CONVERGENCE_INTERVAL = 2

# This is the list of encapsulations that will be tested in this script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v6_in_v4']
DESTINATION_PREFIX = 150
NEXTHOP_PREFIX = 100
pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-56-lag, t1-lag.
    pytest.mark.topology("t1")
]


def _is_logical_converged_csonic(host):
    """Return whether route reads must use a logical cSONiC runtime VRF."""
    return isinstance(host, CsonicHost) and bool(host.bgp_vrf)


def _command_stdout(result):
    """Return stdout, or None for a failed/invalid command result."""
    if not isinstance(result, Mapping):
        return None
    if result.get('failed', False) or result.get('rc', 0) != 0:
        return None
    stdout = result.get('stdout', '')
    if isinstance(stdout, list):
        return stdout[0] if stdout else ''
    return stdout if isinstance(stdout, str) else None


def _route_prefixes_from_output(output):
    """Extract exact IPv4/IPv6 CIDR tokens from a text BGP table."""
    return set(re.findall(
        r'(?<![0-9a-fA-F:.])[0-9a-fA-F:.]+/\d+(?![0-9a-fA-F:.])',
        output or '',
    ))


def _scale_route_command(host, prefix_type, community=''):
    """Build the FRR table read used only by logical cSONiC peers."""
    command = 'show {} bgp '.format('ip' if prefix_type == 'v4' else 'ipv6')
    if community:
        command += 'community ' + community
    return command


def _route_present_in_data(route_data, prefix):
    """Require direct FRR route JSON to identify the requested prefix."""
    if not isinstance(route_data, dict):
        return False
    returned_prefix = route_data.get('prefix')
    if returned_prefix is not None and returned_prefix != prefix:
        return False
    return returned_prefix == prefix and bool(route_data.get('paths'))


def _neighbor_route_data(host, route):
    """Read one logical cSONiC route and fail closed on query errors."""
    if not _is_logical_converged_csonic(host):
        return host.get_route(route)

    afi = 'ipv6' if ':' in route else 'ip'
    result = host.command(
        'show {} bgp {} json'.format(afi, route),
        module_ignore_errors=True,
    )
    output = _command_stdout(result)
    if output is None:
        raise RuntimeError('Neighbor route-table query failed')
    if not output.strip():
        raise RuntimeError('Neighbor route-table query returned no output')
    try:
        route_data = json.loads(output)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(
            'Neighbor route-table query returned invalid JSON') from error
    if not isinstance(route_data, dict):
        raise ValueError('Neighbor route-table query did not return an object')
    return route_data


def _community_tokens(value):
    """Return exact standard/large BGP community tokens from route JSON."""
    tokens = set()
    if isinstance(value, Mapping):
        for nested in value.values():
            tokens.update(_community_tokens(nested))
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            tokens.update(_community_tokens(nested))
    elif isinstance(value, str):
        for token in re.split(r'[\s,]+', value):
            token = token.strip("[]{}()'\"")
            if re.fullmatch(r'\d+:\d+(?::\d+)?', token):
                tokens.add(token)
    return tokens


def _neighbor_route_matches(host, route, expected_present, community=''):
    """Return whether a logical cSONiC route reached the expected state."""
    try:
        result = _neighbor_route_data(host, route)
    except Exception as error:
        Logger.debug('Failed to query route %s on %s: %s', route, host, error)
        return False
    present = _route_present_in_data(result, route)
    if present != expected_present:
        return False
    if not community:
        return True
    community_present = community in _community_tokens(result)
    return community_present if expected_present else not community_present


def _csonic_scale_routes_match(host, command, expected_routes, present):
    """Check one complete logical cSONiC scale-table snapshot."""
    output = _command_stdout(host.run_command(command))
    if output is None:
        return False
    observed_routes = _route_prefixes_from_output(output)
    expected_routes = set(expected_routes)
    if present:
        return expected_routes <= observed_routes
    return expected_routes.isdisjoint(observed_routes)


@pytest.fixture(
    name="encap_type",
    scope="module",
    params=SUPPORTED_ENCAP_TYPES)
def fixture_encap_type(request):
    '''
        This fixture forces the script to perform one encap_type at a time.
        So this script doesn't support multiple encap types at the same.
    '''
    return request.param


@pytest.fixture(autouse=True)
def _ignore_route_sync_errlogs(duthosts, rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        IgnoreRegex = [
            ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
            ".*missed_in_asic_db_routes.*",
            ".*Look at reported mismatches above.*",
            ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
            ".*'vnetRouteCheck' status failed.*",
            ".*Vnet Route Mismatch reported.*",
            ".*_M_construct null not valid.*",
        ]
        # Ignore in KVM test
        KVMIgnoreRegex = [
            ".*doTask: Logic error: basic_string: construction from null is not valid.*",
        ]
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(IgnoreRegex)
        if duthost.facts["asic_type"] == "vs":
            loganalyzer[rand_one_dut_hostname].ignore_regex.extend(KVMIgnoreRegex)
    return


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(duthosts,
                  request,
                  rand_one_dut_hostname,
                  minigraph_facts,
                  tbinfo,
                  nbrhosts,
                  encap_type):
    '''
        Setup for the entire script.
        The basic steps in VxLAN configs are:
            1. Configure VxLAN tunnel.
            2. Configure Vnet and its VNI.

            The testcases are focused on the "configure routes" step. They add,
            delete, modify, the routes while testing the advertisement.
    '''
    data = {}
    nbrnames = list(nbrhosts.keys())
    data['t2'] = []
    for name in nbrnames:
        if 'T2' in name:
            data['t2'].append(nbrhosts[name])

    asic_type = duthosts[rand_one_dut_hostname].facts["asic_type"]
    if asic_type not in ["cisco-8000", "mellanox", "marvell-teralynx", "vs", "vpp"]:
        pytest.skip(f"{asic_type} is not a supported platform for this test. \
                Only support MNLX, CISCO and marvell-teralynx platforms.")

    # Should I keep the temporary files copied to DUT?
    ecmp_utils.Constants['KEEP_TEMP_FILES'] = \
        request.config.option.keep_temp_files

    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    ecmp_utils.Constants['DEBUG'] = request.config.option.debug_enabled

    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    ecmp_utils.Constants['DUT_HOSTID'] = request.config.option.dut_hostid

    Logger.info("Constants to be used in the script:%s", ecmp_utils.Constants)

    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = \
        data['duthost'].get_extended_minigraph_facts(tbinfo)
    data['dut_mac'] = data['duthost'].facts['router_mac']
    time.sleep(WAIT_TIME)

    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=4789,
        dutmac=data['dut_mac'])
    data['active_routes'] = {}

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    encap_type_data = {}
    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}
    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    try:
        tunnel_names[outer_layer_version]
    except KeyError:
        tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(
            data['duthost'],
            minigraph_data=minigraph_facts,
            af=outer_layer_version,
            ttl_mode="pipe" if data['duthost'].facts.get("asic_type") == "cisco-8000" else None)

    payload_version = ecmp_utils.get_payload_version(encap_type)
    encap_type = "{}_in_{}".format(payload_version, outer_layer_version)

    try:
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
    except KeyError:
        vnet_af_map[outer_layer_version] = ecmp_utils.create_vnets(
            data['duthost'],
            tunnel_name=tunnel_names[outer_layer_version],
            vnet_count=1,     # default scope can take only one vnet.
            vnet_name_prefix="Vnet_" + encap_type,
            scope="default",
            vni_base=10000,
            advertise_prefix='true')
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
    data[encap_type] = encap_type_data

    yield data

    # Cleanup code.
    if encap_type == 'v4_in_v4':
        prefix_mask = 24
        prefix_type = 'v4'
    else:
        prefix_mask = 64
        prefix_type = 'v6'
    if 'active_routes' in data:
        ecmp_utils.set_routes_in_dut(data['duthost'],
                                     data['active_routes'],
                                     prefix_type,
                                     'DEL',
                                     bfd=False,
                                     mask=prefix_mask)

    # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
    # There will be same vnet in multiple encap types.
    # So remove vnets *after* removing the routes first.
    for vnet in list(data[encap_type]['vnet_vni_map'].keys()):
        data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    time.sleep(5)
    for tunnel in list(tunnel_names.values()):
        data['duthost'].shell(
            "redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))
    time.sleep(1)


class Test_VxLAN_route_Advertisement():

    '''
        Class for all the Vxlan tunnel cases where primary and secondary next hops are configured.
    '''
    def create_bgp_profile(self, name, community):
        # sonic-db-cli APPL_DB HSET "BGP_PROFILE_TABLE:FROM_SDN_SLB_ROUTES" "community_id" "1234:1235"
        self.duthost.shell("sonic-db-cli APPL_DB HSET 'BGP_PROFILE_TABLE:{}' 'community_id' '{}'"
                           .format(name, community))

    def remove_bgp_profile(self, name):
        # sonic-db-cli APPL_DB DEL "BGP_PROFILE_TABLE:FROM_SDN_SLB_ROUTES"
        self.duthost.shell("sonic-db-cli APPL_DB DEL 'BGP_PROFILE_TABLE:{}' "
                           .format(name))

    def gnenrate_vnet_routes(self, encap_type, num_routes):
        # We are not aiming to test the vnet route functionality so we shall stick to 4 nexthops for all prefixes.
        nexthops = ['202.1.1.1', '202.1.1.2', '202.1.1.3', '202.1.1.4']
        if num_routes > 4000:
            py_assert("Routes more than 4000 are not suppored.")
        routes = {}
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        routes[vnet] = {}
        count = 0
        if self.prefix_type == 'v4':
            for i in range(1, 250):
                for j in range(2, 250):
                    key = f"99.{i}.{j}.0"
                    routes[vnet][key] = nexthops.copy()
                    count = count + 1
                    if count >= num_routes:
                        return routes
        else:
            for i in range(1, 250):
                for j in range(2, 250):
                    key = f"dc4a:{i}:{j}::"
                    routes[vnet][key] = nexthops.copy()
                    count = count + 1
                    if count >= num_routes:
                        return routes

        return routes

    def add_unmonitored_vnet_route(self, routes, profile):
        if self.prefix_type == 'v4':
            prefix_mask = 24
        else:
            prefix_mask = 64
        self.vxlan_test_setup['active_routes'] = routes.copy()
        ecmp_utils.set_routes_in_dut(self.duthost,
                                     routes,
                                     self.prefix_type,
                                     'SET',
                                     bfd=False,
                                     mask=prefix_mask,
                                     profile=profile)

    def remove_unmonitored_vnet_route(self, routes):
        if self.prefix_type == 'v4':
            prefix_mask = 24
        else:
            prefix_mask = 64
        del self.vxlan_test_setup['active_routes']
        ecmp_utils.set_routes_in_dut(self.duthost,
                                     routes,
                                     self.prefix_type,
                                     'DEL',
                                     bfd=False,
                                     mask=prefix_mask)

    def verify_nighbor_has_routes(self, routes, community=""):
        if self.prefix_type == 'v4':
            prefix_mask = 24
        else:
            prefix_mask = 64
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{prefix}/{prefix_mask}'
                for t2device in self.vxlan_test_setup['t2']:
                    host = t2device['host']
                    if _is_logical_converged_csonic(host):
                        py_assert(wait_until(
                            ROUTE_CONVERGENCE_TIMEOUT,
                            ROUTE_CONVERGENCE_INTERVAL, 0,
                            _neighbor_route_matches, host, route, True,
                            community),
                            "Route {} with community {} did not propagate to T2 {}"
                            .format(route, community or '<any>', host))
                    else:
                        result = host.get_route(route)
                        py_assert(route in result['vrfs']['default']['bgpRouteEntries'],
                                  "Route not propogated to the T2")
                        if community != "":
                            py_assert(community in str(result), "community not propogated.")
        return

    def verify_nighbor_doesnt_have_routes(self, routes, community=""):
        if self.prefix_type == 'v4':
            prefix_mask = 24
        else:
            prefix_mask = 64
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{prefix}/{prefix_mask}'
                for t2device in self.vxlan_test_setup['t2']:
                    host = t2device['host']
                    if _is_logical_converged_csonic(host):
                        py_assert(wait_until(
                            ROUTE_CONVERGENCE_TIMEOUT,
                            ROUTE_CONVERGENCE_INTERVAL, 0,
                            _neighbor_route_matches, host, route, False,
                            community),
                            "Route {} or community {} is still propagated to T2 {}"
                            .format(route, community or '<any>', host))
                    else:
                        result = host.get_route(route)
                        py_assert(route not in result['vrfs']['default']['bgpRouteEntries'],
                                  "Route not propogated to the T2")
                        if community != "":
                            py_assert(community not in str(result), "community is still getting propogated.")
        return

    def verify_nighbor_has_routes_scale(self, routes, community=""):
        if self.prefix_type == 'v4':
            prefix_mask = 24
            cmd = "show ip bgp "
            cmty = "community " + community if community != "" else ""
            grepdata = " | grep ' 99.'"
        else:
            prefix_mask = 64
            cmd = "show ipv6 bgp "
            cmty = "match community " + community if community != "" else ""
            grepdata = " | grep ' dc4a:'"
        cmd = cmd + cmty + grepdata

        retry_count = 4
        for t2device in self.vxlan_test_setup['t2']:
            host = t2device['host']
            if _is_logical_converged_csonic(host):
                expected_routes = [
                    f'{prefix}/{prefix_mask}'
                    for vnet in routes
                    for prefix in routes[vnet]
                ]
                csonic_cmd = _scale_route_command(
                    host, self.prefix_type, community)
                py_assert(wait_until(
                    40, 10, 0, _csonic_scale_routes_match,
                    host, csonic_cmd, expected_routes, True),
                    "Routes with community {} did not propagate to T2 {}"
                    .format(community or '<any>', host))
                continue

            result = host.run_command(cmd)
            while len(result['stdout'][0]) == 0 and retry_count > 0:
                time.sleep(10)
                result = host.run_command(cmd)
                retry_count = retry_count - 1
            if len(result['stdout'][0]) == 0:
                py_assert(False, "Routes not propogated to the T2.")

            for vnet in routes:
                for prefix in routes[vnet]:
                    route = f'{prefix}/{prefix_mask}'
                    if route not in result['stdout'][0]:
                        py_assert(False, "Route not propogated to the T2.{route} with community{community} not found.")
        return

    def verify_nighbor_doesnt_have_routes_scale(self, routes, community=""):
        if self.prefix_type == 'v4':
            prefix_mask = 24
            cmd = "show ip bgp "
            grepdata = " | grep ' 99.'"
        else:
            prefix_mask = 64
            cmd = "show ipv6 bgp "
            grepdata = " | grep ' dc4a:'"
        if community != "":
            cmd = cmd + "community " + community
        cmd = cmd + grepdata
        for t2device in self.vxlan_test_setup['t2']:
            host = t2device['host']
            if _is_logical_converged_csonic(host):
                expected_routes = [
                    f'{prefix}/{prefix_mask}'
                    for vnet in routes
                    for prefix in routes[vnet]
                ]
                csonic_cmd = _scale_route_command(
                    host, self.prefix_type, community)
                py_assert(wait_until(
                    ROUTE_CONVERGENCE_TIMEOUT,
                    ROUTE_CONVERGENCE_INTERVAL, 0,
                    _csonic_scale_routes_match,
                    host, csonic_cmd, expected_routes, False),
                    "Routes are still propagated to T2 {}".format(host))
                continue

            result = host.run_command(cmd)
            for vnet in routes:
                for prefix in routes[vnet]:
                    route = f'{prefix}/{prefix_mask}'
                    if route in result['stdout'][0]:
                        py_assert(False, "Route ot propogated to the T2 which is unexpected.")

        return

    def test_basic_route_advertisement(self, setUp, encap_type, duthost):  # noqa: F811
        '''
        Create a tunnel route and advertise the tunnel route to all neighbor without community id
        Result: All BGP neighbors can recieve the advertised BGP routes
        '''
        self.vxlan_test_setup = setUp
        self.duthost = duthost
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
        else:
            self.prefix_type = 'v6'
        routes = self.gnenrate_vnet_routes(encap_type, 1)
        self.add_unmonitored_vnet_route(routes, "")
        time.sleep(WAIT_TIME)
        self.verify_nighbor_has_routes(routes, "")
        self.remove_unmonitored_vnet_route(routes)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, "")
        return

    def test_basic_route_advertisement_with_community(self, setUp, encap_type, duthost):  # noqa: F811
        '''
        Create a tunnel route and advertise the tunnel route to all neighbor with community id.
        Result: All BGP neighbors can recieve the advertised BGP routes with community id
        '''
        self.vxlan_test_setup = setUp
        self.duthost = duthost
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
        else:
            self.prefix_type = 'v6'

        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "1234:4321")
        routes = self.gnenrate_vnet_routes(encap_type, 1)
        self.add_unmonitored_vnet_route(routes, "FROM_SDN_SLB_ROUTES")
        time.sleep(WAIT_TIME)
        self.verify_nighbor_has_routes(routes, "1234:4321")
        self.remove_unmonitored_vnet_route(routes)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, "1234:4321")
        self.remove_bgp_profile("FROM_SDN_SLB_ROUTES")
        return

    def test_basic_route_advertisement_with_community_change(self, setUp, encap_type, duthost):  # noqa: F811
        '''
        Update a tunnel route and advertise the tunnel route to all neighbor with new community id.
        Result:	All BGP neighbors can recieve the advertised BGP routes with new community id
        '''
        self.vxlan_test_setup = setUp
        self.duthost = duthost
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
        else:
            self.prefix_type = 'v6'
        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "1234:4321")
        routes = self.gnenrate_vnet_routes(encap_type, 1)
        self.add_unmonitored_vnet_route(routes, "FROM_SDN_SLB_ROUTES")
        time.sleep(WAIT_TIME)
        self.verify_nighbor_has_routes(routes, "1234:4321")
        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "9999:8888")
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_nighbor_has_routes(routes, "9999:8888")
        self.remove_unmonitored_vnet_route(routes)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, "9999:8888")
        self.remove_bgp_profile("FROM_SDN_SLB_ROUTES")
        return

    def test_route_advertisement_without_and_with_community(self, setUp, encap_type, duthost):  # noqa: F811
        '''
        Create a tunnel route and advertise the tunnel route to all neighbor with BGP profile,
        but create the profile later
        Result: All BGP neighbors can recieve the advertised BGP routes without community id first,
        after the profile table created, the community id would be added and all BGP neighbors can
        recieve this update and associate the community id with the route
        '''
        self.vxlan_test_setup = setUp
        self.duthost = duthost
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
        else:
            self.prefix_type = 'v6'
        routes = self.gnenrate_vnet_routes(encap_type, 1)
        self.add_unmonitored_vnet_route(routes, "FROM_SDN_SLB_ROUTES")
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, "")
        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "9999:8888")
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_nighbor_has_routes(routes, "9999:8888")
        self.remove_unmonitored_vnet_route(routes)
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_nighbor_doesnt_have_routes(routes, "9999:8888")
        self.remove_bgp_profile("FROM_SDN_SLB_ROUTES")
        return

    def test_scale_route_advertisement_with_community(self, setUp, encap_type, duthost):  # noqa: F811
        '''
        Create 4k tunnel routes and advertise all tunnel routes to all neighbor with community id.
        Result: All BGP neighbors can recieve 4k advertised BGP routes with community id and record the time.
        2nd part:
        Update BGP_PROFILE_TABLE with new community id for 4k tunnel routes and advertise all tunnel routes.
        Result:	All BGP neighbors can recieve 4k advertised BGP routes with new community id and record the time
        '''
        self.vxlan_test_setup = setUp
        self.duthost = duthost
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
        else:
            self.prefix_type = 'v6'

        # Part 1
        routes = self.gnenrate_vnet_routes(encap_type, 4000)
        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "9999:8888")
        self.add_unmonitored_vnet_route(routes, "FROM_SDN_SLB_ROUTES")
        self.verify_nighbor_has_routes_scale(routes, "9999:8888")

        # Part 2
        self.create_bgp_profile("FROM_SDN_SLB_ROUTES", "1234:4321")
        time.sleep(WAIT_TIME_EXTRA*20)
        self.verify_nighbor_has_routes_scale(routes, "1234:4321")
        self.remove_unmonitored_vnet_route(routes)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes_scale(routes, "")

        self.remove_bgp_profile("FROM_SDN_SLB_ROUTES")
        return
