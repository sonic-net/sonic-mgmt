"""Regressions for converged cSONiC T1-LAG BGP compatibility."""

import json

from tests.bgp import bgp_helpers
from tests.bgp import route_checker
from tests.bgp.test_bgp_gr_helper import get_csonic_prime_peer_names
from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost


def _tbinfo():
    return {
        'topo': {
            'properties': {
                'configuration_properties': {
                    'common': {
                        'nhipv4': '10.10.246.254',
                        'nhipv6': 'fc0a::ff',
                    },
                },
            },
        },
    }


def _logical_neighbor(host):
    return {
        'host': host,
        'is_multi_vrf_peer': True,
        'multi_vrf_data': {
            'vrf': 'VrfARISTA01T0',
            'ptf_bp_config': {
                'ipv4': '10.10.246.117/31',
                'ipv6': 'fc0a::75/127',
            },
        },
    }


def test_csonic_direct_client_next_hops_stay_paired_with_logical_peer():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')

    assert bgp_helpers.get_neighbor_exabgp_nexthops(
        _tbinfo(), _logical_neighbor(host)) == (
            '10.10.246.117', 'fc0a::75')
    assert bgp_helpers.get_neighbor_exabgp_nexthops(
        _tbinfo(), {'host': host}) == ('10.10.246.254', 'fc0a::ff')


def test_csonic_route_details_use_runtime_vrf_and_direct_frr_shape():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    observed = {}

    def get_route(prefix, vrf=None):
        observed.update(prefix=prefix, vrf=vrf)
        return {
            'paths': [{
                'aspath': {'string': '65100 64001'},
                'community': {'string': '1010:1010 1234:5678'},
            }],
        }

    host.get_route = get_route
    details = bgp_helpers.get_neighbor_route_details(
        _logical_neighbor(host), '172.16.10.0/24')

    assert observed == {
        'prefix': '172.16.10.0/24',
        'vrf': 'VrfARISTA01T0',
    }
    assert details == {
        'present': True,
        'aspath': '65100 64001',
        'communities': {'1010:1010', '1234:5678'},
    }


def test_eos_and_sonic_route_shapes_remain_supported():
    eos = object.__new__(EosHost)
    eos_calls = []

    def eos_get_route(prefix, **kwargs):
        eos_calls.append(kwargs)
        vrf = kwargs.get('vrf', 'default')
        return {
            'vrfs': {
                vrf: {
                    'bgpRouteEntries': {
                        prefix: {
                            'bgpRoutePaths': [{
                                'asPathEntry': {'asPath': '65100 64001'},
                                'routeDetail': {
                                    'communityList': ['1010:1010'],
                                },
                            }],
                        },
                    },
                },
            },
        }

    eos.get_route = eos_get_route
    eos_neighbor = {
        'host': eos,
        'is_multi_vrf_peer': True,
        'multi_vrf_data': {'vrf': 'ARISTA01T0'},
    }
    assert bgp_helpers.get_neighbor_route_details(
        eos_neighbor, '172.16.10.0/24') == {
            'present': True,
            'aspath': '65100 64001',
            'communities': {'1010:1010'},
        }
    assert eos_calls == [{'vrf': 'ARISTA01T0'}]
    eos_calls.clear()
    assert bgp_helpers.get_neighbor_route_details(
        {'host': eos}, '172.16.10.0/24')['present']
    assert eos_calls == [{}]
    assert bgp_helpers.get_neighbor_exabgp_nexthops(
        _tbinfo(), eos_neighbor) == ('10.10.246.254', 'fc0a::ff')

    sonic = object.__new__(SonicHost)
    sonic.get_route = lambda prefix: {
        'paths': [{'aspath': {'string': '65100 64001'}}],
    }
    assert bgp_helpers.get_neighbor_route_details(
        {'host': sonic}, '172.16.10.0/24')['aspath'] == '65100 64001'


def test_csonic_received_routes_are_configured_and_read_in_runtime_vrf():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        if 'received-routes json' in command:
            return {
                'rc': 0,
                'stdout': json.dumps({
                    'receivedRoutes': {
                        '172.16.10.0/24': {},
                        '172.16.30.0/24': {},
                    },
                }),
            }
        return {'rc': 0, 'stdout': ''}

    host._docker_exec = docker_exec
    routes = route_checker._parse_routes_on_csonic_host(
        host, 64001, '10.0.0.32', 4)

    assert routes == {
        '172.16.10.0/24': '',
        '172.16.30.0/24': '',
    }
    assert any(
        "router bgp 64001 vrf VrfARISTA01T0" in command
        and "address-family ipv4 unicast" in command
        for command in commands
    )
    assert any(
        'show bgp vrf VrfARISTA01T0 neighbors 10.0.0.32 '
        'received-routes json' in command
        for command in commands
    )


def test_gr_helper_reports_every_logical_peer_on_shared_csonic_prime():
    peer1 = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    peer2 = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA03T2')
    other = CsonicHost('csonic-other', bgp_vrf='VrfARISTA01T0')
    nbrhosts = {
        'ARISTA01T2': {'host': peer1},
        'ARISTA03T2': {'host': peer2},
        'ARISTA01T0': {'host': other},
    }

    assert get_csonic_prime_peer_names(nbrhosts, 'ARISTA01T2') == [
        'ARISTA01T2',
        'ARISTA03T2',
    ]
