"""Regressions for converged cSONiC T1-LAG BGP compatibility."""

import json

import pytest

from tests.bgp import bgp_helpers
from tests.bgp import route_checker
from tests.bgp.test_bgp_gr_helper import get_csonic_prime_peer_names
from tests.bgp.test_bgp_gr_helper import get_shared_prime_preserved_prefix_counters
from tests.bgp.test_bgp_gr_helper import shared_prime_prefix_counter_snapshots_match
from tests.bgp.test_bgp_gr_helper import shared_prime_prefix_counters_preserved
from tests.bgp.test_bgp_gr_helper import verify_shared_prime_routes_during_graceful_restart
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


@pytest.mark.parametrize("ip_ver, peer, expected_command", [
    (
        4,
        '10.0.0.32',
        'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast '
        'neighbors 10.0.0.32 routes"',
    ),
    (
        6,
        'fc00::41',
        'vtysh -c "show bgp vrf VrfARISTA01T0 ipv6 unicast '
        'neighbors fc00::41 routes"',
    ),
])
def test_csonic_suppress_fib_route_propagation_uses_runtime_vrf(
    ip_ver, peer, expected_command,
):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {'rc': 0, 'stdout': '91.0.1.0/24'}

    host._docker_exec = docker_exec
    assert bgp_helpers.check_propagate_route(
        _logical_neighbor(host), ['91.0.1.0/24'], peer, ip_ver=ip_ver)
    assert commands == [expected_command]


def test_converged_ptf_receive_ports_use_logical_minigraph_neighbors():
    class DutHost:
        def shell(self, command):
            raise AssertionError("LLDP lookup must not run for converged peers")

        def get_extended_minigraph_facts(self, tbinfo):
            return {
                'minigraph_neighbors': {
                    'Ethernet56': {'name': 'ARISTA15T2'},
                    'Ethernet60': {'name': 'ARISTA15T2'},
                    'Ethernet116': {'name': 'ARISTA14T0'},
                },
                'minigraph_ptf_indices': {
                    'Ethernet56': 14,
                    'Ethernet60': 15,
                    'Ethernet116': 29,
                },
            }

    assert bgp_helpers.get_ptf_recv_port(
        DutHost(), 'ARISTA14T0', {}, multi_vrf_topo=True) == [29]
    assert bgp_helpers.get_ptf_recv_port(
        DutHost(), 'ARISTA15T2', {}, multi_vrf_topo=True) == [14, 15]


def test_ordinary_ptf_receive_ports_keep_lldp_lookup():
    class DutHost:
        def __init__(self):
            self.commands = []

        def shell(self, command):
            self.commands.append(command)
            return {'stdout': 'Ethernet116\n'}

        def get_extended_minigraph_facts(self, tbinfo):
            return {'minigraph_ptf_indices': {'Ethernet116': 29}}

    duthost = DutHost()
    assert bgp_helpers.get_ptf_recv_port(
        duthost, 'ARISTA14T0', {}, multi_vrf_topo=False) == [29]
    assert duthost.commands == [
        "show lldp table | grep -w ARISTA14T0 | awk '{print $1}'",
    ]


def test_suppress_fib_eos_and_sonic_commands_remain_unchanged():
    eos = object.__new__(EosHost)
    eos_commands = []

    def eos_command(commands):
        eos_commands.extend(commands)
        return {'stdout': ['91.0.1.0/24']}

    eos.eos_command = eos_command
    assert bgp_helpers.check_propagate_route(
        {'host': eos}, ['91.0.1.0/24'], '10.0.0.0')
    assert eos_commands == [
        'show ip bgp neighbors 10.0.0.0 routes vrf default',
    ]

    sonic = object.__new__(SonicHost)
    sonic_commands = []

    def sonic_shell(command, **kwargs):
        sonic_commands.append((command, kwargs))
        return {'stdout': '91.0.1.0/24'}

    sonic.shell = sonic_shell
    assert bgp_helpers.check_propagate_route(
        {'host': sonic}, ['91.0.1.0/24'], '10.0.0.0')
    assert sonic_commands == [(
        'show ip bgp vrf default neighbor 10.0.0.0 routes',
        {'module_ignore_errors': True},
    )]


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


def test_converged_csonic_route_families_are_read_without_runtime_mutation():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        if 'routes json' in command:
            return {
                'rc': 0,
                'stdout': json.dumps({
                    'routes': {
                        '172.16.10.0/24': {},
                        '172.16.30.0/24': {},
                    },
                }),
            }
        return {'rc': 0, 'stdout': ''}

    host._docker_exec = docker_exec
    routes_v4 = route_checker._parse_routes_on_csonic_host(
        host, 64001, '10.0.0.32', 4)
    routes_v6 = route_checker._parse_routes_on_csonic_host(
        host, 64001, 'fc00::41', 6)

    assert routes_v4 == {
        '172.16.10.0/24': '',
        '172.16.30.0/24': '',
    }
    assert routes_v6 == routes_v4
    assert commands == [
        ' '.join((
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast',
            'neighbors 10.0.0.32 routes json"',
        )),
        ' '.join((
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv6 unicast',
            'neighbors fc00::41 routes json"',
        )),
    ]


def test_ordinary_csonic_received_routes_keep_historical_commands():
    host = CsonicHost('csonic-neighbor')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        if 'received-routes json' in command:
            return {
                'rc': 0,
                'stdout': json.dumps({
                    'receivedRoutes': {'172.16.10.0/24': {}},
                }),
            }
        return {'rc': 0, 'stdout': ''}

    host._docker_exec = docker_exec
    routes = route_checker._parse_routes_on_csonic_host(
        host, 64001, '10.0.0.32', 4)

    assert routes == {'172.16.10.0/24': ''}
    assert commands == [
        ' '.join((
            "vtysh -c 'configure terminal'",
            "-c 'router bgp 64001'",
            "-c 'address-family ipv4 unicast'",
            "-c 'neighbor 10.0.0.32 soft-reconfiguration inbound'",
        )),
        'show ip bgp neighbors 10.0.0.32 received-routes json',
    ]


@pytest.mark.parametrize(
    'bgp_vrf, ipv6, output, expected_command',
    [
        (
            'VrfARISTA01T0',
            False,
            '*> 172.16.10.0/24 10.0.0.32 0 64001 i no-export',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast '
            'community no-export"',
        ),
        (
            'VrfARISTA01T0',
            True,
            '*> 2000:172:16:10::/64 fc00::41 0 64001 i no-export',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv6 unicast '
            'community no-export"',
        ),
        (
            None,
            False,
            '*> 172.16.10.0/24 10.0.0.32 0 64001 i no-export',
            "vtysh -c 'show ip bgp community no-export'",
        ),
    ],
)
def test_csonic_no_export_query_uses_logical_vrf(
        bgp_vrf, ipv6, output, expected_command):
    host = CsonicHost('csonic-prime', bgp_vrf=bgp_vrf)
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {'rc': 0, 'stdout': output}

    host._docker_exec = docker_exec

    assert bgp_helpers.get_no_export_output(host, ipv6=ipv6)
    assert commands == [expected_command]


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


def test_gr_helper_accepts_compacted_stale_ecmp_paths_for_shared_prime():
    neighbor_routes = {
        '10.0.0.1': {
            '192.0.2.0/24': [{'peerId': '10.0.0.1'}],
            '198.51.100.0/24': [{'peerId': '10.0.0.1'}],
        },
        '10.0.0.5': {
            '192.0.2.0/24': [{'peerId': '10.0.0.5'}],
        },
    }
    rib = {
        # FRR can omit one equivalent stale ECMP path from the global view.
        '192.0.2.0/24': [{'peerId': '10.0.0.5', 'stale': True}],
        '198.51.100.0/24': [{'peerId': '10.0.0.1', 'stale': True}],
    }

    verify_shared_prime_routes_during_graceful_restart(
        neighbor_routes, rib, ['10.0.0.1', '10.0.0.5'])


def test_gr_helper_excludes_selected_path_count_from_baseline():
    walk_counters = {
        'All RIB': 6370,
        'Valid': 6370,
        'Useable': 6370,
        'Used': 1,
    }

    assert get_shared_prime_preserved_prefix_counters(walk_counters) == {
        'All RIB': 6370,
        'Valid': 6370,
        'Useable': 6370,
    }


def test_gr_helper_requires_stable_non_empty_counter_snapshots():
    previous = {
        ('10.0.0.1', None): {
            'All RIB': 1843,
            'Valid': 1843,
            'Useable': 1843,
        },
        ('10.0.0.5', None): {
            'All RIB': 2460,
            'Valid': 2460,
            'Useable': 2460,
        },
    }
    current = {
        peer: dict(counters)
        for peer, counters in previous.items()
    }

    assert shared_prime_prefix_counter_snapshots_match(previous, current)
    assert not shared_prime_prefix_counter_snapshots_match(None, current)

    current[('10.0.0.1', None)]['All RIB'] += 1
    assert not shared_prime_prefix_counter_snapshots_match(previous, current)

    current = {
        ('10.0.0.1', None): {
            'All RIB': 0,
            'Valid': 0,
            'Useable': 0,
        },
    }
    assert not shared_prime_prefix_counter_snapshots_match(current, current)


def test_gr_helper_requires_exact_shared_prime_route_counts():
    during_restart = {
        'ribTableWalkCounters': {
            'Stale': 6370,
            'All RIB': 6370,
            'Valid': 6370,
            'Useable': 6370,
        },
    }
    recovered_empty_peer = {
        'ribTableWalkCounters': {
            'Stale': 0,
            'All RIB': 0,
            'Valid': 0,
            'Useable': 0,
        },
    }
    expected = {
        'All RIB': 6370,
        'Valid': 6370,
        'Useable': 6370,
    }

    assert shared_prime_prefix_counters_preserved(
        during_restart, expected, during_restart=True)
    assert not shared_prime_prefix_counters_preserved(
        during_restart, {**expected, 'All RIB': 6371},
        during_restart=True)
    assert not shared_prime_prefix_counters_preserved(
        {
            'ribTableWalkCounters': {
                **during_restart['ribTableWalkCounters'],
                'Valid': 6369,
            },
        },
        expected,
        during_restart=True)
    assert shared_prime_prefix_counters_preserved(
        recovered_empty_peer,
        {'All RIB': 0, 'Valid': 0, 'Useable': 0},
        during_restart=False)


def test_gr_helper_rejects_non_stale_shared_prime_path():
    neighbor_routes = {
        '10.0.0.1': {
            '192.0.2.0/24': [{'peerId': '10.0.0.1'}],
        },
    }
    rib = {
        '192.0.2.0/24': [{'peerId': '10.0.0.1', 'stale': False}],
    }

    with pytest.raises(pytest.fail.Exception, match='only stale paths'):
        verify_shared_prime_routes_during_graceful_restart(
            neighbor_routes, rib, ['10.0.0.1'])
