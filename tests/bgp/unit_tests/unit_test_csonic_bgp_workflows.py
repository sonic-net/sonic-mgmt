"""Focused regressions for logical-neighbor cSONiC BGP workflows."""

import json

import pytest

from tests.bgp import bgp_helpers
from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost


pytestmark = [pytest.mark.topology("any")]


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


def test_direct_client_next_hops_follow_only_logical_csonic_peer():
    logical = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    ordinary = CsonicHost('ordinary-csonic')

    assert bgp_helpers.get_neighbor_exabgp_nexthops(
        _tbinfo(), _logical_neighbor(logical)) == (
            '10.10.246.117', 'fc0a::75')
    assert bgp_helpers.get_neighbor_exabgp_nexthops(
        _tbinfo(), _logical_neighbor(ordinary)) == (
            '10.10.246.254', 'fc0a::ff')


def test_converged_route_details_use_runtime_vrf_and_selected_path():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {
            'rc': 0,
            'stdout': json.dumps({
                'paths': [
                    {
                        'aspath': {'string': '65100 64001'},
                        'community': {'string': '9999:9999'},
                    },
                    {
                        'bestpath': {'overall': True},
                        'aspath': {'string': '65100 64002'},
                        'community': {
                            'string': '1010:1010 1234:5678',
                        },
                    },
                ],
            }),
        }

    host._docker_exec = docker_exec
    details = bgp_helpers.get_converged_csonic_route_details(
        _logical_neighbor(host), '172.16.10.0/24')

    assert details == {
        'present': True,
        'aspath': '65100 64002',
        'communities': {'1010:1010', '1234:5678'},
    }
    assert commands == [
        'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast '
        '172.16.10.0/24 json"',
    ]


def test_disjoint_multipath_communities_do_not_mask_policy_failure():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': json.dumps({
            'paths': [
                {
                    'bestpath': {'overall': True},
                    'community': {'list': ['DROP']},
                },
                {'community': {'list': ['TEST']}},
            ],
        }),
    }

    details = bgp_helpers.get_converged_csonic_route_details(
        _logical_neighbor(host), '172.16.10.0/24')
    assert details['communities'] == {'DROP'}
    assert 'TEST' not in details['communities']


@pytest.mark.parametrize(
    'result, error',
    [
        (
            {'rc': 1, 'stdout': '', 'stderr': 'FRR unavailable'},
            'route query failed',
        ),
        (
            {'rc': 0, 'stdout': '', 'stderr': ''},
            'returned no output',
        ),
        (
            {'rc': 0, 'stdout': '% invalid', 'stderr': ''},
            'invalid JSON',
        ),
        (
            {'rc': 0, 'stdout': json.dumps([]), 'stderr': ''},
            'list instead of an object',
        ),
        (
            {
                'rc': 0,
                'stdout': json.dumps({'warning': 'No BGP instance exists'}),
                'stderr': '',
            },
            'error object without paths',
        ),
        (
            {
                'rc': 0,
                'stdout': json.dumps({'paths': {}}),
                'stderr': '',
            },
            'invalid paths',
        ),
        (
            {
                'rc': 0,
                'stdout': json.dumps({'paths': [{'aspath': {}}]}),
                'stderr': '',
            },
            '0 selected paths',
        ),
    ],
)
def test_converged_route_details_fail_closed(result, error):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: result

    with pytest.raises((RuntimeError, ValueError), match=error):
        bgp_helpers.get_converged_csonic_route_details(
            _logical_neighbor(host), '172.16.10.0/24')


def test_valid_empty_converged_route_response_means_absent():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': json.dumps({}),
    }

    assert bgp_helpers.get_converged_csonic_route_details(
        _logical_neighbor(host), '172.16.10.0/24') == {
            'present': False,
            'aspath': None,
            'communities': set(),
        }


def test_ordinary_csonic_does_not_enter_logical_route_path():
    host = CsonicHost('ordinary-csonic')
    host._docker_exec = lambda *args, **kwargs: pytest.fail(
        'ordinary cSONiC route command must remain untouched')

    with pytest.raises(TypeError, match='converged CsonicHost'):
        bgp_helpers.get_converged_csonic_route_details(
            _logical_neighbor(host), '172.16.10.0/24')


@pytest.mark.parametrize(
    'details, expected_aspath, accepted, expected',
    [
        (
            {'present': True, 'aspath': '65100 64001'},
            '65100 64001',
            True,
            True,
        ),
        (
            {'present': True, 'aspath': '65100 64002'},
            '65100 64001',
            True,
            False,
        ),
        (
            {'present': False, 'aspath': None},
            '65100 64001',
            True,
            False,
        ),
        (
            {'present': False, 'aspath': None},
            '65100 64001',
            False,
            True,
        ),
        (
            {'present': True, 'aspath': '65100 64001'},
            '65100 64001',
            False,
            False,
        ),
    ],
)
def test_bbr_neighbor_route_acceptance_is_fail_closed(
        details, expected_aspath, accepted, expected):
    assert bgp_helpers.neighbor_route_matches(
        details, expected_aspath, accepted=accepted) is expected


@pytest.mark.parametrize(
    'ip_ver, peer, expected_command',
    [
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
    ],
)
def test_suppress_fib_queries_use_runtime_vrf(
        ip_ver, peer, expected_command):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {'rc': 0, 'stdout': '91.0.1.0/24'}

    host._docker_exec = docker_exec
    assert bgp_helpers.check_propagate_route(
        _logical_neighbor(host), ['91.0.1.0/24'], peer, ip_ver=ip_ver)
    assert commands == [expected_command]


@pytest.mark.parametrize('ip_ver, peer', [
    (4, '10.0.0.32'),
    (6, 'fc00::41'),
])
@pytest.mark.parametrize('action', [
    bgp_helpers.ACTION_IN,
    bgp_helpers.ACTION_NOT_IN,
])
def test_failed_suppress_fib_query_never_matches_state(
        monkeypatch, ip_ver, peer, action):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
        'failed': False,
    }
    monkeypatch.setattr(bgp_helpers.logging, 'warning', lambda *args: None)

    assert not bgp_helpers.check_propagate_route(
        _logical_neighbor(host), ['91.0.1.0/24'], peer,
        ip_ver=ip_ver, action=action)


@pytest.mark.parametrize(
    'ip_ver, peer, expected, suffix_only',
    [
        (4, '10.0.0.32', '91.0.1.0/24', '191.0.1.0/24'),
        (6, 'fc00::41', '2001:db8:1::/64', '1:2001:db8:1::/64'),
    ],
)
def test_suppress_fib_uses_exact_cidr_tokens(
        ip_ver, peer, expected, suffix_only):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': '*> {} 10.0.0.1'.format(suffix_only),
        'stderr': '',
        'failed': False,
    }
    neighbor = _logical_neighbor(host)

    assert not bgp_helpers.check_propagate_route(
        neighbor, [expected], peer, ip_ver=ip_ver)
    assert bgp_helpers.check_propagate_route(
        neighbor, [expected], peer, ip_ver=ip_ver,
        action=bgp_helpers.ACTION_NOT_IN)


def test_converged_ptf_receive_ports_use_logical_minigraph_neighbors():
    class DutHost:
        def shell(self, command):
            raise AssertionError('LLDP lookup must not run for converged peers')

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
        DutHost(), 'ARISTA14T0', {}, multi_vrf_topo=True,
        csonic_multi_vrf=True) == [29]
    assert bgp_helpers.get_ptf_recv_port(
        DutHost(), 'ARISTA15T2', {}, multi_vrf_topo=True,
        csonic_multi_vrf=True) == [14, 15]


def test_converged_ceos_receive_ports_keep_prime_interface_lldp_lookup():
    class DutHost:
        def __init__(self):
            self.commands = []

        def shell(self, command):
            self.commands.append(command)
            return {'stdout': 'Ethernet116\n'}

        def get_extended_minigraph_facts(self, tbinfo):
            return {'minigraph_ptf_indices': {'Ethernet116': 29}}

    tbinfo = {
        'topo': {
            'properties': {
                'convergence_data': {
                    'convergence_mapping': {
                        'ARISTA01T0': ['ARISTA01T0', 'ARISTA03T0'],
                    },
                    'converged_peers': {
                        'ARISTA01T0': {
                            'vrf': {
                                'ARISTA03T0': {
                                    'Ethernet16': {'ipv4': '10.0.0.1/31'},
                                },
                            },
                        },
                    },
                },
            },
        },
    }
    duthost = DutHost()

    assert bgp_helpers.get_ptf_recv_port(
        duthost, 'ARISTA03T0', tbinfo, multi_vrf_topo=True,
        csonic_multi_vrf=False) == [29]
    assert duthost.commands == [
        "show lldp table | grep -w ARISTA01T0[[:space:]]*Ethernet16 "
        "| awk '{print $1}'",
    ]


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


@pytest.mark.parametrize(
    'ipv6, output, expected_command',
    [
        (
            False,
            '*> 172.16.10.0/24 10.0.0.32 0 64001 i no-export',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast '
            'community no-export"',
        ),
        (
            True,
            '*> 2000:172:16:10::/64 fc00::41 0 64001 i no-export',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv6 unicast '
            'community no-export"',
        ),
    ],
)
def test_no_export_queries_use_logical_vrf(
        ipv6, output, expected_command):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {'rc': 0, 'stdout': output}

    host._docker_exec = docker_exec

    assert bgp_helpers.get_no_export_output(
        _logical_neighbor(host), ipv6=ipv6)
    assert commands == [expected_command]


@pytest.mark.parametrize('ipv6', [False, True])
def test_no_export_queries_fail_closed(ipv6):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }

    with pytest.raises(RuntimeError, match='Failed to query .* no-export'):
        bgp_helpers.get_no_export_output(
            _logical_neighbor(host), ipv6=ipv6)


def test_ordinary_csonic_no_export_remains_unsupported():
    host = CsonicHost('ordinary-csonic')
    host._docker_exec = lambda *args, **kwargs: pytest.fail(
        'ordinary cSONiC no-export command must remain untouched')

    with pytest.raises(TypeError, match='Expected EosHost or SonicHost'):
        bgp_helpers.get_no_export_output({'host': host})


def test_ceos_and_sonic_no_export_commands_remain_unchanged():
    eos = object.__new__(EosHost)
    eos_commands = []
    eos.eos_command = lambda commands: (
        eos_commands.extend(commands) or {
            'stdout': ['*> 172.16.10.0/24 10.0.0.1 no-export'],
        })
    assert bgp_helpers.get_no_export_output({
        'host': eos,
        'is_multi_vrf_peer': True,
        'multi_vrf_data': {'vrf': 'ARISTA01T0'},
    })
    assert eos_commands == [
        'show ip bgp community no-export vrf ARISTA01T0',
    ]

    sonic = object.__new__(SonicHost)
    sonic_commands = []
    sonic.command = lambda command: (
        sonic_commands.append(command) or {
            'stdout': '*> 172.16.10.0/24 10.0.0.1 no-export',
        })
    assert bgp_helpers.get_no_export_output({'host': sonic})
    assert sonic_commands == [
        "vtysh -c 'show ip bgp community no-export'",
    ]


def test_suppress_fib_eos_and_sonic_commands_remain_unchanged():
    eos = object.__new__(EosHost)
    eos_commands = []
    eos.eos_command = lambda commands: (
        eos_commands.extend(commands) or {'stdout': ['91.0.1.0/24']})
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
