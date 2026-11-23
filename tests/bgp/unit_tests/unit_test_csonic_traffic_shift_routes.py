"""Focused cSONiC logical-VRF route snapshot regressions."""

import json

import pytest

from tests.bgp import route_checker
from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost


pytestmark = [pytest.mark.topology("any")]


class DutHost:
    hostname = 'dut'

    def __init__(self, bgp_entries=None):
        self.bgp_entries = bgp_entries or []

    def minigraph_facts(self, host):
        assert host == self.hostname
        return {
            'ansible_facts': {
                'minigraph_bgp_asn': 65100,
                'minigraph_bgp': self.bgp_entries,
            },
        }

    def get_bgp_confed_asn(self):
        return 65000


def _logical_peer(name, host, peer_ips):
    return {
        name: {
            'host': host,
            'conf': {
                'bgp': {
                    'asn': 64001,
                    'peers': {65100: peer_ips},
                },
            },
        },
    }


@pytest.mark.parametrize(
    'ip_ver, peer, expected_command',
    [
        (
            4,
            '10.0.0.32',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv4 unicast '
            'neighbors 10.0.0.32 routes json"',
        ),
        (
            6,
            'fc00::41',
            'vtysh -c "show bgp vrf VrfARISTA01T0 ipv6 unicast '
            'neighbors fc00::41 routes json"',
        ),
    ],
)
def test_converged_route_snapshots_use_explicit_runtime_vrf_command(
        ip_ver, peer, expected_command):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {
            'rc': 0,
            'stdout': json.dumps({
                'routes': {
                    '172.16.10.0/24': {},
                    '172.16.30.0/24': {},
                },
            }),
        }

    host._docker_exec = docker_exec

    assert route_checker._parse_routes_on_csonic_host(
        host, peer, ip_ver) == {
            '172.16.10.0/24': '',
            '172.16.30.0/24': '',
        }
    assert commands == [expected_command]


@pytest.mark.parametrize(
    'result, expected_error',
    [
        (
            {'rc': 1, 'stdout': '', 'stderr': 'FRR unavailable'},
            'Failed to retrieve routes',
        ),
        (
            {'rc': 0, 'stdout': '', 'stderr': ''},
            'route query returned empty output',
        ),
        (
            {'rc': 0, 'stdout': '% invalid', 'stderr': ''},
            'route query returned invalid JSON',
        ),
        (
            {'rc': 0, 'stdout': json.dumps({}), 'stderr': ''},
            "did not return a valid 'routes' map",
        ),
        (
            {
                'rc': 0,
                'stdout': json.dumps({'routes': []}),
                'stderr': '',
            },
            "did not return a valid 'routes' map",
        ),
    ],
)
def test_converged_route_snapshots_fail_closed(result, expected_error):
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: result

    with pytest.raises((RuntimeError, ValueError), match=expected_error):
        route_checker._parse_routes_on_csonic_host(
            host, '10.0.0.32', 4)


def test_logical_parser_rejects_ordinary_csonic_host():
    with pytest.raises(TypeError, match='converged CsonicHost'):
        route_checker._parse_routes_on_csonic_host(
            CsonicHost('ordinary-csonic'), '10.0.0.32', 4)


def test_converged_route_snapshot_accepts_valid_empty_map():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': json.dumps({'routes': {}}),
    }

    assert route_checker._parse_routes_on_csonic_host(
        host, '10.0.0.32', 4) == {}


def test_dual_dut_peer_selection_matches_selected_dut():
    mg_facts = {
        'minigraph_bgp': [
            {
                'name': 'ARISTA01T1',
                'addr': '10.0.1.57',
                'peer_addr': '10.0.1.56',
            },
        ],
    }

    assert route_checker._select_csonic_dut_peer(
        mg_facts,
        'ARISTA01T1',
        ['10.0.0.56', '10.0.1.56', 'fc00::71', 'fc00::1:71'],
        4,
    ) == '10.0.1.56'


@pytest.mark.parametrize(
    'minigraph_addrs, expected',
    [
        ([], r'matches=\[\]'),
        (
            ['10.0.0.56', '10.0.1.56'],
            r"matches=\['10.0.0.56', '10.0.1.56'\]",
        ),
    ],
)
def test_dual_dut_peer_selection_rejects_missing_or_ambiguous_match(
        minigraph_addrs, expected):
    mg_facts = {
        'minigraph_bgp': [
            {
                'name': 'ARISTA01T1',
                'addr': '192.0.2.{}'.format(index + 1),
                'peer_addr': peer,
            }
            for index, peer in enumerate(minigraph_addrs)
        ],
    }

    with pytest.raises(ValueError, match=expected):
        route_checker._select_csonic_dut_peer(
            mg_facts,
            'ARISTA01T1',
            ['10.0.0.56', '10.0.1.56'],
            4,
        )


def test_multi_logical_peer_dispatch_keeps_result_keys_isolated(monkeypatch):
    first = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    second = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA03T0')

    def route_result(prefix):
        return {
            'rc': 0,
            'stdout': json.dumps({'routes': {prefix: {}}}),
        }

    first._docker_exec = lambda command, **kwargs: route_result(
        '172.16.1.0/24')
    second._docker_exec = lambda command, **kwargs: route_result(
        '172.16.3.0/24')
    peers = {}
    peers.update(_logical_peer('ARISTA01T0', first, ['10.0.0.1']))
    peers.update(_logical_peer('ARISTA03T0', second, ['10.0.0.3']))

    def sequential_run(target, args, kwargs, nodes, **options):
        results = {}
        for node in nodes:
            target(node=node, results=results)
        return results

    monkeypatch.setattr(route_checker, 'parallel_run', sequential_run)

    assert route_checker.parse_routes_on_csonic(
        DutHost([
            {
                'name': 'ARISTA01T0',
                'addr': '10.0.0.2',
                'peer_addr': '10.0.0.1',
            },
            {
                'name': 'ARISTA03T0',
                'addr': '10.0.0.4',
                'peer_addr': '10.0.0.3',
            },
        ]),
        peers,
        4,
    ) == {
        'ARISTA01T0': {'172.16.1.0/24': ''},
        'ARISTA03T0': {'172.16.3.0/24': ''},
    }


def test_parent_rejects_incomplete_snapshot(monkeypatch):
    first = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    second = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA03T0')
    peers = {}
    peers.update(_logical_peer('ARISTA01T0', first, ['10.0.0.1']))
    peers.update(_logical_peer('ARISTA03T0', second, ['10.0.0.3']))
    monkeypatch.setattr(
        route_checker,
        'parallel_run',
        lambda *args, **kwargs: {'ARISTA01T0': {}},
    )

    with pytest.raises(
            RuntimeError, match=r"missing=\['ARISTA03T0'\]"):
        route_checker.parse_routes_on_csonic(
            DutHost(), peers, 4)


def test_real_parallel_run_propagates_failed_route_query():
    host = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T0')
    host._docker_exec = lambda command, **kwargs: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }
    peers = _logical_peer('ARISTA01T0', host, ['10.0.0.1'])

    with pytest.raises(pytest.fail.Exception, match='Processes .* failed'):
        route_checker.parse_routes_on_csonic(
            DutHost([
                {
                    'name': 'ARISTA01T0',
                    'addr': '10.0.0.2',
                    'peer_addr': '10.0.0.1',
                },
            ]),
            peers,
            4,
        )


def test_ordinary_csonic_keeps_historical_vsonic_commands(monkeypatch):
    host = CsonicHost('ordinary-csonic')
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

    def sequential_run(target, args, kwargs, nodes, **options):
        results = {}
        for node in nodes:
            target(node=node, results=results)
        return results

    monkeypatch.setattr(route_checker, 'parallel_run', sequential_run)
    peers = _logical_peer(
        'ARISTA01T0', host, ['10.0.0.1', 'fc00::1'])

    assert route_checker.parse_routes_on_neighbors(
        DutHost(), peers, 4) == {
            'ARISTA01T0': {'172.16.10.0/24': ''},
        }
    expected_config = ''.join([
        "sudo vtysh -c 'configure terminal' -c 'router bgp' ",
        "-c 'address-family ipv4'  -c                        ",
        "'neighbor 10.0.0.1 soft-reconfiguration inbound' ",
    ])
    expected_query = ''.join([
        "sudo vtysh -c 'show ip bgp neighbors 10.0.0.1 ",
        "received-routes json'",
    ])
    assert commands == [expected_config, expected_query]


@pytest.mark.parametrize('host_type', ['eos', 'sonic'])
def test_established_eos_and_sonic_dispatch_is_unchanged(
        monkeypatch, host_type):
    host = (object.__new__(EosHost) if host_type == 'eos'
            else object.__new__(SonicHost))
    if host_type == 'eos':
        host.bgp_vrf = 'ARISTA01T0'
    calls = []

    def parse_eos(*args):
        calls.append(('eos', args))
        return {'eos': {}}

    def parse_vsonic(*args):
        calls.append(('vsonic', args))
        return {'vsonic': {}}

    monkeypatch.setattr(route_checker, 'parse_routes_on_eos', parse_eos)
    monkeypatch.setattr(route_checker, 'parse_routes_on_vsonic', parse_vsonic)
    neighbors = {'ARISTA01T0': {'host': host}}

    result = route_checker.parse_routes_on_neighbors(
        object(), neighbors, 4, ['1234:5678'])
    if isinstance(host, EosHost):
        assert result == {'eos': {}}
        assert calls[0][0] == 'eos'
        assert calls[0][1][-1] == ['1234:5678']
    else:
        assert result == {'vsonic': {}}
        assert calls[0][0] == 'vsonic'
