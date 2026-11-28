"""Regressions for logical cSONiC VXLAN route-advertisement compatibility."""

from collections import UserDict
import json

import pytest

from tests.common.devices.csonic import CsonicHost
from tests.vxlan.test_vxlan_route_advertisement import Test_VxLAN_route_Advertisement as VxlanRouteAdvertisement
from tests.vxlan.test_vxlan_route_advertisement import _command_stdout
from tests.vxlan.test_vxlan_route_advertisement import _community_tokens
from tests.vxlan.test_vxlan_route_advertisement import _csonic_scale_routes_match
from tests.vxlan.test_vxlan_route_advertisement import _is_logical_converged_csonic
from tests.vxlan.test_vxlan_route_advertisement import _neighbor_route_data
from tests.vxlan.test_vxlan_route_advertisement import _neighbor_route_matches
from tests.vxlan.test_vxlan_route_advertisement import _route_prefixes_from_output
from tests.vxlan.test_vxlan_route_advertisement import _route_present_in_data
from tests.vxlan.test_vxlan_route_advertisement import _scale_route_command


pytestmark = [pytest.mark.topology("any")]


def _poll_wait(_timeout, _interval, _delay, condition, *args):
    return any(condition(*args) for _ in range(5))


class LegacyRouteHost:
    """EOS/cEOS-compatible result shapes used by the unchanged branch."""

    def __init__(self, route_present=True, community=''):
        self.commands = []
        self.route_present = route_present
        self.community = community

    def get_route(self, route):
        entries = {route: {'community': self.community}} if self.route_present else {}
        return {'vrfs': {'default': {'bgpRouteEntries': entries}}}

    def run_command(self, command):
        self.commands.append(command)
        return {'stdout': ['']}


def _test_instance(host, prefix_type='v4'):
    test = VxlanRouteAdvertisement()
    test.prefix_type = prefix_type
    test.vxlan_test_setup = {'t2': [{'host': host}]}
    return test


def test_command_output_contract_fails_closed():
    assert _command_stdout({'stdout': ['EOS output']}) == 'EOS output'
    assert _command_stdout({'stdout': 'FRR output'}) == 'FRR output'
    assert _command_stdout(UserDict({'stdout': ['wrapped output']})) == (
        'wrapped output')
    assert _command_stdout({'rc': 0, 'stdout': ''}) == ''
    assert _command_stdout({'rc': 1, 'stdout': ''}) is None
    assert _command_stdout({'failed': True, 'stdout': ''}) is None
    assert _command_stdout(None) is None
    assert _command_stdout({'stdout': object()}) is None


def test_route_presence_requires_returned_prefix_identity():
    prefix = '99.1.2.0/24'
    assert _route_present_in_data({
        'prefix': prefix,
        'paths': [{'valid': True}],
    }, prefix)
    assert not _route_present_in_data({
        'prefix': '199.1.2.0/24',
        'paths': [{'valid': True}],
    }, prefix)
    assert not _route_present_in_data({'paths': [{'valid': True}]}, prefix)
    assert not _route_present_in_data({
        'prefix': prefix,
        'paths': [],
    }, prefix)


def test_converged_csonic_route_query_is_scoped_and_strict():
    prefix = '99.1.2.0/24'
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    commands = []

    def docker_exec(command, **kwargs):
        commands.append(command)
        return {
            'rc': 0,
            'stdout': json.dumps({
                'prefix': prefix,
                'paths': [{'valid': True}],
            }),
        }

    csonic._docker_exec = docker_exec

    assert _neighbor_route_data(csonic, prefix)['paths']
    assert commands == [
        'vtysh -c "show bgp vrf VrfARISTA01T2 ipv4 unicast '
        '99.1.2.0/24 json"',
    ]

    csonic._docker_exec = lambda command, **kwargs: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }
    with pytest.raises(RuntimeError, match='query failed'):
        _neighbor_route_data(csonic, prefix)


def test_ordinary_csonic_remains_on_legacy_get_route_path():
    prefix = '99.1.2.0/24'
    ordinary = CsonicHost('ordinary-csonic')
    calls = []
    expected = {'legacy': True}
    ordinary.get_route = lambda route: calls.append(route) or expected

    assert not _is_logical_converged_csonic(ordinary)
    assert _neighbor_route_data(ordinary, prefix) is expected
    assert calls == [prefix]


def test_logical_csonic_scale_commands_use_frr_grammar():
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')

    v4 = _scale_route_command(csonic, 'v4', '1234:4321')
    assert v4 == 'show ip bgp community 1234:4321'
    assert csonic._translate_command(v4) == (
        'vtysh -c "show bgp vrf VrfARISTA01T2 ipv4 unicast '
        'community 1234:4321"')

    v6 = _scale_route_command(csonic, 'v6', '1234:4321')
    assert v6 == 'show ipv6 bgp community 1234:4321'
    assert csonic._translate_command(v6) == (
        'vtysh -c "show bgp vrf VrfARISTA01T2 ipv6 unicast '
        'community 1234:4321"')


def test_eos_paths_keep_immediate_checks_and_exact_command_grammar(monkeypatch):
    routes = {'Vnet_v4': {'99.1.2.0': ['202.1.1.1']}}
    host = LegacyRouteHost(route_present=True, community='1234:4321')
    test = _test_instance(host)

    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.wait_until',
        lambda *args, **kwargs: pytest.fail('legacy EOS path must not poll'),
    )
    test.verify_nighbor_has_routes(routes, '1234:4321')
    host.route_present = False
    test.verify_nighbor_doesnt_have_routes(routes, '1234:4321')

    outputs = iter([
        {'stdout': ['']},
        {'stdout': ['*> 99.1.2.0/24 10.0.0.1']},
    ])
    host.run_command = lambda command: (
        host.commands.append(command) or next(outputs)
    )
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.time.sleep',
        lambda _seconds: None,
    )
    test.verify_nighbor_has_routes_scale(routes, '1234:4321')
    assert host.commands == [
        "show ip bgp community 1234:4321 | grep ' 99.'",
        "show ip bgp community 1234:4321 | grep ' 99.'",
    ]

    host.commands = []
    host.run_command = lambda command: (
        host.commands.append(command)
        or {'stdout': ['*> 98.1.2.0/24 10.0.0.1']}
    )
    test.verify_nighbor_doesnt_have_routes_scale(routes)
    assert host.commands == ["show ip bgp  | grep ' 99.'"]


def test_eos_ipv6_scale_grammar_remains_match_community(monkeypatch):
    routes = {'Vnet_v6': {'dc4a:1:2::': ['202.1.1.1']}}
    host = LegacyRouteHost()
    host.run_command = lambda command: (
        host.commands.append(command)
        or {'stdout': ['*> dc4a:1:2::/64 fc00::1']}
    )
    test = _test_instance(host, prefix_type='v6')
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.time.sleep',
        lambda _seconds: None,
    )

    test.verify_nighbor_has_routes_scale(routes, '1234:4321')
    assert host.commands == [
        "show ipv6 bgp match community 1234:4321 | grep ' dc4a:'",
    ]


def test_community_and_prefix_tokens_reject_substring_collisions():
    data = {
        'paths': [{
            'community': {
                'string': '11234:4321 1234:43210 1234:4321',
            },
            'communities': ['65000:1:7'],
        }],
    }
    assert _community_tokens(data) == {
        '11234:4321',
        '1234:43210',
        '1234:4321',
        '65000:1:7',
    }

    output = """
*> 199.1.2.0/24 10.0.0.1
*> 1:2001:db8:1::/64 fc00::1
"""
    assert _route_prefixes_from_output(output) == {
        '199.1.2.0/24',
        '1:2001:db8:1::/64',
    }
    assert '99.1.2.0/24' not in _route_prefixes_from_output(output)
    assert '2001:db8:1::/64' not in _route_prefixes_from_output(output)


def test_failed_query_never_masquerades_as_state():
    prefix = '99.1.2.0/24'
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    csonic._docker_exec = lambda command, **kwargs: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }
    assert not _neighbor_route_matches(csonic, prefix, False)
    assert not _neighbor_route_matches(csonic, prefix, True)


@pytest.mark.parametrize('route_data', [
    {
        'prefix': '199.1.2.0/24',
        'paths': [{'valid': True}],
    },
    {
        'paths': [{'valid': True}],
    },
])
def test_withdrawal_rejects_nonempty_unidentified_route_data(route_data):
    prefix = '99.1.2.0/24'
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    csonic._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': json.dumps(route_data),
        'stderr': '',
    }
    assert not _neighbor_route_matches(csonic, prefix, False)
    assert not _neighbor_route_matches(csonic, prefix, True)


def test_withdrawal_accepts_frr_empty_object_absence():
    prefix = '99.1.2.0/24'
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    csonic._docker_exec = lambda command, **kwargs: {
        'rc': 0,
        'stdout': '{}',
        'stderr': '',
    }
    assert _neighbor_route_matches(csonic, prefix, False)
    assert not _neighbor_route_matches(csonic, prefix, True)


def test_csonic_scale_withdrawal_polls_each_neighbor_independently(monkeypatch):
    route = '99.1.2.0/24'
    routes = {'Vnet_v4': {'99.1.2.0': ['202.1.1.1']}}
    first = CsonicHost('first', bgp_vrf='VrfARISTA01T2')
    second = CsonicHost('second', bgp_vrf='VrfARISTA03T2')
    calls = {'first': 0, 'second': 0}

    def result_for(name):
        calls[name] += 1
        output = (
            '*> {} 10.0.0.1'.format(route)
            if calls[name] == 1 else
            '*> 199.1.2.0/24 10.0.0.1'
        )
        return {'rc': 0, 'stdout': output}

    first.run_command = lambda _command: result_for('first')
    second.run_command = lambda _command: result_for('second')
    test = VxlanRouteAdvertisement()
    test.prefix_type = 'v4'
    test.vxlan_test_setup = {
        't2': [{'host': first}, {'host': second}],
    }
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.wait_until',
        _poll_wait,
    )

    test.verify_nighbor_doesnt_have_routes_scale(routes)
    assert calls == {'first': 2, 'second': 2}


def test_csonic_scale_advertisement_retries_each_neighbor_independently(
    monkeypatch,
):
    route = '99.1.2.0/24'
    routes = {'Vnet_v4': {'99.1.2.0': ['202.1.1.1']}}
    first = CsonicHost('first', bgp_vrf='VrfARISTA01T2')
    second = CsonicHost('second', bgp_vrf='VrfARISTA03T2')
    calls = {'first': 0, 'second': 0}

    def result_for(name):
        calls[name] += 1
        output = (
            '*> 199.1.2.0/24 10.0.0.1'
            if calls[name] == 1 else
            '*> {} 10.0.0.1'.format(route)
        )
        return {'rc': 0, 'stdout': output}

    first.run_command = lambda _command: result_for('first')
    second.run_command = lambda _command: result_for('second')
    test = VxlanRouteAdvertisement()
    test.prefix_type = 'v4'
    test.vxlan_test_setup = {
        't2': [{'host': first}, {'host': second}],
    }
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.wait_until',
        _poll_wait,
    )

    test.verify_nighbor_has_routes_scale(routes)
    assert calls == {'first': 2, 'second': 2}


def test_csonic_scale_query_failure_is_never_absence(monkeypatch):
    route = '99.1.2.0/24'
    csonic = CsonicHost('prime', bgp_vrf='VrfARISTA01T2')
    csonic.run_command = lambda _command: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }
    assert not _csonic_scale_routes_match(
        csonic, 'show ip bgp', [route], False)

    test = _test_instance(csonic)
    routes = {'Vnet_v4': {'99.1.2.0': ['202.1.1.1']}}
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.wait_until',
        _poll_wait,
    )
    with pytest.raises(pytest.fail.Exception, match='still propagated'):
        test.verify_nighbor_doesnt_have_routes_scale(routes)
