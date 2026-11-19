"""Regressions for cSONiC VXLAN route-advertisement compatibility."""

from collections import UserDict

import pytest

from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost
from tests.common.helpers.bgp_routing import check_route_on_neighbors
from tests.common.helpers.bgp_routing import route_present_in_data
from tests.common.helpers.bgp_routing import route_present_on_host
from tests.vxlan.test_vxlan_route_advertisement import Test_VxLAN_route_Advertisement as VxlanRouteAdvertisement
from tests.vxlan.test_vxlan_route_advertisement import _command_stdout
from tests.vxlan.test_vxlan_route_advertisement import _neighbor_route_matches
from tests.vxlan.test_vxlan_route_advertisement import _route_prefixes_from_output
from tests.vxlan.test_vxlan_route_advertisement import _scale_route_command

pytestmark = [pytest.mark.topology("any")]


def test_route_presence_and_command_output_support_eos_and_direct_frr_shapes():
    prefix = '99.1.2.0/24'
    assert route_present_in_data({
        'vrfs': {'default': {'bgpRouteEntries': {prefix: {}}}},
    }, prefix)
    assert route_present_in_data({'paths': [{'valid': True}]}, prefix)
    assert not route_present_in_data({'paths': []}, prefix)

    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    csonic.get_route = lambda observed_prefix: {
        'prefix': observed_prefix,
        'paths': [{'valid': True}],
    }
    assert route_present_on_host(csonic, prefix)

    assert _command_stdout({'stdout': ['EOS output']}) == 'EOS output'
    assert _command_stdout({'stdout': 'FRR output'}) == 'FRR output'
    # pytest-ansible wraps EOS results in a UserDict-compatible mapping.
    assert _command_stdout(UserDict({'stdout': ['wrapped EOS output']})) == (
        'wrapped EOS output')
    assert _command_stdout({'rc': 0, 'stdout': ''}) == ''
    assert _command_stdout({
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }) is None


def test_vxlan_scale_commands_preserve_eos_and_use_frr_for_csonic():
    eos = object.__new__(EosHost)
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')

    assert _scale_route_command(eos, 'v4', '1234:4321') == (
        "show ip bgp community 1234:4321 | grep ' 99.'")
    bare_csonic_v4 = _scale_route_command(
        csonic, 'v4', '1234:4321')
    assert bare_csonic_v4 == "show ip bgp community 1234:4321"
    assert csonic._translate_command(bare_csonic_v4) == (
        'vtysh -c "show bgp vrf VrfARISTA01T2 ipv4 unicast '
        'community 1234:4321"')
    assert _scale_route_command(eos, 'v6', '1234:4321') == (
        "show ipv6 bgp match community 1234:4321 | grep ' dc4a:'")
    bare_csonic_v6 = _scale_route_command(
        csonic, 'v6', '1234:4321')
    assert bare_csonic_v6 == "show ipv6 bgp community 1234:4321"
    assert csonic._translate_command(bare_csonic_v6) == (
        'vtysh -c "show bgp vrf VrfARISTA01T2 ipv6 unicast '
        'community 1234:4321"')


def test_neighbor_route_match_waits_for_exact_route_and_community_state():
    prefix = '99.1.2.0/24'

    class Host:
        route_data = {}

        def get_route(self, route):
            assert route == prefix
            return self.route_data

    host = Host()
    assert not _neighbor_route_matches(host, prefix, True)
    assert _neighbor_route_matches(host, prefix, False)

    host.route_data = {
        'prefix': prefix,
        'paths': [{'community': {'string': '1234:4321'}}],
    }
    assert _neighbor_route_matches(host, prefix, True, '1234:4321')
    assert not _neighbor_route_matches(host, prefix, True, '9999:8888')
    assert not _neighbor_route_matches(host, prefix, False, '1234:4321')

    host.route_data = {
        'prefix': prefix,
        'paths': [{'community': {'string': '9999:8888'}}],
    }
    assert _neighbor_route_matches(host, prefix, True, '9999:8888')


def test_scale_route_output_uses_exact_cidr_tokens():
    output = """
*> 199.1.2.0/24 10.0.0.1
*> dc4a:100::/64 fc00::1
"""

    assert _route_prefixes_from_output(output) == {
        '199.1.2.0/24',
        'dc4a:100::/64',
    }
    assert '99.1.2.0/24' not in _route_prefixes_from_output(output)


def test_failed_neighbor_query_never_masquerades_as_route_withdrawal(
    monkeypatch,
):
    prefix = '99.1.2.0/24'
    csonic = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')

    def fail_query(_prefix):
        raise RuntimeError('FRR unavailable')

    csonic.get_route = fail_query
    assert route_present_on_host(csonic, prefix) is None
    assert not check_route_on_neighbors(
        {'ARISTA01T2': {'host': csonic}}, ['ARISTA01T2'], prefix, False)
    assert not _neighbor_route_matches(csonic, prefix, False)

    test = VxlanRouteAdvertisement()
    test.prefix_type = 'v4'
    test.vxlan_test_setup = {'t2': [{'host': csonic}]}
    routes = {'Vnet_v4': {'99.1.2.0': ['202.1.1.1']}}

    csonic.run_command = lambda _command: {
        'rc': 0,
        'stdout': '*> 99.1.2.0/24 202.1.1.1',
        'stderr': '',
    }
    test.verify_nighbor_has_routes_scale(routes)

    csonic.run_command = lambda _command: {
        'rc': 0,
        'stdout': '*> 199.1.2.0/24 202.1.1.1',
        'stderr': '',
    }
    monkeypatch.setattr(
        'tests.vxlan.test_vxlan_route_advertisement.time.sleep',
        lambda _seconds: None,
    )
    with pytest.raises(pytest.fail.Exception, match='did not propagate'):
        test.verify_nighbor_has_routes_scale(routes)
    test.verify_nighbor_doesnt_have_routes_scale(routes)

    csonic.run_command = lambda _command: {
        'rc': 1,
        'stdout': '',
        'stderr': 'FRR unavailable',
    }
    with pytest.raises(pytest.fail.Exception, match='route-table query failed'):
        test.verify_nighbor_doesnt_have_routes_scale(routes)
