"""Focused regressions for T1-LAG shared-prime cSONiC graceful restart."""

import pytest

from tests.bgp.test_bgp_gr_helper import get_complete_csonic_t1_lag_session_map
from tests.bgp.test_bgp_gr_helper import get_csonic_t1_lag_prime_peer_names
from tests.bgp.test_bgp_gr_helper import get_shared_prime_preserved_prefix_counters
from tests.bgp.test_bgp_gr_helper import shared_prime_prefix_counter_snapshots_match
from tests.bgp.test_bgp_gr_helper import shared_prime_prefix_counters_preserved
from tests.bgp.test_bgp_gr_helper import verify_shared_prime_routes_during_graceful_restart
from tests.common.devices.csonic import CsonicHost


pytestmark = [pytest.mark.topology("any")]

T1_LAG = {
    'topo': {
        'name': 't1-lag',
        'properties': {'topo_is_multi_vrf': True},
    },
}
T0 = {
    'topo': {
        'name': 't0',
        'properties': {'topo_is_multi_vrf': True},
    },
}


def _neighbor(host):
    return {
        'host': host,
        'is_multi_vrf_peer': bool(host.bgp_vrf),
    }


def test_reports_every_logical_peer_only_for_converged_csonic_t1_lag():
    peer1 = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA01T2')
    peer2 = CsonicHost('csonic-prime', bgp_vrf='VrfARISTA03T2')
    other = CsonicHost('csonic-other', bgp_vrf='VrfARISTA01T0')
    ordinary = CsonicHost('csonic-ordinary')
    nbrhosts = {
        'ARISTA01T2': _neighbor(peer1),
        'ARISTA03T2': _neighbor(peer2),
        'ARISTA01T0': _neighbor(other),
        'ORDINARY': _neighbor(ordinary),
    }

    assert get_csonic_t1_lag_prime_peer_names(
        nbrhosts, 'ARISTA01T2', T1_LAG) == [
            'ARISTA01T2',
            'ARISTA03T2',
        ]
    assert get_csonic_t1_lag_prime_peer_names(
        nbrhosts, 'ARISTA01T2', T0) == ['ARISTA01T2']
    assert get_csonic_t1_lag_prime_peer_names(
        nbrhosts, 'ORDINARY', T1_LAG) == ['ORDINARY']


def test_requires_a_complete_nonempty_logical_peer_session_map():
    bgp_neighbors = {
        '10.0.0.1': {'name': 'ARISTA01T2'},
        'fc00::1': {'name': 'ARISTA01T2'},
        '10.0.0.5': {'name': 'ARISTA03T2'},
    }

    assert get_complete_csonic_t1_lag_session_map(
        ['ARISTA01T2', 'ARISTA03T2'], bgp_neighbors) == {
            'ARISTA01T2': ['10.0.0.1', 'fc00::1'],
            'ARISTA03T2': ['10.0.0.5'],
        }
    with pytest.raises(ValueError, match='ARISTA05T2'):
        get_complete_csonic_t1_lag_session_map(
            ['ARISTA01T2', 'ARISTA05T2'], bgp_neighbors)
    with pytest.raises(ValueError, match='Missing DUT BGP sessions'):
        get_complete_csonic_t1_lag_session_map([], bgp_neighbors)


def test_accepts_compacted_stale_ecmp_paths():
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
        '192.0.2.0/24': [{'peerId': '10.0.0.5', 'stale': True}],
        '198.51.100.0/24': [{'peerId': '10.0.0.1', 'stale': True}],
    }

    verify_shared_prime_routes_during_graceful_restart(
        neighbor_routes, rib, ['10.0.0.1', '10.0.0.5'])


def test_rejects_empty_or_non_stale_route_evidence():
    with pytest.raises(pytest.fail.Exception, match='No shared-prime routes'):
        verify_shared_prime_routes_during_graceful_restart(
            {'10.0.0.1': {}}, {}, ['10.0.0.1'])

    with pytest.raises(pytest.fail.Exception, match='only stale paths'):
        verify_shared_prime_routes_during_graceful_restart(
            {
                '10.0.0.1': {
                    '192.0.2.0/24': [{'peerId': '10.0.0.1'}],
                },
            },
            {
                '192.0.2.0/24': [
                    {'peerId': '10.0.0.1', 'stale': False},
                ],
            },
            ['10.0.0.1'])


def test_requires_complete_counter_fields():
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
    with pytest.raises(KeyError, match='Useable'):
        get_shared_prime_preserved_prefix_counters({
            'All RIB': 1,
            'Valid': 1,
        })


def test_requires_stable_nonempty_complete_counter_snapshots():
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
    expected_keys = set(previous)
    current = {peer: dict(counters) for peer, counters in previous.items()}

    assert shared_prime_prefix_counter_snapshots_match(
        previous, current, expected_keys)
    assert not shared_prime_prefix_counter_snapshots_match(
        None, current, expected_keys)
    assert not shared_prime_prefix_counter_snapshots_match({}, {}, set())

    incomplete = dict(current)
    incomplete.pop(('10.0.0.5', None))
    assert not shared_prime_prefix_counter_snapshots_match(
        incomplete, incomplete, expected_keys)

    current[('10.0.0.1', None)]['All RIB'] += 1
    assert not shared_prime_prefix_counter_snapshots_match(
        previous, current, expected_keys)

    empty_counts = {
        ('10.0.0.1', None): {
            'All RIB': 0,
            'Valid': 0,
            'Useable': 0,
        },
    }
    assert not shared_prime_prefix_counter_snapshots_match(
        empty_counts, empty_counts, set(empty_counts))


def test_requires_exact_shared_prime_route_counts():
    during_restart = {
        'ribTableWalkCounters': {
            'Stale': 6370,
            'All RIB': 6370,
            'Valid': 6370,
            'Useable': 6370,
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

    recovered = {
        'ribTableWalkCounters': {
            'Stale': 0,
            'All RIB': 6370,
            'Valid': 6370,
            'Useable': 6370,
        },
    }
    assert shared_prime_prefix_counters_preserved(
        recovered, expected, during_restart=False)
