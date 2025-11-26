"""
Example test showing how to use BGP Sentinel fixtures.

This demonstrates how other test modules can leverage the BGP Sentinel
fixtures without duplicating setup/teardown code.

The fixtures are imported in tests/bgp/conftest.py, so they're
automatically available to all tests in the tests/bgp/ directory.
"""

import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from bgp_sentinel_fixtures import (
    get_sentinel_community,
    is_bgp_sentinel_session_established
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs'),
]


def test_bgp_sentinel_basic_config(enable_bgp_sentinel):
    """
    Test that BGP Sentinel can be configured successfully.

    This is a simple test that just uses the enable_bgp_sentinel fixture
    to verify the feature can be enabled.
    """
    config = enable_bgp_sentinel

    # Verify configuration was applied
    pytest_assert(config['is_enabled'],
                  'BGP Sentinel should be enabled')

    duthost = config['duthost']
    logger.info('BGP Sentinel successfully configured on {}'.format(duthost.hostname))

    # Verify loopback addresses are configured
    pytest_assert(config['lo_ipv4'], 'IPv4 loopback should be configured')
    pytest_assert(config['lo_ipv6'], 'IPv6 loopback should be configured')


def test_bgp_sentinel_session_establishment(bgp_sentinel_with_exabgp):
    """
    Test that BGP Sentinel sessions can be established with ExaBGP peers.

    This test uses the full bgp_sentinel_with_exabgp fixture which:
    - Enables BGP Sentinel
    - Starts ExaBGP peers
    - Establishes iBGP sessions
    """
    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']
    ibgp_sessions = config['ibgp_sessions']

    # Verify sessions are established
    pytest_assert(len(ibgp_sessions) > 0,
                  'At least one iBGP session should be configured')

    is_established = is_bgp_sentinel_session_established(duthost, ibgp_sessions)
    pytest_assert(is_established,
                  'BGP Sentinel sessions should be established')

    logger.info('Successfully established {} iBGP sessions: {}'.format(
        len(ibgp_sessions), ibgp_sessions))


def test_bgp_sentinel_community_config(enable_bgp_sentinel):
    """
    Test that sentinel community is properly configured.
    """
    config = enable_bgp_sentinel
    duthost = config['duthost']

    # Get sentinel community from DUT
    sentinel_comm = get_sentinel_community(duthost)

    pytest_assert(sentinel_comm is not None,
                  'Sentinel community should be defined')

    logger.info('Sentinel community configured as: {}'.format(sentinel_comm))


@pytest.mark.parametrize('ip_version', ['IPv4', 'IPv6'])
def test_bgp_sentinel_route_announcement(bgp_sentinel_with_exabgp, ip_version):
    """
    Test route announcement through BGP Sentinel.

    This is a template showing how to announce routes through the
    established BGP Sentinel sessions.
    """
    import requests

    config = bgp_sentinel_with_exabgp
    duthost = config['duthost']
    ptfip = config['ptfip']

    # Skip if the requested IP version session is not established
    if ip_version == 'IPv4' and config['ipv4_nh'] is None:
        pytest.skip('IPv4 iBGP session not established')
    if ip_version == 'IPv6' and config['ipv6_nh'] is None:
        pytest.skip('IPv6 iBGP session not established')

    # Get sentinel community
    sentinel_comm = get_sentinel_community(duthost)
    pytest_assert(sentinel_comm is not None, 'Sentinel community not found')

    # Determine neighbor and port based on IP version
    if ip_version == 'IPv4':
        neighbor = config['lo_ipv4']
        nexthop = config['ptf_bp_v4']
        port = config['exabgp_ports']['v4']
        test_route = '192.168.100.0/24'
    else:
        neighbor = config['lo_ipv6']
        nexthop = config['ptf_bp_v6']
        port = config['exabgp_ports']['v6']
        test_route = '2001:db8:100::/48'

    # Announce a test route
    url = "http://{}:{}".format(ptfip, port)
    data = {
        "command": "neighbor {} announce route {} next-hop {} local-preference 10000 community [{}]".format(
            neighbor, test_route, nexthop, sentinel_comm
        )
    }

    logger.info('Announcing route {} via {}'.format(test_route, neighbor))
    response = requests.post(url, data=data, proxies={"http": None, "https": None})
    pytest_assert(response.status_code == 200,
                  'Route announcement should succeed')

    # Verify route is received (add actual verification here)
    import time
    time.sleep(5)

    logger.info('Route {} announced successfully'.format(test_route))

    # Withdraw the route
    data['command'] = "neighbor {} withdraw route {} next-hop {}".format(
        neighbor, test_route, nexthop
    )
    response = requests.post(url, data=data, proxies={"http": None, "https": None})
    pytest_assert(response.status_code == 200,
                  'Route withdrawal should succeed')


# Additional example: Using BGP Sentinel in a test class
class TestBGPSentinelFeatures:
    """
    Example test class showing how to use BGP Sentinel fixtures
    in a class-based test structure.
    """

    def test_feature_enabled(self, enable_bgp_sentinel):
        """Test that feature is enabled."""
        config = enable_bgp_sentinel
        assert config['is_enabled'], 'BGP Sentinel should be enabled'

    def test_multiple_sessions(self, bgp_sentinel_with_exabgp):
        """Test multiple BGP sessions can be established."""
        config = bgp_sentinel_with_exabgp
        # Can have both IPv4 and IPv6 sessions
        assert len(config['ibgp_sessions']) <= 2, 'Should have at most 2 sessions'
        assert len(config['ibgp_sessions']) > 0, 'Should have at least 1 session'
