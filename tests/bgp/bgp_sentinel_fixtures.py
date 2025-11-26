"""
Reusable fixtures and utilities for BGP Sentinel feature testing.

This module provides fixtures to enable/configure BGP Sentinel and BGP Monitor
features for use across multiple test modules.
"""

import re
import json
import time
import yaml
import pytest
import logging
import ipaddress
from jinja2 import Template
from tests.common.utilities import wait_until, wait_tcp_connection

# Import constants from bgp_helpers if available
try:
    from tests.bgp.bgp_helpers import (
        CONSTANTS_FILE,
        BGPSENTINEL_CONFIG_FILE,
        BGP_SENTINEL_PORT_V4,
        BGP_SENTINEL_NAME_V4,
        BGP_SENTINEL_PORT_V6,
        BGP_SENTINEL_NAME_V6
    )
except ImportError:
    # Fallback values if bgp_helpers is not available
    CONSTANTS_FILE = '/etc/sonic/constants.yml'
    BGPSENTINEL_CONFIG_FILE = '/tmp/bgpsentinel.json'
    BGP_SENTINEL_NAME_V4 = "bgp_sentinelV4"
    BGP_SENTINEL_NAME_V6 = "bgp_sentinelV6"
    BGP_SENTINEL_PORT_V4 = 7900
    BGP_SENTINEL_PORT_V6 = 7901

logger = logging.getLogger(__name__)

# BGP Sentinel configuration template
BGP_SENTINEL_TMPL = '''\
{
    "BGP_SENTINELS": {
        "BGPSentinel": {
            "ip_range": {{ v4_listen_range }},
            "name": "BGPSentinel",
            "src_address": "{{ v4_src_address }}"
        },
        "BGPSentinelV6": {
            "ip_range": {{ v6_listen_range }},
            "name": "BGPSentinelV6",
            "src_address": "{{ v6_src_address }}"
        }
    }
}'''

# Export all public functions and fixtures
__all__ = [
    'enable_bgp_sentinel',
    'bgp_sentinel_with_exabgp',
    'is_bgp_sentinel_supported',
    'is_bgp_monv6_supported',
    'get_sentinel_community',
    'is_bgp_sentinel_session_established',
    'BGP_SENTINEL_TMPL',
    'CONSTANTS_FILE',
    'BGPSENTINEL_CONFIG_FILE',
    'BGP_SENTINEL_PORT_V4',
    'BGP_SENTINEL_NAME_V4',
    'BGP_SENTINEL_PORT_V6',
    'BGP_SENTINEL_NAME_V6'
]


def is_bgp_sentinel_supported(duthost):
    """
    Check if BGP Sentinel is supported on the DUT.

    Args:
        duthost: DUT host object

    Returns:
        bool: True if BGP Sentinel is supported, False otherwise
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds, module_ignore_errors=True)
    if output['rc'] != 0:
        return False

    bgp_sentinel_pattern = r"\s+neighbor BGPSentinel\s+"
    return re.search(bgp_sentinel_pattern, output['stdout']) is not None


def is_bgp_monv6_supported(duthost):
    """
    Check if BGP Monitor V6 is supported on the DUT.

    Args:
        duthost: DUT host object

    Returns:
        bool: True if BGP Monitor V6 is supported, False otherwise
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds, module_ignore_errors=True)
    if output['rc'] != 0:
        return False

    bgp_monv6_pattern = r"\s+neighbor BGPMON_V6\s+"
    return re.search(bgp_monv6_pattern, output['stdout']) is not None


def get_sentinel_community(duthost, constants_file='/etc/sonic/constants.yml'):
    """
    Get the sentinel community value from DUT constants file.

    Args:
        duthost: DUT host object
        constants_file: Path to constants file

    Returns:
        str: Sentinel community value or None if not found
    """
    constants_stat = duthost.stat(path=constants_file)
    if not constants_stat['stat']['exists']:
        logger.warning('No file {} on DUT, BGP Sentinel may not be supported'.format(constants_file))
        return None

    try:
        constants = yaml.safe_load(duthost.shell('cat {}'.format(constants_file))['stdout'])
        return constants['constants']['bgp']['sentinel_community']
    except Exception as e:
        logger.error('Failed to get sentinel_community: {}'.format(e))
        return None


def is_bgp_sentinel_session_established(duthost, ibgp_sessions):
    """
    Check if BGP Sentinel sessions are established.

    Args:
        duthost: DUT host object
        ibgp_sessions: List of iBGP session IPs to check

    Returns:
        bool: True if all sessions are established, False otherwise
    """
    try:
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        if set(ibgp_sessions) <= set(bgp_facts['bgp_neighbors'].keys()):
            for nbr in ibgp_sessions:
                if bgp_facts['bgp_neighbors'][nbr]['state'] != 'established':
                    return False
            return True
    except Exception as e:
        logger.debug('Failed to get BGP facts: {}'.format(e))
    return False


@pytest.fixture(scope='module')
def enable_bgp_sentinel(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Enable BGP Sentinel feature on DUT.

    This fixture:
    - Configures BGP Sentinel with dynamic listen ranges
    - Uses DUT loopback as source address
    - Cleans up configuration after test

    Args:
        duthosts: Multi-DUT fixture
        enum_rand_one_per_hwsku_frontend_hostname: Selected DUT hostname
        tbinfo: Testbed info

    Yields:
        dict: Configuration info containing:
            - duthost: DUT host object
            - lo_ipv4: IPv4 loopback address
            - lo_ipv6: IPv6 loopback address
            - config_file: Path to config file
            - is_enabled: Whether feature was successfully enabled
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get loopback addresses
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr = lo_facts['ipv4']['address']
    lo_ipv6_addr = None
    for item in lo_facts['ipv6']:
        if not item['address'].startswith('fe80'):
            lo_ipv6_addr = item['address']
            break

    if lo_ipv6_addr is None:
        pytest.skip('No IPv6 loopback address found')

    # Get listen ranges from topology
    from tests.common.utilities import get_upstream_neigh_type
    ipv4_subnet, ipv6_subnet = None, None
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)

    for k, v in tbinfo['topo']['properties']['configuration'].items():
        if ((upstream_nbr_type == 'T0' and 'tor' in v['properties']) or
                (upstream_nbr_type == 'T2' and 'spine' in v['properties'])):
            ipv4_addr = ipaddress.ip_interface(v['bp_interface']['ipv4'].encode().decode())
            ipv6_addr = ipaddress.ip_interface(v['bp_interface']['ipv6'].encode().decode())
            ipv4_subnet = str(ipv4_addr.network)
            ipv6_subnet = str(ipv6_addr.network)
            break

    if not ipv4_subnet or not ipv6_subnet:
        pytest.skip('Could not determine listen ranges from topology')

    # Get PTF backplane addresses
    ptf_bp_v4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    ptf_bp_v6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6'].lower()

    # Render and apply configuration
    config_file = '/tmp/bgp_sentinel_config.json'
    bgp_sentinel_tmpl = Template(BGP_SENTINEL_TMPL)
    config_content = bgp_sentinel_tmpl.render(
        v4_listen_range=json.dumps([ipv4_subnet, ptf_bp_v4 + '/32']),
        v4_src_address=lo_ipv4_addr,
        v6_listen_range=json.dumps([ipv6_subnet, ptf_bp_v6 + '/128']),
        v6_src_address=lo_ipv6_addr
    )

    duthost.copy(content=config_content, dest=config_file)
    duthost.shell("sonic-cfggen -j {} -w".format(config_file))

    # Configure IPv6 NHT
    duthost.shell('vtysh -c "configure terminal" -c "ipv6 nht resolve-via-default"',
                  module_ignore_errors=True)

    # Wait for configuration to take effect
    time.sleep(5)

    # Check if feature is enabled
    is_enabled = is_bgp_sentinel_supported(duthost)

    config_info = {
        'duthost': duthost,
        'lo_ipv4': lo_ipv4_addr,
        'lo_ipv6': lo_ipv6_addr,
        'ipv4_subnet': ipv4_subnet,
        'ipv6_subnet': ipv6_subnet,
        'ptf_bp_v4': ptf_bp_v4,
        'ptf_bp_v6': ptf_bp_v6,
        'config_file': config_file,
        'is_enabled': is_enabled
    }

    logger.info('BGP Sentinel enabled: {}'.format(is_enabled))
    if not is_enabled:
        logger.warning('BGP Sentinel configuration applied but not detected in running config')

    yield config_info

    # Cleanup
    logger.info('Cleaning up BGP Sentinel configuration')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')
    duthost.file(path=config_file, state='absent')


@pytest.fixture(scope='module')
def bgp_sentinel_with_exabgp(enable_bgp_sentinel, ptfhost, tbinfo):
    """
    Enable BGP Sentinel and start ExaBGP peers on PTF.

    This fixture builds on enable_bgp_sentinel by also:
    - Starting ExaBGP instances on PTF
    - Establishing iBGP sessions
    - Setting up routing between PTF and DUT loopback
    - Providing helper functions for route announcement

    Args:
        enable_bgp_sentinel: BGP Sentinel configuration fixture
        ptfhost: PTF host object
        tbinfo: Testbed info

    Yields:
        dict: Extended configuration with:
            - All fields from enable_bgp_sentinel
            - ibgp_sessions: List of established iBGP session IPs
            - ptfip: PTF management IP
            - exabgp_ports: Dict of ExaBGP ports
            - Helper functions for route manipulation
    """
    # Use the imported constants from module level
    config = enable_bgp_sentinel
    if not config['is_enabled']:
        pytest.skip('BGP Sentinel is not enabled')

    duthost = config['duthost']
    lo_ipv4_addr = config['lo_ipv4']
    lo_ipv6_addr = config['lo_ipv6']
    ptf_bp_v4 = config['ptf_bp_v4']
    ptf_bp_v6 = config['ptf_bp_v6']

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    # Start ExaBGP processes on PTF
    ptfhost.exabgp(
        name=BGP_SENTINEL_NAME_V4,
        state="started",
        local_ip=ptf_bp_v4,
        router_id=ptf_bp_v4,
        peer_ip=lo_ipv4_addr,
        local_asn=dut_asn,
        peer_asn=dut_asn,
        port=BGP_SENTINEL_PORT_V4
    )

    ptfhost.exabgp(
        name=BGP_SENTINEL_NAME_V6,
        state="started",
        local_ip=ptf_bp_v6,
        router_id=ptf_bp_v4,
        peer_ip=lo_ipv6_addr,
        local_asn=dut_asn,
        peer_asn=dut_asn,
        port=BGP_SENTINEL_PORT_V6
    )

    # Wait for ExaBGP to start
    if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V4, timeout_s=60):
        pytest.fail("Failed to start BGP Sentinel ExaBGP on port {}".format(BGP_SENTINEL_PORT_V4))

    if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V6, timeout_s=60):
        pytest.fail("Failed to start BGP Sentinel ExaBGP on port {}".format(BGP_SENTINEL_PORT_V6))

    # Setup routing from PTF to DUT loopback
    ipv4_nh, ipv6_nh = _add_route_to_dut_lo(ptfhost, tbinfo, lo_ipv4_addr, lo_ipv6_addr)

    # Determine active iBGP sessions
    ibgp_sessions = []
    if ipv4_nh:
        ibgp_sessions.append(ptf_bp_v4)
    if ipv6_nh:
        ibgp_sessions.append(ptf_bp_v6)

    # Wait for iBGP sessions to establish
    if not wait_until(30, 5, 5, is_bgp_sentinel_session_established, duthost, ibgp_sessions):
        logger.warning('BGP Sentinel sessions did not establish within timeout')

    # Extended configuration
    extended_config = dict(config)
    extended_config.update({
        'ibgp_sessions': ibgp_sessions,
        'ptfip': ptfhost.mgmt_ip,
        'exabgp_ports': {
            'v4': BGP_SENTINEL_PORT_V4,
            'v6': BGP_SENTINEL_PORT_V6
        },
        'ipv4_nh': ipv4_nh,
        'ipv6_nh': ipv6_nh
    })

    yield extended_config

    # Cleanup
    logger.info('Cleaning up ExaBGP and routes')
    if ipv4_nh:
        ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, ipv4_nh), module_ignore_errors=True)
    if ipv6_nh:
        ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, ipv6_nh), module_ignore_errors=True)

    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V4, state="absent")
    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V6, state="absent")


def _add_route_to_dut_lo(ptfhost, tbinfo, lo_ipv4_addr, lo_ipv6_addr):
    """
    Helper function to add routes from PTF to DUT loopback.

    Args:
        ptfhost: PTF host object
        tbinfo: Testbed info
        lo_ipv4_addr: DUT IPv4 loopback address
        lo_ipv6_addr: DUT IPv6 loopback address

    Returns:
        tuple: (ipv4_nexthop, ipv6_nexthop) that worked, or (None, None)
    """
    from tests.common.utilities import get_upstream_neigh_type

    spine_bp_addr = {}
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)

    for k, v in tbinfo['topo']['properties']['configuration'].items():
        if ((upstream_nbr_type == 'T0' and 'tor' in v['properties']) or
                (upstream_nbr_type == 'T2' and 'spine' in v['properties'])):
            ipv4_addr = ipaddress.ip_interface(v['bp_interface']['ipv4'].encode().decode())
            ipv6_addr = ipaddress.ip_interface(v['bp_interface']['ipv6'].encode().decode())
            spine_bp_addr[k] = {'ipv4': str(ipv4_addr.ip), 'ipv6': str(ipv6_addr.ip)}

    ipv4_nh, ipv6_nh = None, None
    for _, v in spine_bp_addr.items():
        # Try IPv4 route
        if ipv4_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            time.sleep(5)
            ipv4_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv4_addr), module_ignore_errors=True)
            if ipv4_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            else:
                ipv4_nh = v['ipv4']

        # Try IPv6 route
        if ipv6_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            time.sleep(5)
            ipv6_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv6_addr), module_ignore_errors=True)
            if ipv6_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            else:
                ipv6_nh = v['ipv6']

    return ipv4_nh, ipv6_nh
