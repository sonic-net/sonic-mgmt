"""
Tests for BGP peering over IPv6 link-local addresses (unnumbered BGP).

This test validates that SONiC can establish BGP sessions using interface-based
(unnumbered) peering, which uses IPv6 link-local addresses for session setup.

Test plan:
1. Select one PortChannel interface with an existing BGP neighbor
2. Record the neighbor's ASN and current BGP session details
3. Remove the existing global-IP BGP sessions on both DUT and neighbor
4. Configure unnumbered BGP peering on DUT (neighbor <interface> interface remote-as)
5. Configure link-local BGP neighbor on EOS/cEOS peer using DUT's fe80 address
6. Verify the BGP session establishes successfully
7. Verify routes are exchanged
8. Clean up by restoring the original configuration via config reload

Addresses issue: https://github.com/sonic-net/sonic-mgmt/issues/18431
"""

import json
import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.device_type('vs'),
]

WAIT_TIMEOUT = 180
POLL_INTERVAL = 10


def get_neighbor_portchannel_intf(neigh_host, neigh_ipv4):
    """Find the neighbor's Port-Channel interface that has the given IP address.

    Args:
        neigh_host: Neighbor host object (EosHost)
        neigh_ipv4: IPv4 address to search for

    Returns:
        Port-Channel interface name or None
    """
    try:
        result = neigh_host.eos_command(commands=["show ip interface brief | json"])
        intf_data = result['stdout'][0] if isinstance(result['stdout'], list) else result['stdout']
        if isinstance(intf_data, dict):
            for intf_name, intf_info in intf_data.get('interfaces', {}).items():
                if 'Port-Channel' in intf_name:
                    ip_info = intf_info.get('interfaceAddress', {})
                    if isinstance(ip_info, dict):
                        addr = ip_info.get('ipAddr', {}).get('address', '')
                        if addr == neigh_ipv4:
                            return intf_name
                    elif isinstance(ip_info, list):
                        for entry in ip_info:
                            addr = entry.get('primaryIp', {}).get('address', '')
                            if addr == neigh_ipv4:
                                return intf_name
    except Exception as e:
        logger.warning("Could not query neighbor interfaces: {}".format(e))
    return None


@pytest.fixture(scope='module')
def setup_info(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """Gather setup information for the link-local BGP test."""
    duthost = duthosts[rand_one_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    portchannel_members = config_facts.get('PORTCHANNEL_MEMBER', {})
    pc_intfs = config_facts.get('PORTCHANNEL_INTERFACE', {})

    # Build map: neighbor name -> PortChannel
    pc_to_neighbor = {}
    for pc_name in portchannels:
        if pc_name not in portchannel_members:
            continue
        for member_intf in portchannel_members[pc_name]:
            if member_intf in dev_nbrs:
                pc_to_neighbor[pc_name] = dev_nbrs[member_intf]['name']
                break

    # Find a PortChannel with an IPv4 BGP neighbor
    selected = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if ':' in neigh_ip:
            continue  # Skip IPv6 entries, find IPv4 first
        neigh_name = neigh_info.get('name', '')
        neigh_asn = neigh_info.get('asn', '')
        for pc_name, pc_neigh_name in pc_to_neighbor.items():
            if pc_neigh_name == neigh_name and neigh_name in nbrhosts:
                selected = {
                    'pc': pc_name,
                    'neigh_name': neigh_name,
                    'neigh_ipv4': neigh_ip,
                    'neigh_asn': neigh_asn,
                }
                break
        if selected:
            break

    if not selected:
        pytest.skip("No suitable PortChannel BGP neighbor found")

    # Find IPv6 address for the same neighbor
    neigh_ipv6 = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if neigh_info.get('name', '') == selected['neigh_name'] and ':' in neigh_ip:
            neigh_ipv6 = neigh_ip
            break

    # Get DUT's addresses on this PortChannel
    dut_ipv4 = None
    dut_ipv6 = None
    for addr_key in pc_intfs.get(selected['pc'], {}):
        addr = addr_key.split('/')[0] if '/' in addr_key else addr_key
        if ':' in addr:
            dut_ipv6 = addr
        else:
            dut_ipv4 = addr

    # Get DUT's link-local on this PortChannel
    result = duthost.shell("ip -6 addr show dev {} scope link".format(selected['pc']))
    dut_link_local = None
    for line in result['stdout'].split('\n'):
        if 'inet6 fe80' in line.strip():
            dut_link_local = line.strip().split()[1].split('/')[0]
            break

    pytest_assert(dut_link_local,
                  "No link-local address on {}".format(selected['pc']))

    # Find the EOS neighbor's Port-Channel interface
    neigh_host = nbrhosts[selected['neigh_name']]['host']
    neigh_pc_intf = get_neighbor_portchannel_intf(neigh_host, selected['neigh_ipv4'])
    if not neigh_pc_intf:
        # Fallback: try common naming
        pc_num = ''.join(c for c in selected['pc'] if c.isdigit())
        for candidate in ["Port-Channel{}".format(pc_num),
                          "Port-Channel1",
                          "Port-Channel{}".format(int(pc_num) % 100 if pc_num else 1)]:
            try:
                neigh_host.eos_command(commands=["show interfaces {}".format(candidate)])
                neigh_pc_intf = candidate
                break
            except Exception:
                continue

    pytest_assert(neigh_pc_intf,
                  "Could not determine neighbor's Port-Channel interface")

    info = {
        'duthost': duthost,
        'dut_asn': dut_asn,
        'dut_ipv4': dut_ipv4,
        'dut_ipv6': dut_ipv6,
        'dut_link_local': dut_link_local,
        'portchannel': selected['pc'],
        'neigh_name': selected['neigh_name'],
        'neigh_host': neigh_host,
        'neigh_asn': selected['neigh_asn'],
        'neigh_ipv4': selected['neigh_ipv4'],
        'neigh_ipv6': neigh_ipv6,
        'neigh_pc_intf': neigh_pc_intf,
    }

    logger.info("Setup: DUT {} ({}) <-> {} ({}) via {}/{}".format(
        dut_ipv4, dut_link_local, selected['neigh_name'],
        selected['neigh_ipv4'], selected['pc'], neigh_pc_intf))

    return info


def bgp_unnumbered_established(duthost, portchannel):
    """Check if the unnumbered BGP session via a PortChannel is established.

    FRR shows unnumbered neighbors by interface name in 'show bgp summary'.
    The Ansible bgp_facts module may not parse unnumbered peers, so we
    use vtysh JSON output directly.
    """
    result = duthost.shell(
        "vtysh -c 'show bgp summary json'", module_ignore_errors=True)
    if result['rc'] != 0:
        return False
    try:
        bgp_data = json.loads(result['stdout'])
        # Check both ipv4 and ipv6 unicast address families
        for af in ['ipv4Unicast', 'ipv6Unicast']:
            peers = bgp_data.get(af, {}).get('peers', {})
            for peer_key, peer_data in peers.items():
                if peer_data.get('state') != 'Established':
                    continue
                # Match by interface name or link-local
                if (portchannel.lower() in peer_key.lower() or
                        'fe80' in peer_key.lower()):
                    logger.info("Unnumbered peer found: %s (AF=%s, state=%s, pfxRcd=%s)",
                                peer_key, af, peer_data.get('state'),
                                peer_data.get('pfxRcd', 0))
                    return True
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to parse BGP summary JSON: %s", e)
    return False


@pytest.mark.disable_loganalyzer
def test_bgp_link_local_ipv6(setup_info):
    """
    Test BGP peering over IPv6 link-local addresses (unnumbered).

    Validates that:
    1. Unnumbered BGP session can be established via a PortChannel interface
    2. Routes are exchanged over the link-local session
    3. The session uses IPv6 link-local addressing
    """
    duthost = setup_info['duthost']
    neigh_host = setup_info['neigh_host']
    portchannel = setup_info['portchannel']
    dut_asn = setup_info['dut_asn']
    neigh_asn = setup_info['neigh_asn']
    neigh_ipv4 = setup_info['neigh_ipv4']
    neigh_ipv6 = setup_info['neigh_ipv6']
    dut_ipv4 = setup_info['dut_ipv4']
    dut_ipv6 = setup_info['dut_ipv6']
    dut_link_local = setup_info['dut_link_local']
    neigh_pc_intf = setup_info['neigh_pc_intf']

    try:
        # Step 1: Verify existing BGP session is up
        logger.info("Step 1: Verify existing BGP session to %s is established", neigh_ipv4)
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        pytest_assert(
            bgp_facts['bgp_neighbors'].get(neigh_ipv4, {}).get('state') == 'established',
            "Existing IPv4 BGP session to {} not established".format(neigh_ipv4))

        # Record initial route count for comparison
        initial_prefixes = int(bgp_facts['bgp_neighbors'][neigh_ipv4].get('accepted prefixes', 0))
        logger.info("Initial prefix count from %s: %d", neigh_ipv4, initial_prefixes)

        # Step 2: Remove existing BGP sessions on DUT
        logger.info("Step 2: Remove existing BGP neighbor %s on DUT", neigh_ipv4)
        vtysh_remove = ['config', 'router bgp {}'.format(dut_asn),
                        'no neighbor {}'.format(neigh_ipv4)]
        if neigh_ipv6:
            vtysh_remove.append('no neighbor {}'.format(neigh_ipv6))
        cmd = 'vtysh ' + ' '.join(['-c "{}"'.format(c) for c in vtysh_remove])
        duthost.shell(cmd, module_ignore_errors=True)

        # Step 3: Remove existing BGP session on EOS neighbor for DUT
        logger.info("Step 3: Remove DUT neighbors on EOS peer")
        remove_lines = ["no neighbor {}".format(dut_ipv4)]
        if dut_ipv6:
            remove_lines.append("no neighbor {}".format(dut_ipv6))
        neigh_host.eos_config(lines=remove_lines,
                              parents="router bgp {}".format(neigh_asn))
        time.sleep(3)

        # Step 4: Verify old session is down
        logger.info("Step 4: Verify old BGP session is down")
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        pytest_assert(
            neigh_ipv4 not in bgp_facts['bgp_neighbors'] or
            bgp_facts['bgp_neighbors'][neigh_ipv4].get('state') != 'established',
            "Old BGP session to {} still established after removal".format(neigh_ipv4))

        # Step 5: Configure unnumbered BGP on DUT
        logger.info("Step 5: Configure unnumbered BGP on DUT via %s", portchannel)
        vtysh_add = [
            'config',
            'router bgp {}'.format(dut_asn),
            'neighbor {} interface remote-as {}'.format(portchannel, neigh_asn),
            'address-family ipv4 unicast',
            'neighbor {} activate'.format(portchannel),
            'exit-address-family',
            'address-family ipv6 unicast',
            'neighbor {} activate'.format(portchannel),
            'exit-address-family',
        ]
        cmd = 'vtysh ' + ' '.join(['-c "{}"'.format(c) for c in vtysh_add])
        result = duthost.shell(cmd)
        pytest_assert(result['rc'] == 0,
                      "Failed to configure unnumbered BGP: {}".format(result.get('stderr', '')))

        # Step 6: Configure link-local neighbor on EOS
        logger.info(
            "Step 6: Configure link-local BGP neighbor on EOS (%s%%%s)",
            dut_link_local, neigh_pc_intf)
        # EOS supports BGP peering with link-local addresses using the interface scope
        eos_neighbor = "{}%{}".format(dut_link_local, neigh_pc_intf)
        eos_lines = [
            "neighbor {} remote-as {}".format(eos_neighbor, dut_asn),
        ]
        neigh_host.eos_config(lines=eos_lines,
                              parents="router bgp {}".format(neigh_asn))

        # Step 7: Wait for BGP session to establish
        logger.info(
            "Step 7: Waiting for unnumbered BGP session to establish (timeout=%ds)",
            WAIT_TIMEOUT)
        established = wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                                 bgp_unnumbered_established, duthost, portchannel)

        if not established:
            # Debug output
            summary = duthost.shell("vtysh -c 'show bgp summary'", module_ignore_errors=True)
            logger.error("BGP summary:\n%s", summary.get('stdout', ''))
            detail = duthost.shell("vtysh -c 'show bgp neighbors {}'".format(portchannel),
                                   module_ignore_errors=True)
            logger.error("Neighbor detail:\n%s", detail.get('stdout', ''))
            # Also check EOS side
            try:
                eos_bgp = neigh_host.eos_command(commands=["show ip bgp summary"])
                eos_output = eos_bgp['stdout'][0] if isinstance(
                    eos_bgp['stdout'], list) else eos_bgp['stdout']
                logger.error("EOS BGP summary:\n%s", eos_output)
            except Exception as e:
                logger.error("Could not get EOS BGP summary: %s", e)

        pytest_assert(established,
                      "Unnumbered BGP session via {} did not establish within {}s".format(
                          portchannel, WAIT_TIMEOUT))
        logger.info("Unnumbered BGP session established!")

        # Step 8: Verify routes are received
        logger.info("Step 8: Verify routes are received via unnumbered session")
        time.sleep(15)  # Allow route exchange to complete

        # Check routes via vtysh BGP summary JSON
        result = duthost.shell("vtysh -c 'show bgp summary json'", module_ignore_errors=True)
        route_count = 0
        if result['rc'] == 0:
            try:
                bgp_summary = json.loads(result['stdout'])
                for af in ['ipv4Unicast', 'ipv6Unicast']:
                    for peer, data in bgp_summary.get(af, {}).get('peers', {}).items():
                        if (portchannel.lower() in peer.lower() or
                                'fe80' in peer.lower()):
                            pfx = data.get('pfxRcd', 0)
                            if pfx > 0:
                                route_count = pfx
                                logger.info("Peer %s (AF=%s): received %d prefixes",
                                            peer, af, pfx)
                                break
                    if route_count > 0:
                        break
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Could not parse BGP summary JSON: %s", e)

        pytest_assert(route_count > 0,
                      "No routes received via unnumbered BGP session on {}".format(portchannel))
        logger.info(
            "Received %d routes via unnumbered BGP (was %d via global IP)",
            route_count, initial_prefixes)

        # Step 9: Verify the session uses the correct interface
        logger.info("Step 9: Verify session details")
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(portchannel),
            module_ignore_errors=True)
        pytest_assert('Established' in detail.get('stdout', ''),
                      "BGP neighbor detail does not show Established state")
        logger.info("Session detail confirmed: Established via %s", portchannel)

    finally:
        # Cleanup: restore original configuration
        logger.info("Cleanup: Restoring original configuration")

        # Remove link-local neighbor from EOS
        try:
            cleanup_lines = []
            if 'eos_neighbor' in dir():
                cleanup_lines.append("no neighbor {}".format(eos_neighbor))
            # Restore original global IP neighbors
            if dut_ipv4:
                cleanup_lines.append("neighbor {} remote-as {}".format(dut_ipv4, dut_asn))
            if dut_ipv6:
                cleanup_lines.append("neighbor {} remote-as {}".format(dut_ipv6, dut_asn))
            if cleanup_lines:
                neigh_host.eos_config(lines=cleanup_lines,
                                      parents="router bgp {}".format(neigh_asn))
        except Exception as e:
            logger.warning("EOS cleanup failed: %s", e)

        # Config reload on DUT to restore everything
        config_reload(duthost, wait=360)

        # Wait for all original BGP sessions to re-establish
        original_neighbors = [neigh_ipv4]
        if neigh_ipv6:
            original_neighbors.append(neigh_ipv6)
        pytest_assert(
            wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                       duthost.check_bgp_session_state, original_neighbors),
            "BGP sessions did not re-establish after config reload")
        logger.info("Original configuration restored, all sessions up")
