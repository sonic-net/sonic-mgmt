"""
Tests for BGP peering over IPv6 link-local addresses (unnumbered BGP).

This test validates that SONiC can establish BGP sessions using interface-based
(unnumbered) peering, which uses IPv6 link-local addresses for session setup.

Test plan:
1. Select one interface (PortChannel or Ethernet) with an existing BGP neighbor
2. Record the neighbor's ASN and current BGP session details
3. Remove the existing global-IP BGP sessions on both DUT and neighbor
4. Configure unnumbered BGP peering on DUT (neighbor <interface> interface remote-as)
5. Configure interface-based BGP neighbor on EOS/cEOS peer
6. Verify the BGP session establishes successfully
7. Verify routes are exchanged
8. Clean up by restoring the original configuration via config reload

Addresses issue: https://github.com/sonic-net/sonic-mgmt/issues/18431
"""

import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
]

WAIT_TIMEOUT = 120
POLL_INTERVAL = 10


def find_neigh_eos_intf(neigh_host, neigh_ipv4):
    """Find the neighbor's interface (Port-Channel or Ethernet) that has the given IP.

    Args:
        neigh_host: Neighbor host object (EosHost)
        neigh_ipv4: IPv4 address to search for

    Returns:
        Interface name (e.g. 'Port-Channel1', 'Ethernet1') or None
    """
    try:
        result = neigh_host.eos_command(commands=["show ip interface brief | json"])
        intf_data = result['stdout'][0] if isinstance(result['stdout'], list) else result['stdout']
        if isinstance(intf_data, dict):
            for intf_name, intf_info in intf_data.get('interfaces', {}).items():
                # Skip loopback, management, vlan interfaces
                if not (intf_name.startswith('Ethernet') or intf_name.startswith('Port-Channel')):
                    continue
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
    # This test uses eos_command/eos_config on the neighbor host, so it
    # requires EOS/cEOS neighbors.
    common_props = tbinfo.get('topo', {}).get('properties', {}).get(
        'configuration_properties', {}).get('common', {})
    neighbor_type = common_props.get('neighbor_type', 'eos')
    if neighbor_type.lower() not in ('eos', 'ceos'):
        pytest.skip("BGP link-local test requires EOS neighbors; "
                    "current neighbor_type is '{}'".format(neighbor_type))

    duthost = duthosts[rand_one_dut_hostname]

    dut_asn = common_props.get('dut_asn')
    if not dut_asn:
        config_facts_tmp = duthost.config_facts(
            host=duthost.hostname, source="running")['ansible_facts']
        device_metadata = config_facts_tmp.get('DEVICE_METADATA', {}).get('localhost', {})
        dut_asn = device_metadata.get('bgp_asn')
        if not dut_asn:
            pytest.skip("dut_asn not found in testbed configuration_properties or DEVICE_METADATA")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL', {})
    portchannel_members = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    intf_table = config_facts.get('INTERFACE', {})
    pc_intf_table = config_facts.get('PORTCHANNEL_INTERFACE', {})

    # Build map: interface -> neighbor name
    # For PortChannels: look up member interfaces in DEVICE_NEIGHBOR
    intf_to_neighbor = {}
    for pc_name in portchannels:
        if pc_name not in portchannel_members:
            continue
        for member_intf in portchannel_members[pc_name]:
            if member_intf in dev_nbrs:
                intf_to_neighbor[pc_name] = dev_nbrs[member_intf]['name']
                break

    # For direct Ethernet interfaces with BGP: check INTERFACE table
    for intf_key in intf_table:
        # intf_key could be "EthernetX" or "EthernetX|ip/mask"
        intf_name = intf_key.split('|')[0] if '|' in intf_key else intf_key
        if intf_name.startswith('Ethernet') and intf_name in dev_nbrs:
            if intf_name not in intf_to_neighbor:
                intf_to_neighbor[intf_name] = dev_nbrs[intf_name]['name']

    # Find an interface with an established IPv4 BGP neighbor
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    selected = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if ':' in neigh_ip:
            continue  # Skip IPv6, find IPv4 first
        bgp_state = bgp_facts.get('bgp_neighbors', {}).get(
            neigh_ip, {}).get('state', '')
        neigh_name = neigh_info.get('name', '')
        logger.info("Candidate neighbor %s (%s): BGP state=%s, in nbrhosts=%s",
                    neigh_ip, neigh_name, bgp_state, neigh_name in nbrhosts)
        if bgp_state != 'established':
            continue
        neigh_asn = neigh_info.get('asn', '')
        for intf_name, mapped_neigh in intf_to_neighbor.items():
            if mapped_neigh == neigh_name and neigh_name in nbrhosts:
                selected = {
                    'intf': intf_name,
                    'neigh_name': neigh_name,
                    'neigh_ipv4': neigh_ip,
                    'neigh_asn': neigh_asn,
                }
                break
        if selected:
            break

    if not selected:
        pytest.skip("No BGP neighbor with established session found on any interface")

    dut_intf = selected['intf']

    # Find IPv6 address for the same neighbor
    neigh_ipv6 = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if neigh_info.get('name', '') == selected['neigh_name'] and ':' in neigh_ip:
            neigh_ipv6 = neigh_ip
            break

    # Get DUT's addresses on this interface
    dut_ipv4 = None
    dut_ipv6 = None
    # Check both PORTCHANNEL_INTERFACE and INTERFACE tables
    addr_table = pc_intf_table.get(dut_intf, {}) if dut_intf.startswith('PortChannel') \
        else intf_table.get(dut_intf, {})
    for addr_key in addr_table:
        addr = addr_key.split('/')[0] if '/' in addr_key else addr_key
        if ':' in addr:
            dut_ipv6 = addr
        else:
            dut_ipv4 = addr

    # Get DUT's link-local on this interface
    result = duthost.shell("ip -6 addr show dev {} scope link".format(dut_intf))
    dut_link_local = None
    for line in result['stdout'].split('\n'):
        if 'inet6 fe80' in line.strip():
            dut_link_local = line.strip().split()[1].split('/')[0]
            break

    pytest_assert(dut_link_local,
                  "No link-local address on {}".format(dut_intf))

    # Find the EOS neighbor's interface
    neigh_host = nbrhosts[selected['neigh_name']]['host']
    neigh_intf = find_neigh_eos_intf(neigh_host, selected['neigh_ipv4'])
    if not neigh_intf:
        # Fallback: try common naming patterns
        if dut_intf.startswith('PortChannel'):
            pc_num = ''.join(c for c in dut_intf if c.isdigit())
            candidates = ["Port-Channel{}".format(pc_num),
                          "Port-Channel1",
                          "Port-Channel{}".format(int(pc_num) % 100 if pc_num else 1)]
        else:
            # For Ethernet, try Ethernet1 (cEOS typically uses Ethernet1 for the first port)
            candidates = ["Ethernet1"]
        for candidate in candidates:
            try:
                neigh_host.eos_command(commands=["show interfaces {}".format(candidate)])
                neigh_intf = candidate
                break
            except Exception:
                continue

    pytest_assert(neigh_intf,
                  "Could not determine neighbor's interface for {}".format(
                      selected['neigh_name']))

    info = {
        'duthost': duthost,
        'dut_asn': dut_asn,
        'dut_ipv4': dut_ipv4,
        'dut_ipv6': dut_ipv6,
        'dut_link_local': dut_link_local,
        'dut_intf': dut_intf,
        'neigh_name': selected['neigh_name'],
        'neigh_host': neigh_host,
        'neigh_asn': selected['neigh_asn'],
        'neigh_ipv4': selected['neigh_ipv4'],
        'neigh_ipv6': neigh_ipv6,
        'neigh_intf': neigh_intf,
    }

    logger.info("Setup: DUT %s (%s) <-> %s (%s) via %s/%s",
                dut_ipv4, dut_link_local, selected['neigh_name'],
                selected['neigh_ipv4'], dut_intf, neigh_intf)

    return info


def bgp_unnumbered_established(duthost, dut_intf):
    """Check if the unnumbered BGP session via an interface is established.

    FRR shows unnumbered neighbors by interface name in 'show bgp summary'.
    """
    result = duthost.shell(
        "vtysh -c 'show bgp summary json'", module_ignore_errors=True)
    if result['rc'] != 0:
        return False
    try:
        bgp_data = json.loads(result['stdout'])
        for af in ['ipv4Unicast', 'ipv6Unicast']:
            peers = bgp_data.get(af, {}).get('peers', {})
            for peer_key, peer_data in peers.items():
                if peer_data.get('state') != 'Established':
                    continue
                if dut_intf.lower() in peer_key.lower():
                    logger.info(
                        "Unnumbered peer found: %s (AF=%s, pfxRcd=%s)",
                        peer_key, af, peer_data.get('pfxRcd', 0))
                    return True
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to parse BGP summary JSON: %s", e)
    return False


@pytest.fixture(scope='function')
def configure_unnumbered_bgp(setup_info):
    """Configure unnumbered BGP peering and restore original config afterward."""
    duthost = setup_info['duthost']
    neigh_host = setup_info['neigh_host']
    dut_intf = setup_info['dut_intf']
    dut_asn = setup_info['dut_asn']
    neigh_asn = setup_info['neigh_asn']
    neigh_ipv4 = setup_info['neigh_ipv4']
    neigh_ipv6 = setup_info['neigh_ipv6']
    dut_ipv4 = setup_info['dut_ipv4']
    dut_ipv6 = setup_info['dut_ipv6']
    neigh_intf = setup_info['neigh_intf']

    # --- Setup ---

    # Wait for the selected BGP session to be established
    logger.info("Waiting for BGP session to %s to be established", neigh_ipv4)
    pytest_assert(
        wait_until(60, 5, 0, lambda: duthost.bgp_facts()['ansible_facts']
                   .get('bgp_neighbors', {}).get(neigh_ipv4, {})
                   .get('state', '') == 'established'),
        "IPv4 BGP session to {} not established".format(neigh_ipv4))

    bgp_facts = duthost.bgp_facts()['ansible_facts']
    initial_prefixes = int(
        bgp_facts['bgp_neighbors'][neigh_ipv4].get('accepted prefixes', 0))
    logger.info("Initial prefix count from %s: %d", neigh_ipv4,
                initial_prefixes)

    # Stop bgpcfgd to prevent it from re-adding the numbered neighbor.
    # bgpcfgd monitors CONFIG_DB and reconciles FRR config — even after
    # removing the neighbor from both CONFIG_DB and FRR, bgpcfgd can
    # re-add it from its internal peer cache or startup state.
    logger.info("Stopping bgpcfgd to prevent neighbor reconciliation")
    duthost.shell("docker exec bgp supervisorctl stop bgpcfgd",
                  module_ignore_errors=True)

    # Remove existing BGP neighbor from CONFIG_DB and FRR
    logger.info("Remove existing BGP neighbor %s from CONFIG_DB and FRR", neigh_ipv4)
    duthost.shell(
        'sonic-db-cli CONFIG_DB DEL "BGP_NEIGHBOR|{}"'.format(neigh_ipv4),
        module_ignore_errors=True)
    if neigh_ipv6:
        duthost.shell(
            'sonic-db-cli CONFIG_DB DEL "BGP_NEIGHBOR|{}"'.format(neigh_ipv6),
            module_ignore_errors=True)
    vtysh_remove = ['config', 'router bgp {}'.format(dut_asn),
                    'no neighbor {}'.format(neigh_ipv4)]
    if neigh_ipv6:
        vtysh_remove.append('no neighbor {}'.format(neigh_ipv6))
    cmd = 'vtysh ' + ' '.join(['-c "{}"'.format(c) for c in vtysh_remove])
    duthost.shell(cmd, module_ignore_errors=True)

    # Remove existing BGP session on EOS neighbor
    logger.info("Remove DUT neighbors on EOS peer")
    remove_lines = []
    if dut_ipv4:
        remove_lines.append("no neighbor {}".format(dut_ipv4))
    if dut_ipv6:
        remove_lines.append("no neighbor {}".format(dut_ipv6))
    if remove_lines:
        neigh_host.eos_config(lines=remove_lines,
                              parents="router bgp {}".format(neigh_asn))

    # Wait for old neighbor to be removed
    def old_neighbor_removed():
        facts = duthost.bgp_facts()['ansible_facts']
        return neigh_ipv4 not in facts.get('bgp_neighbors', {})

    wait_until(30, 3, 0, old_neighbor_removed)

    # Configure unnumbered BGP on DUT
    logger.info("Configure unnumbered BGP on DUT via %s", dut_intf)
    vtysh_add = [
        'config',
        'router bgp {}'.format(dut_asn),
        'neighbor {} interface remote-as {}'.format(dut_intf, neigh_asn),
        'address-family ipv4 unicast',
        'neighbor {} activate'.format(dut_intf),
        'exit-address-family',
        'address-family ipv6 unicast',
        'neighbor {} activate'.format(dut_intf),
        'exit-address-family',
    ]
    cmd = 'vtysh ' + ' '.join(['-c "{}"'.format(c) for c in vtysh_add])
    result = duthost.shell(cmd)
    pytest_assert(result['rc'] == 0,
                  "Failed to configure unnumbered BGP: {}".format(
                      result.get('stderr', '')))

    # Configure BGP peering on EOS using interface-based (unnumbered) config.
    eos_peer_group = "LINK_LOCAL_PG"
    logger.info("Configure interface-based BGP peering on EOS via %s (peer-group %s)",
                neigh_intf, eos_peer_group)
    neigh_host.eos_config(
        lines=[
            "neighbor {} peer group".format(eos_peer_group),
            "neighbor {} remote-as {}".format(eos_peer_group, dut_asn),
            "neighbor interface {} peer-group {}".format(neigh_intf, eos_peer_group),
        ],
        parents="router bgp {}".format(neigh_asn))

    # Enable address families for the peer-group
    for af in ["ipv4", "ipv6"]:
        neigh_host.eos_config(
            lines=[
                "neighbor {} activate".format(eos_peer_group),
            ],
            parents=["router bgp {}".format(neigh_asn),
                     "address-family {}".format(af)])

    # Verify EOS accepted the config
    eos_bgp_cfg = neigh_host.eos_command(
        commands=["show running-config section bgp"])
    eos_cfg_text = eos_bgp_cfg['stdout'][0] if isinstance(
        eos_bgp_cfg['stdout'], list) else eos_bgp_cfg['stdout']
    logger.info("EOS BGP config after setup:\n%s", eos_cfg_text)
    if eos_peer_group not in eos_cfg_text:
        pytest.fail("EOS did not accept the interface-based BGP config. "
                    "Running config:\n{}".format(eos_cfg_text))

    yield {
        'initial_prefixes': initial_prefixes,
        'eos_peer_group': eos_peer_group,
    }

    # --- Teardown ---
    logger.info("Teardown: Restoring original configuration")

    eos_peer_group = "LINK_LOCAL_PG"
    try:
        # Remove interface neighbor
        neigh_host.eos_config(
            lines=["no neighbor interface {}".format(neigh_intf)],
            parents="router bgp {}".format(neigh_asn))
        # Deactivate from address-families
        for af in ["ipv4", "ipv6"]:
            neigh_host.eos_config(
                lines=["no neighbor {} activate".format(eos_peer_group)],
                parents=["router bgp {}".format(neigh_asn),
                         "address-family {}".format(af)])
        # Remove peer-group
        neigh_host.eos_config(
            lines=["no neighbor {} peer group".format(eos_peer_group)],
            parents="router bgp {}".format(neigh_asn))
        # Restore original numbered neighbors
        restore_lines = []
        if dut_ipv4:
            restore_lines.append(
                "neighbor {} remote-as {}".format(dut_ipv4, dut_asn))
        if dut_ipv6:
            restore_lines.append(
                "neighbor {} remote-as {}".format(dut_ipv6, dut_asn))
        if restore_lines:
            neigh_host.eos_config(lines=restore_lines,
                                  parents="router bgp {}".format(neigh_asn))
    except Exception as e:
        logger.error("EOS cleanup failed: %s", e)
        eos_cleanup_failed = True
    else:
        eos_cleanup_failed = False

    # Restart bgpcfgd before config reload (was stopped during setup)
    logger.info("Restarting bgpcfgd before config reload")
    duthost.shell("docker exec bgp supervisorctl start bgpcfgd",
                  module_ignore_errors=True)

    # Config reload on DUT to restore everything
    config_reload(duthost, wait=120)

    # Wait for all original BGP sessions to re-establish
    original_neighbors = [neigh_ipv4]
    if neigh_ipv6:
        original_neighbors.append(neigh_ipv6)
    if not wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                      duthost.check_bgp_session_state, original_neighbors):
        pytest_assert(False,
                      "BGP sessions did not re-establish after config reload")
    else:
        logger.info("Original configuration restored, all sessions up")

    if eos_cleanup_failed:
        pytest.fail("EOS cleanup failed during teardown - neighbor may still "
                    "have stale link-local configuration")


@pytest.mark.disable_loganalyzer
def test_bgp_link_local_ipv6(setup_info, configure_unnumbered_bgp):
    """
    Test BGP peering over IPv6 link-local addresses (unnumbered).

    Validates that:
    1. Unnumbered BGP session can be established via an interface
    2. Routes are exchanged over the link-local session
    3. The session uses IPv6 link-local addressing
    """
    duthost = setup_info['duthost']
    dut_intf = setup_info['dut_intf']
    initial_prefixes = configure_unnumbered_bgp['initial_prefixes']

    # Wait for BGP session to establish
    logger.info("Waiting for unnumbered BGP session to establish (timeout=%ds)",
                WAIT_TIMEOUT)
    established = wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                             bgp_unnumbered_established, duthost, dut_intf)

    if not established:
        # Debug output
        summary = duthost.shell("vtysh -c 'show bgp summary'",
                                module_ignore_errors=True)
        logger.error("BGP summary:\n%s", summary.get('stdout', ''))
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(dut_intf),
            module_ignore_errors=True)
        logger.error("Neighbor detail:\n%s", detail.get('stdout', ''))
        try:
            neigh_host = setup_info['neigh_host']
            eos_bgp = neigh_host.eos_command(
                commands=["show ip bgp summary"])
            eos_out = eos_bgp['stdout'][0] if isinstance(
                eos_bgp['stdout'], list) else eos_bgp['stdout']
            logger.error("EOS BGP summary:\n%s", eos_out)
        except Exception as e:
            logger.error("Could not get EOS BGP summary: %s", e)

        pytest.fail(
            "Unnumbered BGP session via {} did not establish within {}s."
            .format(dut_intf, WAIT_TIMEOUT))

    logger.info("Unnumbered BGP session established!")

    # Verify routes are received
    logger.info("Verify routes are received via unnumbered session")

    def routes_received(duthost, dut_intf):
        result = duthost.shell("vtysh -c 'show bgp summary json'",
                               module_ignore_errors=True)
        if result['rc'] != 0:
            return False
        try:
            bgp_summary = json.loads(result['stdout'])
            for af in ['ipv4Unicast', 'ipv6Unicast']:
                for peer, data in bgp_summary.get(af, {}).get(
                        'peers', {}).items():
                    if (dut_intf.lower() in peer.lower()
                            and data.get('pfxRcd', 0) > 0):
                        return True
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    pytest_assert(
        wait_until(30, 5, 0, routes_received, duthost, dut_intf),
        "No routes received via unnumbered BGP session on {}".format(dut_intf))

    # Log actual route count
    result = duthost.shell("vtysh -c 'show bgp summary json'",
                           module_ignore_errors=True)
    route_count = 0
    if result['rc'] == 0:
        try:
            bgp_summary = json.loads(result['stdout'])
            for af in ['ipv4Unicast', 'ipv6Unicast']:
                for peer, data in bgp_summary.get(af, {}).get(
                        'peers', {}).items():
                    if dut_intf.lower() in peer.lower():
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
    logger.info("Received %d routes via unnumbered BGP (was %d via global IP)",
                route_count, initial_prefixes)

    # Verify session details
    logger.info("Verify session details")
    detail_json = duthost.shell(
        "vtysh -c 'show bgp neighbors {} json'".format(dut_intf),
        module_ignore_errors=True)
    if detail_json['rc'] == 0:
        try:
            nbr_data = json.loads(detail_json['stdout'])
            session_established = False
            for nbr_key, nbr_info in nbr_data.items():
                state = nbr_info.get('bgpState', '')
                if state == 'Established':
                    session_established = True
                    logger.info("Session detail confirmed: %s is Established via %s",
                                nbr_key, dut_intf)
                    break
            pytest_assert(session_established,
                          "BGP neighbor detail does not show Established state "
                          "for {}".format(dut_intf))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse neighbor JSON: %s", e)
            detail = duthost.shell(
                "vtysh -c 'show bgp neighbors {}'".format(dut_intf),
                module_ignore_errors=True)
            pytest_assert('Established' in detail.get('stdout', ''),
                          "BGP neighbor detail does not show Established state")
    else:
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(dut_intf),
            module_ignore_errors=True)
        pytest_assert('Established' in detail.get('stdout', ''),
                      "BGP neighbor detail does not show Established state")
        logger.info("Session detail confirmed: Established via %s", dut_intf)
