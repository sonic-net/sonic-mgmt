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

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
]

WAIT_TIMEOUT = 120
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
    # This test uses eos_command/eos_config on the neighbor host, so it
    # requires EOS/cEOS neighbors.  Skip gracefully for other neighbor types.
    common_props = tbinfo.get('topo', {}).get('properties', {}).get(
        'configuration_properties', {}).get('common', {})
    neighbor_type = common_props.get('neighbor_type', 'eos')
    if neighbor_type.lower() not in ('eos', 'ceos'):
        pytest.skip("BGP link-local test requires EOS neighbors; "
                    "current neighbor_type is '{}'".format(neighbor_type))

    duthost = duthosts[rand_one_dut_hostname]
    dut_asn = common_props.get('dut_asn')
    if not dut_asn:
        # Fallback: get ASN from running config
        config_facts_tmp = duthost.config_facts(
            host=duthost.hostname, source="running")['ansible_facts']
        device_metadata = config_facts_tmp.get('DEVICE_METADATA', {}).get('localhost', {})
        dut_asn = device_metadata.get('bgp_asn')
        if not dut_asn:
            pytest.skip("dut_asn not found in testbed configuration_properties or DEVICE_METADATA")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    portchannel_members = config_facts.get('PORTCHANNEL_MEMBER', {})

    # Build map: neighbor name -> PortChannel
    pc_to_neighbor = {}
    for pc_name in portchannels:
        if pc_name not in portchannel_members:
            continue
        for member_intf in portchannel_members[pc_name]:
            if member_intf in dev_nbrs:
                pc_to_neighbor[pc_name] = dev_nbrs[member_intf]['name']
                break

    # Find a PortChannel with an established IPv4 BGP neighbor
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    selected = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if ':' in neigh_ip:
            continue  # Skip IPv6 entries, find IPv4 first
        # Only select neighbors with established BGP sessions
        bgp_state = bgp_facts.get('bgp_neighbors', {}).get(
            neigh_ip, {}).get('state', '')
        neigh_name = neigh_info.get('name', '')
        logger.info("Candidate neighbor %s (%s): BGP state=%s, in nbrhosts=%s",
                    neigh_ip, neigh_name, bgp_state, neigh_name in nbrhosts)
        if bgp_state != 'established':
            logger.info("Skipping %s: BGP state is '%s', not 'established'", neigh_ip, bgp_state)
            continue
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
        pytest.skip("No PortChannel BGP neighbor with established session found")

    # Find IPv6 address for the same neighbor
    neigh_ipv6 = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if neigh_info.get('name', '') == selected['neigh_name'] and ':' in neigh_ip:
            neigh_ipv6 = neigh_ip
            break

    # Get DUT's addresses on this PortChannel
    dut_ipv4 = None
    dut_ipv6 = None
    for addr_key in config_facts.get('PORTCHANNEL_INTERFACE', {}).get(selected['pc'], {}):
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

    logger.info("Setup: DUT %s (%s) <-> %s (%s) via %s/%s",
                dut_ipv4, dut_link_local, selected['neigh_name'],
                selected['neigh_ipv4'], selected['pc'], neigh_pc_intf)

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
        for af in ['ipv4Unicast', 'ipv6Unicast']:
            peers = bgp_data.get(af, {}).get('peers', {})
            for peer_key, peer_data in peers.items():
                if peer_data.get('state') != 'Established':
                    continue
                if (portchannel.lower() in peer_key.lower()):
                    logger.info(
                        "Unnumbered peer found: %s (AF=%s, pfxRcd=%s)",
                        peer_key, af, peer_data.get('pfxRcd', 0))
                    return True
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to parse BGP summary JSON: %s", e)
    return False


@pytest.fixture(scope='function')
def configure_unnumbered_bgp(setup_info):
    """Configure unnumbered BGP peering and restore original config afterward.

    Setup:
        1. Verify existing BGP session is up
        2. Remove existing global-IP BGP sessions on both DUT and neighbor
        3. Configure unnumbered BGP on DUT
        4. Configure link-local neighbor on EOS peer
    Teardown:
        1. Remove link-local neighbor from EOS and restore original neighbors
        2. Config reload on DUT
        3. Wait for original BGP sessions to re-establish
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
    neigh_pc_intf = setup_info['neigh_pc_intf']

    # --- Setup ---

    # Wait for the selected BGP session to be established (it was established
    # at module setup time, but may have temporarily dropped)
    logger.info("Waiting for BGP session to %s to be established", neigh_ipv4)
    pytest_assert(
        wait_until(60, 5, 0, lambda: duthost.bgp_facts()['ansible_facts']
                   .get('bgp_neighbors', {}).get(neigh_ipv4, {})
                   .get('state', '') == 'established'),
        "IPv4 BGP session to {} not established".format(neigh_ipv4))

    bgp_facts = duthost.bgp_facts()['ansible_facts']
    initial_prefixes = int(
        bgp_facts['bgp_neighbors'][neigh_ipv4].get('accepted prefixes', 0))
    initial_prefixes_v6 = 0
    if neigh_ipv6:
        initial_prefixes_v6 = int(
            bgp_facts['bgp_neighbors'].get(neigh_ipv6, {})
            .get('accepted prefixes', 0))
    # Stash baselines so the test can assert the unnumbered session preserves
    # the full IPv4 (and IPv6) advertisement set, not just that prefixes > 0.
    setup_info['initial_ipv4_prefixes'] = initial_prefixes
    setup_info['initial_ipv6_prefixes'] = initial_prefixes_v6
    logger.info("Initial prefix count from %s: %d (v4), %d (v6)",
                neigh_ipv4, initial_prefixes, initial_prefixes_v6)

    # Remove existing BGP sessions on DUT
    logger.info("Remove existing BGP neighbor %s on DUT", neigh_ipv4)
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

    # Wait for old neighbor to be removed from DUT BGP before proceeding
    def old_neighbor_removed():
        facts = duthost.bgp_facts()['ansible_facts']
        return neigh_ipv4 not in facts.get('bgp_neighbors', {})

    wait_until(30, 3, 0, old_neighbor_removed)

    # Configure unnumbered BGP on DUT.
    # NOTE: 'v6only' is required — without it FRR auto-picks the peer's IPv4
    # address from the /31 on the PortChannel (since SONiC configures both
    # IPv4 and IPv6 on inter-switch links) and tries to open a numbered IPv4
    # session instead of a link-local unnumbered session.
    logger.info("Configure unnumbered BGP on DUT via %s", portchannel)
    vtysh_add = [
        'config',
        'router bgp {}'.format(dut_asn),
        'neighbor {} interface v6only remote-as {}'.format(portchannel, neigh_asn),
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
                  "Failed to configure unnumbered BGP: {}".format(
                      result.get('stderr', '')))

    # Configure BGP peering on EOS using interface-based (unnumbered) config.
    # EOS does not support raw fe80:: addresses as BGP neighbors.
    # Instead, EOS uses: neighbor interface <intf> peer-group <pg>
    # with the peer-group configured for the remote AS.
    #
    # NOTE: cEOS defaults Port-Channel interfaces to 'ipv6 nd ra disabled'.
    # FRR's unnumbered peering on the DUT side relies on receiving IPv6 RAs
    # from the peer to discover its link-local address; without RAs the DUT
    # stays in '(unspec)' state and never opens TCP/179. We therefore enable
    # RAs on the peer Port-Channel as part of the peering setup.
    eos_peer_group = "LINK_LOCAL_PG"
    logger.info("Enable IPv6 RAs on EOS %s (required for FRR unnumbered peer discovery)",
                neigh_pc_intf)
    neigh_host.eos_config(
        lines=["no ipv6 nd ra disabled"],
        parents="interface {}".format(neigh_pc_intf))

    logger.info("Configure interface-based BGP peering on EOS via %s (peer-group %s)",
                neigh_pc_intf, eos_peer_group)
    neigh_host.eos_config(
        lines=[
            "neighbor {} peer group".format(eos_peer_group),
            "neighbor {} remote-as {}".format(eos_peer_group, dut_asn),
            "neighbor interface {} peer-group {}".format(neigh_pc_intf, eos_peer_group),
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

    # Enable RFC 5549 (extended next-hop encoding) on EOS so it can advertise
    # IPv4 NLRI with an IPv6 next-hop over the link-local session. Without
    # these two knobs, cEOS passively receives the capability from FRR but
    # never advertises it, then drops all outbound IPv4 updates with
    # "IPv4 local address not available" since the TCP session has no IPv4
    # local address. Required since EOS 4.22.1F (multi-agent model).
    logger.info("Enable RFC 5549 extended next-hop on EOS for %s",
                eos_peer_group)
    neigh_host.eos_config(lines=["ip routing ipv6 interfaces"])
    neigh_host.eos_config(
        lines=[
            "neighbor {} next-hop address-family ipv6 originate".format(
                eos_peer_group),
        ],
        parents=["router bgp {}".format(neigh_asn),
                 "address-family ipv4"])

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

    # Remove interface-based peering from EOS and restore originals.
    # Order matters: remove interface neighbor first, then deactivate
    # from address-families, then remove the peer-group itself.
    eos_peer_group = "LINK_LOCAL_PG"
    try:
        # Step 1: remove interface neighbor (must precede peer-group removal)
        neigh_host.eos_config(
            lines=["no neighbor interface {}".format(neigh_pc_intf)],
            parents="router bgp {}".format(neigh_asn))
        # Step 2: revert RFC 5549 knobs and deactivate from address-families
        neigh_host.eos_config(
            lines=[
                "no neighbor {} next-hop address-family ipv6 originate".format(
                    eos_peer_group),
                "no neighbor {} activate".format(eos_peer_group),
            ],
            parents=["router bgp {}".format(neigh_asn),
                     "address-family ipv4"])
        neigh_host.eos_config(
            lines=["no neighbor {} activate".format(eos_peer_group)],
            parents=["router bgp {}".format(neigh_asn),
                     "address-family ipv6"])
        neigh_host.eos_config(lines=["no ip routing ipv6 interfaces"])
        # Step 3: remove the peer-group
        neigh_host.eos_config(
            lines=["no neighbor {} peer group".format(eos_peer_group)],
            parents="router bgp {}".format(neigh_asn))
        # Step 4: restore original numbered neighbors
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
        # Step 5: re-activate the restored v6 neighbor under address-family
        # ipv6. EOS does NOT auto-activate IPv6 peers (unlike IPv4), so without
        # this the original v6 session stays Idle after teardown even though
        # the 'remote-as' line is back. (IPv4 peers are activated by default.)
        if dut_ipv6:
            neigh_host.eos_config(
                lines=["neighbor {} activate".format(dut_ipv6)],
                parents=["router bgp {}".format(neigh_asn),
                         "address-family ipv6"])
    except Exception as e:
        logger.error("EOS cleanup failed: %s", e)
        # Still proceed to config_reload below, but fail the teardown afterward
        # so the error is visible rather than silently swallowed.
        eos_cleanup_failed = True
    else:
        eos_cleanup_failed = False

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
    1. Unnumbered BGP session can be established via a PortChannel interface
    2. Routes are exchanged over the link-local session
    3. The session uses IPv6 link-local addressing
    """
    duthost = setup_info['duthost']
    portchannel = setup_info['portchannel']
    initial_prefixes = configure_unnumbered_bgp['initial_prefixes']

    # Wait for BGP session to establish
    logger.info("Waiting for unnumbered BGP session to establish (timeout=%ds)",
                WAIT_TIMEOUT)
    established = wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                             bgp_unnumbered_established, duthost, portchannel)

    if not established:
        # Debug output before skipping
        summary = duthost.shell("vtysh -c 'show bgp summary'",
                                module_ignore_errors=True)
        logger.error("BGP summary:\n%s", summary.get('stdout', ''))
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(portchannel),
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
            "Unnumbered BGP session via {} did not establish within {}s. "
            "This could indicate a neighbor compatibility issue — the peer "
            "may not support BGP peering over IPv6 link-local addresses."
            .format(portchannel, WAIT_TIMEOUT))

    logger.info("Unnumbered BGP session established!")

    # Verify routes are received — require the full IPv4 (and IPv6) prefix
    # set previously received on the numbered session. This catches RFC 5549
    # bring-up regressions that establish the session but silently drop
    # advertisements (e.g. `IPv4 local address not available`).
    logger.info("Verify full prefix set is received via unnumbered session")
    expected_v4 = setup_info.get('initial_ipv4_prefixes', 0)
    expected_v6 = setup_info.get('initial_ipv6_prefixes', 0)

    def routes_received_via_unnumbered(duthost, portchannel,
                                       exp_v4, exp_v6):
        """Check that the unnumbered peer on `portchannel` has received the
        full expected prefix count in BOTH IPv4 and IPv6 address-families.

        Requiring both AFs validates that RFC 5549 extended next-hop is
        negotiated (IPv4 NLRI carried with an IPv6 next-hop over the
        link-local session).
        """
        result = duthost.shell("vtysh -c 'show bgp summary json'",
                               module_ignore_errors=True)
        if result['rc'] != 0:
            return False
        try:
            bgp_summary = json.loads(result['stdout'])
            ok = {'ipv4Unicast': False, 'ipv6Unicast': False}
            thresholds = {'ipv4Unicast': max(exp_v4, 1),
                          'ipv6Unicast': max(exp_v6, 1)}
            for af in ok:
                for peer, data in bgp_summary.get(af, {}).get(
                        'peers', {}).items():
                    if portchannel.lower() in peer.lower() \
                            and data.get('pfxRcd', 0) >= thresholds[af]:
                        ok[af] = True
                        break
            return ok['ipv4Unicast'] and ok['ipv6Unicast']
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    pytest_assert(
        wait_until(60, 5, 0, routes_received_via_unnumbered,
                   duthost, portchannel, expected_v4, expected_v6),
        "Unnumbered BGP on {} did not receive the full advertisement set "
        "(expected >={} IPv4 and >={} IPv6 prefixes, as observed on the "
        "numbered baseline). RFC 5549 extended next-hop may not be "
        "negotiated, or peer is dropping updates."
        .format(portchannel, expected_v4, expected_v6))

    # Get the actual route count for logging
    result = duthost.shell("vtysh -c 'show bgp summary json'",
                           module_ignore_errors=True)
    route_count = 0
    if result['rc'] == 0:
        try:
            bgp_summary = json.loads(result['stdout'])
            for af in ['ipv4Unicast', 'ipv6Unicast']:
                for peer, data in bgp_summary.get(af, {}).get(
                        'peers', {}).items():
                    if portchannel.lower() in peer.lower():
                        pfx = data.get('pfxRcd', 0)
                        if pfx > 0:
                            route_count = pfx
                            logger.info("Peer %s (AF=%s): received %d "
                                        "prefixes", peer, af, pfx)
                            break
                if route_count > 0:
                    break
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Could not parse BGP summary JSON: %s", e)
    logger.info("Received %d routes via unnumbered BGP (was %d via "
                "global IP)", route_count, initial_prefixes)

    # Verify session details using JSON output for robustness across FRR versions
    logger.info("Verify session details")
    detail_json = duthost.shell(
        "vtysh -c 'show bgp neighbors {} json'".format(portchannel),
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
                                nbr_key, portchannel)
                    break
            pytest_assert(session_established,
                          "BGP neighbor detail does not show Established state for {}".format(portchannel))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse neighbor JSON, falling back to text check: %s", e)
            detail = duthost.shell(
                "vtysh -c 'show bgp neighbors {}'".format(portchannel),
                module_ignore_errors=True)
            pytest_assert('Established' in detail.get('stdout', ''),
                          "BGP neighbor detail does not show Established state")
    else:
        # JSON form not available, fall back to text
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(portchannel),
            module_ignore_errors=True)
        pytest_assert('Established' in detail.get('stdout', ''),
                      "BGP neighbor detail does not show Established state")
        logger.info("Session detail confirmed: Established via %s", portchannel)
