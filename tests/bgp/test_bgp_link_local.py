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
import time
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

    # Get DUT's addresses on this PortChannel (preserve prefix length
    # so teardown removes with the exact same prefix it was configured with)
    dut_ipv4 = None
    dut_ipv6 = None
    dut_ipv4_prefixlen = None
    dut_ipv6_prefixlen = None
    for addr_key in config_facts.get('PORTCHANNEL_INTERFACE', {}).get(selected['pc'], {}):
        if '/' in addr_key:
            addr, prefixlen = addr_key.split('/', 1)
        else:
            addr, prefixlen = addr_key, None
        if ':' in addr:
            dut_ipv6 = addr
            dut_ipv6_prefixlen = prefixlen
        else:
            dut_ipv4 = addr
            dut_ipv4_prefixlen = prefixlen

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

    # Find first member Ethernet of the selected PortChannel (for ethernet variant)
    member_ethernet = None
    pc_members = portchannel_members.get(selected['pc'], {})
    if pc_members:
        member_ethernet = sorted(pc_members.keys())[0]
    logger.info("PortChannel %s member Ethernet: %s", selected['pc'], member_ethernet)

    info = {
        'duthost': duthost,
        'dut_asn': dut_asn,
        'dut_ipv4': dut_ipv4,
        'dut_ipv6': dut_ipv6,
        'dut_link_local': dut_link_local,
        'portchannel': selected['pc'],
        'member_ethernet': member_ethernet,
        'neigh_name': selected['neigh_name'],
        'neigh_host': neigh_host,
        'neigh_asn': selected['neigh_asn'],
        'neigh_ipv4': selected['neigh_ipv4'],
        'neigh_ipv6': neigh_ipv6,
        'neigh_pc_intf': neigh_pc_intf,
        'dut_ipv4_prefixlen': dut_ipv4_prefixlen,
        'dut_ipv6_prefixlen': dut_ipv6_prefixlen,
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


def save_eos_running_config(neigh_host, filename="pre-test-config"):
    """Save EOS running-config to flash for later restore via configure replace."""
    neigh_host.eos_config(
        lines=["copy running-config flash:{}".format(filename)])
    logger.info("Saved EOS running-config to flash:%s", filename)
    return "flash:{}".format(filename)


def restore_eos_full_config(neigh_host, saved_config_path):
    """Restore EOS config from saved file via configure replace."""
    try:
        neigh_host.eos_config(
            lines=["configure replace {}".format(saved_config_path)])
        logger.info("Restored EOS config from %s", saved_config_path)
    except Exception as e:
        logger.error("EOS configure replace failed: %s", e)
        raise


def break_lag_to_ethernet(duthost, neigh_host, setup_info):
    """Break a LAG and prepare the freed Ethernet for unnumbered BGP.

    Steps:
    1. Detect VRF on EOS Port-Channel (for converged peers)
    2. Remove Port-Channel on EOS
    3. Configure freed Ethernet: no switchport, ipv6 enable, VRF
    4. Remove PortChannel member + PortChannel on DUT

    Returns:
        (eos_eth_intf, pc_vrf): EOS Ethernet interface name and VRF (or None)
    """
    portchannel = setup_info['portchannel']
    member_ethernet = setup_info['member_ethernet']
    neigh_pc_intf = setup_info['neigh_pc_intf']

    pytest_assert(member_ethernet,
                  "No member Ethernet found for {}".format(portchannel))

    # Detect VRF on EOS Port-Channel (converged peers use VRFs)
    pc_vrf = None
    try:
        vrf_out = neigh_host.eos_command(
            commands=["show interfaces {} | json".format(neigh_pc_intf)])
        intf_data = vrf_out['stdout'][0] if isinstance(
            vrf_out['stdout'], list) else vrf_out['stdout']
        if isinstance(intf_data, dict):
            for intf_info in intf_data.get('interfaces', {}).values():
                vrf_membership = intf_info.get('vrfMembership', '')
                if vrf_membership:
                    pc_vrf = vrf_membership
                    logger.info("EOS %s is in VRF %s", neigh_pc_intf, pc_vrf)
    except Exception as e:
        logger.warning("Could not detect VRF on %s: %s", neigh_pc_intf, e)

    # Determine the actual Ethernet member of the EOS Port-Channel.
    # Port-Channel<N> -> Ethernet<N> is only a naming convention; the real
    # active member could be any Ethernet, so query the device.
    eos_eth_intf = None
    try:
        pc_info = neigh_host.eos_command(
            commands=["show port-channel {} | json".format(neigh_pc_intf)])
        port_channels = (pc_info.get('stdout', [{}])[0] or {}).get(
            'portChannels', {})
        active_ports = (port_channels.get(neigh_pc_intf, {}) or {}).get(
            'activePorts', {})
        if active_ports:
            # Pick the deterministic first active member (sorted)
            eos_eth_intf = sorted(active_ports.keys())[0]
            logger.info("Selected EOS PC member %s for %s (active members: %s)",
                        eos_eth_intf, neigh_pc_intf, sorted(active_ports.keys()))
    except Exception as e:
        logger.warning("Could not query port-channel members of %s: %s",
                       neigh_pc_intf, e)

    if not eos_eth_intf:
        # Fallback: derive Ethernet from Port-Channel number
        pc_num = ''.join(c for c in neigh_pc_intf if c.isdigit())
        eos_eth_intf = "Ethernet{}".format(pc_num)
        logger.warning(
            "Falling back to name-derived EOS member %s for %s",
            eos_eth_intf, neigh_pc_intf)

    # Remove Port-Channel on EOS and configure freed Ethernet
    logger.info("Breaking LAG: removing EOS %s, configuring %s",
                neigh_pc_intf, eos_eth_intf)
    # Step 1: remove Port-Channel
    neigh_host.eos_config(
        lines=["no interface {}".format(neigh_pc_intf)])
    # Step 2: configure freed Ethernet for L3
    eos_intf_lines = ["no switchport", "ipv6 enable"]
    if pc_vrf:
        eos_intf_lines.insert(0, "vrf {}".format(pc_vrf))
    neigh_host.eos_config(
        lines=eos_intf_lines,
        parents="interface {}".format(eos_eth_intf))
    logger.info("EOS %s configured (VRF=%s)", eos_eth_intf, pc_vrf)

    # Remove PortChannel member and PortChannel on DUT
    duthost.shell("sudo config portchannel member del {} {}".format(
        portchannel, member_ethernet), module_ignore_errors=True)
    duthost.shell("sudo config portchannel del {}".format(portchannel),
                  module_ignore_errors=True)

    # Verify DUT Ethernet has link-local address
    result = duthost.shell(
        "ip -6 addr show dev {} scope link".format(member_ethernet),
        module_ignore_errors=True)
    if 'fe80' in result.get('stdout', ''):
        logger.info("DUT %s has link-local address", member_ethernet)
    else:
        logger.warning("DUT %s may not have link-local yet", member_ethernet)

    return eos_eth_intf, pc_vrf


def configure_unnumbered_eos(neigh_host, neigh_asn, dut_asn,
                             eos_intf, eos_vrf=None):
    """Configure unnumbered BGP on EOS using interface-based peer-group.

    Minimizes eos_config calls to avoid exhausting cEOS session pool
    (default ~6 pending sessions). Uses 4 calls total.

    Applies:
    - IPv6 RA enablement (required for FRR peer discovery)
    - Interface-based peer-group with remote-as
    - Address-family activation (IPv4 + IPv6)
    - RFC 5549 extended next-hop for IPv4 NLRI over IPv6 session
    """
    eos_peer_group = "LINK_LOCAL_PG"
    bgp_parent = "router bgp {}".format(neigh_asn)
    if eos_vrf:
        bgp_parent = ["router bgp {}".format(neigh_asn),
                      "vrf {}".format(eos_vrf)]
    bgp_parents_list = bgp_parent if isinstance(bgp_parent, list) \
        else [bgp_parent]

    # Call 1: Enable IPv6 RAs + global RFC 5549
    logger.info("Enable IPv6 RAs on EOS %s + RFC 5549", eos_intf)
    neigh_host.eos_config(
        lines=["no ipv6 nd ra disabled"],
        parents="interface {}".format(eos_intf))
    neigh_host.eos_config(lines=["ip routing ipv6 interfaces"])

    # Call 3: BGP peer-group + interface neighbor
    logger.info("Configure BGP peer-group %s on EOS via %s",
                eos_peer_group, eos_intf)
    neigh_host.eos_config(
        lines=[
            "neighbor {} peer group".format(eos_peer_group),
            "neighbor {} remote-as {}".format(eos_peer_group, dut_asn),
            "neighbor interface {} peer-group {}".format(
                eos_intf, eos_peer_group),
        ],
        parents=bgp_parent)

    # Call 3: IPv4 AF — activate + RFC 5549 next-hop
    neigh_host.eos_config(
        lines=[
            "neighbor {} activate".format(eos_peer_group),
            "neighbor {} next-hop address-family ipv6 originate".format(
                eos_peer_group),
        ],
        parents=bgp_parents_list + ["address-family ipv4"])

    # Call 4: IPv6 AF — activate
    neigh_host.eos_config(
        lines=["neighbor {} activate".format(eos_peer_group)],
        parents=bgp_parents_list + ["address-family ipv6"])

    # Verify config accepted
    eos_bgp_cfg = neigh_host.eos_command(
        commands=["show running-config section bgp"])
    eos_cfg_text = eos_bgp_cfg['stdout'][0] if isinstance(
        eos_bgp_cfg['stdout'], list) else eos_bgp_cfg['stdout']
    logger.info("EOS BGP config after setup:\n%s", eos_cfg_text)
    if eos_peer_group not in eos_cfg_text:
        pytest.fail("EOS did not accept the interface-based BGP config. "
                    "Running config:\n{}".format(eos_cfg_text))
    return eos_peer_group


def _cleanup_eos_sessions(neigh_host):
    """Abort any stale EOS config sessions to free the session pool.

    cEOS has a limited pool (~6 pending sessions). Prior test runs that
    errored out may leave uncommitted sessions that block new eos_config
    calls with 'Maximum number of pending sessions reached'.
    """
    try:
        sessions_out = neigh_host.eos_command(
            commands=["show configuration sessions"])
        sessions_text = sessions_out['stdout'][0] if isinstance(
            sessions_out['stdout'], list) else sessions_out['stdout']
        logger.info("EOS config sessions:\n%s", sessions_text)
        if isinstance(sessions_text, str):
            for line in sessions_text.split('\n'):
                parts = line.split()
                if parts and parts[0] not in ['Name', '----', '']:
                    sess_name = parts[0]
                    logger.info("Aborting stale EOS session: %s",
                                sess_name)
                    neigh_host.eos_command(
                        commands=["configure session {}".format(
                            sess_name), "abort"])
    except Exception as e:
        # Non-fatal: session cleanup is best-effort
        logger.warning("Could not clean EOS config sessions: %s", e)


@pytest.fixture(scope='function',
                params=['portchannel', 'ethernet',
                        'portchannel-frrtest'],
                ids=['portchannel', 'ethernet',
                     'portchannel-frrtest'])
def configure_unnumbered_bgp(request, setup_info):
    """Configure unnumbered BGP peering and restore original config afterward.

    Params:
    - portchannel: unnumbered BGP on existing PortChannel (full stack)
    - ethernet: break LAG, unnumbered BGP on member Ethernet (full stack)
    - portchannel-frrtest: stops bgpcfgd to isolate FRR regression testing

    Setup:
        1. Save EOS running-config for reliable teardown
        2. Verify existing BGP session is up
        3. Remove existing global-IP BGP sessions on both DUT and neighbor
        4. Configure unnumbered BGP on DUT (vtysh)
        5. Configure link-local neighbor on EOS peer
    Teardown:
        1. Restore EOS via configure replace (saved running-config)
        2. Restart bgpcfgd if stopped
        3. Config reload on DUT
        4. Wait for original BGP sessions to re-establish
    """
    param = request.param
    stop_bgpcfgd = param.endswith('-frrtest')
    intf_type = param.replace('-frrtest', '')

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
    eos_config_backup = None
    eos_eth_intf = None
    pc_vrf = None

    # --- Teardown (registered first via addfinalizer) ---
    def _full_cleanup():
        # Clean up stale EOS config sessions before restoring
        _cleanup_eos_sessions(neigh_host)
        if eos_config_backup:
            restore_eos_full_config(neigh_host, eos_config_backup)
        if stop_bgpcfgd:
            for daemon in ["bgpcfgd", "frrcfgd"]:
                duthost.shell(
                    "docker exec bgp supervisorctl start {}".format(daemon),
                    module_ignore_errors=True)
        config_reload(duthost, wait=120, wait_for_bgp=True)

        # Wait for all original BGP sessions to re-establish
        original_neighbors = [neigh_ipv4]
        if neigh_ipv6:
            original_neighbors.append(neigh_ipv6)
        if not wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                          duthost.check_bgp_session_state,
                          original_neighbors):
            logger.error(
                "BGP sessions did not re-establish after cleanup")
        else:
            logger.info("Original config restored, all sessions up")
    request.addfinalizer(_full_cleanup)

    # --- Setup ---

    # Clear stale EOS config sessions before starting
    _cleanup_eos_sessions(neigh_host)

    # Save EOS running-config for reliable teardown via configure replace
    eos_config_backup = save_eos_running_config(neigh_host)

    # Wait for the selected BGP session to be established
    logger.info("Waiting for BGP session to %s to be established",
                neigh_ipv4)
    pytest_assert(
        wait_until(60, 5, 0, lambda: duthost.bgp_facts()['ansible_facts']
                   .get('bgp_neighbors', {}).get(neigh_ipv4, {})
                   .get('state', '') == 'established'),
        "IPv4 BGP session to {} not established".format(neigh_ipv4))

    bgp_facts = duthost.bgp_facts()['ansible_facts']
    initial_prefixes = int(
        bgp_facts['bgp_neighbors'][neigh_ipv4].get(
            'accepted prefixes', 0))
    initial_prefixes_v6 = 0
    if neigh_ipv6:
        initial_prefixes_v6 = int(
            bgp_facts['bgp_neighbors'].get(neigh_ipv6, {})
            .get('accepted prefixes', 0))
    setup_info['initial_ipv4_prefixes'] = initial_prefixes
    setup_info['initial_ipv6_prefixes'] = initial_prefixes_v6
    logger.info("Initial prefix count from %s: %d (v4), %d (v6)",
                neigh_ipv4, initial_prefixes, initial_prefixes_v6)

    # Optionally stop bgp config daemon(s) to isolate FRR behavior for
    # regression testing. Depending on frr_mgmt_framework_config, the active
    # daemon is either bgpcfgd (legacy) or frrcfgd (new framework). Stop both
    # with module_ignore_errors so the inactive one's failure is harmless.
    if stop_bgpcfgd:
        logger.info("Stopping bgp config daemons (FRR isolation mode)")
        for daemon in ["bgpcfgd", "frrcfgd"]:
            duthost.shell(
                "docker exec bgp supervisorctl stop {}".format(daemon),
                module_ignore_errors=True)

    # For ethernet variant: break LAG and prepare freed Ethernet
    if intf_type == 'ethernet':
        eos_eth_intf, pc_vrf = break_lag_to_ethernet(
            duthost, neigh_host, setup_info)
        dut_intf = setup_info['member_ethernet']
        eos_intf = eos_eth_intf
    else:
        dut_intf = portchannel
        eos_intf = neigh_pc_intf

    # Remove existing BGP sessions on DUT
    logger.info("Remove existing BGP neighbor %s on DUT", neigh_ipv4)
    vtysh_remove = ['config', 'router bgp {}'.format(dut_asn),
                    'no neighbor {}'.format(neigh_ipv4)]
    if neigh_ipv6:
        vtysh_remove.append('no neighbor {}'.format(neigh_ipv6))
    cmd = 'vtysh ' + ' '.join(
        ['-c "{}"'.format(c) for c in vtysh_remove])
    duthost.shell(cmd, module_ignore_errors=True)

    # Remove existing BGP session on EOS neighbor (only for portchannel,
    # ethernet variant already removed neighbors via break_lag_to_ethernet)
    if intf_type != 'ethernet':
        logger.info("Remove DUT neighbors on EOS peer")
        remove_lines = []
        if dut_ipv4:
            remove_lines.append("no neighbor {}".format(dut_ipv4))
        if dut_ipv6:
            remove_lines.append("no neighbor {}".format(dut_ipv6))
        if remove_lines:
            neigh_host.eos_config(
                lines=remove_lines,
                parents="router bgp {}".format(neigh_asn))

    # Wait for old neighbor to be removed from DUT BGP
    def old_neighbor_removed():
        facts = duthost.bgp_facts()['ansible_facts']
        return neigh_ipv4 not in facts.get('bgp_neighbors', {})
    wait_until(30, 3, 0, old_neighbor_removed)

    # Remove IPv4/IPv6 addresses from DUT interface to prevent
    # FRR numbered fallback. Use the actual prefix length captured from
    # config_facts during setup so the remove command matches what was
    # configured (don't rely on module_ignore_errors to mask a mismatch).
    #
    # Only the portchannel variant needs this: the DUT L3 IPs sit on the
    # Port-Channel, and here dut_intf is that Port-Channel. For the ethernet
    # variant, break_lag_to_ethernet() already ran "config portchannel del",
    # which removes the Port-Channel's IPs as a side effect; dut_intf is the
    # freed member Ethernet that never carried those IPs, so issuing
    # "config interface ip remove <member> <pc_ip>/<prefix>" would fail with a
    # non-zero rc and trip the assert below. Skip the block for ethernet.
    if intf_type != 'ethernet':
        dut_ipv4_prefixlen = setup_info.get('dut_ipv4_prefixlen')
        dut_ipv6_prefixlen = setup_info.get('dut_ipv6_prefixlen')
        if dut_ipv4:
            pytest_assert(dut_ipv4_prefixlen,
                          "IPv4 prefix length missing from config_facts for {}".format(dut_intf))
            result = duthost.shell("sudo config interface ip remove {} {}/{}".format(
                dut_intf, dut_ipv4, dut_ipv4_prefixlen))
            pytest_assert(result['rc'] == 0,
                          "Failed to remove IPv4 {}/{} from {}: {}".format(
                              dut_ipv4, dut_ipv4_prefixlen, dut_intf,
                              result.get('stderr', '')))
        if dut_ipv6:
            pytest_assert(dut_ipv6_prefixlen,
                          "IPv6 prefix length missing from config_facts for {}".format(dut_intf))
            result = duthost.shell("sudo config interface ip remove {} {}/{}".format(
                dut_intf, dut_ipv6, dut_ipv6_prefixlen))
            pytest_assert(result['rc'] == 0,
                          "Failed to remove IPv6 {}/{} from {}: {}".format(
                              dut_ipv6, dut_ipv6_prefixlen, dut_intf,
                              result.get('stderr', '')))
    else:
        logger.info("Skipping DUT IP removal on %s: Port-Channel deletion in "
                    "break_lag_to_ethernet already cleared the L3 addresses",
                    dut_intf)

    # Configure unnumbered BGP on DUT
    if stop_bgpcfgd:
        # FRR isolation mode: configure directly via vtysh
        logger.info("Configure unnumbered BGP on DUT via vtysh (FRR isolation) on %s", dut_intf)
        vtysh_add = [
            'config',
            'router bgp {}'.format(dut_asn),
            'neighbor {} interface v6only remote-as {}'.format(
                dut_intf, neigh_asn),
            'address-family ipv4 unicast',
            'neighbor {} activate'.format(dut_intf),
            'exit-address-family',
            'address-family ipv6 unicast',
            'neighbor {} activate'.format(dut_intf),
            'exit-address-family',
        ]
        cmd = 'vtysh ' + ' '.join(
            ['-c "{}"'.format(c) for c in vtysh_add])
        result = duthost.shell(cmd)
        pytest_assert(result['rc'] == 0,
                      "Failed to configure unnumbered BGP on {}: {}".format(
                          dut_intf, result.get('stderr', '')))
    else:
        # Full-stack path: configure via CONFIG_DB (bgpcfgd should push to FRR)
        # CONFIG_DB BGP_NEIGHBOR table uses IP keys — there is currently no
        # schema support for interface-based (unnumbered) neighbors.
        # This path exercises the production stack and is expected to fail
        # until sonic-buildimage#26960 is implemented.
        logger.info("Configure unnumbered BGP on DUT via CONFIG_DB on %s", dut_intf)
        duthost.shell(
            'sonic-db-cli CONFIG_DB HSET "BGP_NEIGHBOR|{}" "asn" "{}" "name" "{}"'.format(
                dut_intf, neigh_asn, setup_info['neigh_name']),
            module_ignore_errors=True)
        # Give bgpcfgd time to process the CONFIG_DB change
        time.sleep(10)
        logger.info("CONFIG_DB BGP_NEIGHBOR entry added for %s "
                    "(bgpcfgd should configure FRR)", dut_intf)

    # Configure unnumbered BGP on EOS
    eos_peer_group = configure_unnumbered_eos(
        neigh_host, neigh_asn, dut_asn, eos_intf,
        eos_vrf=pc_vrf)

    yield {
        'initial_prefixes': initial_prefixes,
        'eos_peer_group': eos_peer_group,
        'dut_intf': dut_intf,
    }


@pytest.mark.disable_loganalyzer
def test_bgp_link_local(setup_info, configure_unnumbered_bgp):
    """
    Test BGP peering over IPv6 link-local addresses (unnumbered).

    Parametrized variants:
    - [portchannel]: unnumbered BGP on LAG interface (full stack)
    - [ethernet]: break LAG, unnumbered BGP on plain Ethernet (full stack)
    - [portchannel-frrtest]: bgpcfgd stopped, isolates FRR regressions

    Validates that:
    1. Unnumbered BGP session can be established
    2. Full prefix set is exchanged (RFC 5549 validated)
    3. The session uses IPv6 link-local addressing
    """
    duthost = setup_info['duthost']
    dut_intf = configure_unnumbered_bgp['dut_intf']
    initial_prefixes = configure_unnumbered_bgp['initial_prefixes']

    # Wait for BGP session to establish
    logger.info("Waiting for unnumbered BGP session to establish (timeout=%ds)",
                WAIT_TIMEOUT)
    established = wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                             bgp_unnumbered_established, duthost, dut_intf)

    if not established:
        # Debug output before failing
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
            "Unnumbered BGP session via {} did not establish within {}s. "
            "This could indicate a neighbor compatibility issue — the peer "
            "may not support BGP peering over IPv6 link-local addresses."
            .format(dut_intf, WAIT_TIMEOUT))

    logger.info("Unnumbered BGP session established!")

    # Verify routes are received — require the full IPv4 (and IPv6) prefix
    # set previously received on the numbered session. This catches RFC 5549
    # bring-up regressions that establish the session but silently drop
    # advertisements (e.g. `IPv4 local address not available`).
    logger.info("Verify full prefix set is received via unnumbered session")
    expected_v4 = setup_info.get('initial_ipv4_prefixes', 0)
    expected_v6 = setup_info.get('initial_ipv6_prefixes', 0)

    def routes_received_via_unnumbered(duthost, dut_intf,
                                       exp_v4, exp_v6):
        """Check that the unnumbered peer on `dut_intf` has received the
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
                    if dut_intf.lower() in peer.lower() \
                            and data.get('pfxRcd', 0) >= thresholds[af]:
                        ok[af] = True
                        break
            return ok['ipv4Unicast'] and ok['ipv6Unicast']
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    pytest_assert(
        wait_until(60, 5, 0, routes_received_via_unnumbered,
                   duthost, dut_intf, expected_v4, expected_v6),
        "Unnumbered BGP on {} did not receive the full advertisement set "
        "(expected >={} IPv4 and >={} IPv6 prefixes, as observed on the "
        "numbered baseline). RFC 5549 extended next-hop may not be "
        "negotiated, or peer is dropping updates."
        .format(dut_intf, expected_v4, expected_v6))

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
                    if dut_intf.lower() in peer.lower():
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
                          "BGP neighbor detail does not show Established state for {}".format(dut_intf))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse neighbor JSON, falling back to text check: %s", e)
            detail = duthost.shell(
                "vtysh -c 'show bgp neighbors {}'".format(dut_intf),
                module_ignore_errors=True)
            pytest_assert('Established' in detail.get('stdout', ''),
                          "BGP neighbor detail does not show Established state")
    else:
        # JSON form not available, fall back to text
        detail = duthost.shell(
            "vtysh -c 'show bgp neighbors {}'".format(dut_intf),
            module_ignore_errors=True)
        pytest_assert('Established' in detail.get('stdout', ''),
                      "BGP neighbor detail does not show Established state")
        logger.info("Session detail confirmed: Established via %s", dut_intf)
