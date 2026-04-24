"""
Tests for BGP peering over IPv6 link-local addresses (unnumbered BGP).

This test validates that SONiC can establish BGP sessions using interface-based
(unnumbered) peering, which uses IPv6 link-local addresses for session setup.

Two scenarios are tested via parametrization:
1. Unnumbered BGP over a PortChannel (LAG) interface
2. Unnumbered BGP over a plain Ethernet interface (LAG broken)

Addresses: https://github.com/sonic-net/sonic-mgmt/issues/18431
           https://github.com/sonic-net/sonic-mgmt/issues/24134
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
    """Find the neighbor's interface that has the given IP.

    Args:
        neigh_host: Neighbor host object (EosHost)
        neigh_ipv4: IPv4 address to search for

    Returns:
        Interface name (e.g. 'Port-Channel1', 'Ethernet1') or None
    """
    try:
        result = neigh_host.eos_command(
            commands=["show ip interface brief | json"])
        intf_data = result['stdout'][0] if isinstance(
            result['stdout'], list) else result['stdout']
        if isinstance(intf_data, dict):
            for intf_name, intf_info in intf_data.get('interfaces', {}).items():
                if not (intf_name.startswith('Ethernet')
                        or intf_name.startswith('Port-Channel')):
                    continue
                ip_info = intf_info.get('interfaceAddress', {})
                if isinstance(ip_info, dict):
                    addr = ip_info.get('ipAddr', {}).get('address', '')
                    if addr == neigh_ipv4:
                        return intf_name
                elif isinstance(ip_info, list):
                    for entry in ip_info:
                        addr = entry.get('primaryIp', {}).get(
                            'address', '')
                        if addr == neigh_ipv4:
                            return intf_name
    except Exception as e:
        logger.warning("Could not query neighbor interfaces: %s", e)
    return None


@pytest.fixture(scope='module')
def setup_info(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """Gather setup information for the link-local BGP test.

    Finds a PortChannel-based BGP neighbor and collects all the info needed
    to test unnumbered BGP on both the PortChannel and its member Ethernet.
    """
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
        device_metadata = config_facts_tmp.get(
            'DEVICE_METADATA', {}).get('localhost', {})
        dut_asn = device_metadata.get('bgp_asn')
        if not dut_asn:
            pytest.skip("dut_asn not found in configuration")

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL', {})
    portchannel_members = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    pc_intf_table = config_facts.get('PORTCHANNEL_INTERFACE', {})

    # Build map: PortChannel -> (neighbor_name, member_ethernet)
    pc_to_info = {}
    for pc_name in portchannels:
        if pc_name not in portchannel_members:
            continue
        members = list(portchannel_members[pc_name].keys())
        for member_intf in members:
            if member_intf in dev_nbrs:
                pc_to_info[pc_name] = {
                    'neigh_name': dev_nbrs[member_intf]['name'],
                    'members': members,
                }
                break

    # Find a PortChannel with an established IPv4 BGP neighbor
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    selected = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if ':' in neigh_ip:
            continue
        bgp_state = bgp_facts.get('bgp_neighbors', {}).get(
            neigh_ip, {}).get('state', '')
        neigh_name = neigh_info.get('name', '')
        if bgp_state != 'established':
            continue
        neigh_asn = neigh_info.get('asn', '')
        for pc_name, pc_info in pc_to_info.items():
            if (pc_info['neigh_name'] == neigh_name
                    and neigh_name in nbrhosts):
                selected = {
                    'pc_intf': pc_name,
                    'member_ethernet': pc_info['members'][0],
                    'neigh_name': neigh_name,
                    'neigh_ipv4': neigh_ip,
                    'neigh_asn': neigh_asn,
                }
                break
        if selected:
            break

    if not selected:
        pytest.skip("No PortChannel BGP neighbor found")

    pc_intf = selected['pc_intf']

    # Get IPv6 neighbor address
    neigh_ipv6 = None
    for neigh_ip, neigh_info in bgp_neighbors.items():
        if (neigh_info.get('name', '') == selected['neigh_name']
                and ':' in neigh_ip):
            neigh_ipv6 = neigh_ip
            break

    # Get DUT's addresses on the PortChannel
    dut_ipv4 = None
    dut_ipv6 = None
    addr_table = pc_intf_table.get(pc_intf, {})
    for addr_key in addr_table:
        addr = addr_key.split('/')[0] if '/' in addr_key else addr_key
        if ':' in addr:
            dut_ipv6 = addr
        else:
            dut_ipv4 = addr

    # Get DUT's link-local on the PortChannel
    result = duthost.shell(
        "ip -6 addr show dev {} scope link".format(pc_intf))
    dut_link_local = None
    for line in result['stdout'].split('\n'):
        if 'inet6 fe80' in line.strip():
            dut_link_local = line.strip().split()[1].split('/')[0]
            break
    pytest_assert(dut_link_local,
                  "No link-local address on {}".format(pc_intf))

    # Find EOS neighbor's interface
    neigh_host = nbrhosts[selected['neigh_name']]['host']
    neigh_intf = find_neigh_eos_intf(neigh_host, selected['neigh_ipv4'])
    if not neigh_intf:
        pc_num = ''.join(c for c in pc_intf if c.isdigit())
        for candidate in ["Port-Channel{}".format(pc_num),
                          "Port-Channel1",
                          "Port-Channel{}".format(
                              int(pc_num) % 100 if pc_num else 1)]:
            try:
                neigh_host.eos_command(
                    commands=["show interfaces {}".format(candidate)])
                neigh_intf = candidate
                break
            except Exception:
                continue
    pytest_assert(neigh_intf,
                  "Could not determine neighbor's interface")

    # Get DUT IP prefixes with masks for later re-assignment
    dut_ipv4_prefix = None
    dut_ipv6_prefix = None
    for addr_key in addr_table:
        if '/' not in addr_key:
            continue
        if ':' in addr_key:
            dut_ipv6_prefix = addr_key
        else:
            dut_ipv4_prefix = addr_key

    info = {
        'duthost': duthost,
        'dut_asn': dut_asn,
        'dut_ipv4': dut_ipv4,
        'dut_ipv6': dut_ipv6,
        'dut_ipv4_prefix': dut_ipv4_prefix,
        'dut_ipv6_prefix': dut_ipv6_prefix,
        'dut_link_local': dut_link_local,
        'pc_intf': pc_intf,
        'member_ethernet': selected['member_ethernet'],
        'neigh_name': selected['neigh_name'],
        'neigh_host': neigh_host,
        'neigh_asn': selected['neigh_asn'],
        'neigh_ipv4': selected['neigh_ipv4'],
        'neigh_ipv6': neigh_ipv6,
        'neigh_intf': neigh_intf,
    }

    logger.info(
        "Setup: DUT %s (%s) <-> %s (%s) via %s (member %s) / %s",
        dut_ipv4, dut_link_local, selected['neigh_name'],
        selected['neigh_ipv4'], pc_intf,
        selected['member_ethernet'], neigh_intf)

    return info


def bgp_unnumbered_established(duthost, intf_name):
    """Check if unnumbered BGP session via an interface is established.

    Verifies that the session uses link-local (fe80::) addressing,
    not IPv4 fallback. FRR may ignore 'v6only' and fall back to IPv4
    on interfaces that have an IPv4 address — that's a false positive.
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
                if intf_name.lower() in peer_key.lower():
                    logger.info(
                        "Candidate peer: %s (AF=%s, pfxRcd=%s)",
                        peer_key, af, peer_data.get('pfxRcd', 0))
                    # Verify it's using link-local, not IPv4 fallback
                    neigh_detail = duthost.shell(
                        "vtysh -c 'show bgp neighbors {} json'"
                        .format(intf_name),
                        module_ignore_errors=True)
                    if neigh_detail['rc'] == 0:
                        try:
                            nd = json.loads(neigh_detail['stdout'])
                            # FRR nests under interface or IP key
                            for key, info in nd.items():
                                remote = info.get(
                                    'bgpNeighborAddr', '')
                                if remote.startswith('fe80'):
                                    logger.info(
                                        "Confirmed link-local peer:"
                                        " %s remote=%s",
                                        peer_key, remote)
                                    return True
                                logger.warning(
                                    "Peer %s uses %s (not "
                                    "link-local) — IPv4 fallback",
                                    peer_key, remote)
                        except (json.JSONDecodeError, KeyError):
                            # Can't parse neighbor detail; fall through
                            # to return False below
                            pass
                    # If we can't verify, don't accept it
                    return False
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to parse BGP summary JSON: %s", e)
    return False


def debug_bgp_state(duthost, intf_name, setup_info):
    """Dump debug info when BGP session fails to establish."""
    summary = duthost.shell(
        "vtysh -c 'show bgp summary'", module_ignore_errors=True)
    logger.error("BGP summary:\n%s", summary.get('stdout', ''))

    detail = duthost.shell(
        "vtysh -c 'show bgp neighbors {}'".format(intf_name),
        module_ignore_errors=True)
    logger.error("Neighbor %s detail:\n%s",
                 intf_name, detail.get('stdout', ''))

    frr_run = duthost.shell(
        "vtysh -c 'show running-config bgpd'",
        module_ignore_errors=True)
    logger.error("FRR running config:\n%s", frr_run.get('stdout', ''))

    try:
        neigh_host = setup_info['neigh_host']
        eos_bgp = neigh_host.eos_command(
            commands=["show ip bgp summary"])
        eos_out = eos_bgp['stdout'][0] if isinstance(
            eos_bgp['stdout'], list) else eos_bgp['stdout']
        logger.error("EOS BGP summary:\n%s", eos_out)

        eos_run = neigh_host.eos_command(
            commands=["show running-config section bgp"])
        eos_run_out = eos_run['stdout'][0] if isinstance(
            eos_run['stdout'], list) else eos_run['stdout']
        logger.error("EOS BGP running config:\n%s", eos_run_out)
    except Exception as e:
        logger.error("Could not get EOS BGP info: %s", e)


def configure_unnumbered_dut(duthost, dut_asn, dut_intf, neigh_asn):
    """Configure unnumbered BGP neighbor on DUT via vtysh (FRR direct)."""
    vtysh_cmds = [
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
        ['-c "{}"'.format(c) for c in vtysh_cmds])
    result = duthost.shell(cmd)
    pytest_assert(result['rc'] == 0,
                  "Failed to configure unnumbered BGP on {}: {}".format(
                      dut_intf, result.get('stderr', '')))

    # Log FRR running config for debugging
    frr_cfg = duthost.shell(
        "vtysh -c 'show running-config bgpd'",
        module_ignore_errors=True)
    logger.info("FRR running config after unnumbered setup on %s:\n%s",
                dut_intf, frr_cfg.get('stdout', ''))


def configure_unnumbered_dut_configdb(
        duthost, dut_asn, dut_intf, neigh_asn):
    """Configure unnumbered BGP neighbor on DUT via CONFIG_DB (production path).

    CONFIG_DB BGP_NEIGHBOR uses IP addresses as keys — there is no schema
    for interface-based (unnumbered) neighbors. This function attempts the
    configuration to validate the production path, but it is expected to
    fail until bgpcfgd gains unnumbered BGP support (sonic-buildimage#26960).
    """
    # CONFIG_DB BGP_NEIGHBOR expects IP key; use interface name anyway
    # to test if bgpcfgd can handle it (it currently cannot).
    neighbor_entry = {
        "asn": str(neigh_asn),
        "name": dut_intf,
        "admin_status": "up",
    }
    entry_json = json.dumps(neighbor_entry)
    duthost.shell(
        "sonic-db-cli CONFIG_DB HMSET 'BGP_NEIGHBOR|{}' {}".format(
            dut_intf,
            ' '.join('{} {}'.format(k, v)
                     for k, v in neighbor_entry.items())),
        module_ignore_errors=True)
    logger.info(
        "CONFIG_DB BGP_NEIGHBOR|%s set: %s (bgpcfgd may not process this)",
        dut_intf, entry_json)

    # Log FRR running config to see if bgpcfgd picked it up
    import time
    time.sleep(10)  # Give bgpcfgd time to process
    frr_cfg = duthost.shell(
        "vtysh -c 'show running-config bgpd'",
        module_ignore_errors=True)
    logger.info("FRR running config after CONFIG_DB setup on %s:\n%s",
                dut_intf, frr_cfg.get('stdout', ''))


def configure_unnumbered_eos(neigh_host, neigh_asn, dut_asn, neigh_intf,
                             eos_vrf=None):
    """Configure interface-based BGP neighbor on EOS peer."""
    eos_peer_group = "LINK_LOCAL_PG"
    # In converged mode, BGP config lives under a VRF context
    if eos_vrf:
        bgp_parent = "router bgp {} vrf {}".format(neigh_asn, eos_vrf)
    else:
        bgp_parent = "router bgp {}".format(neigh_asn)
    neigh_host.eos_config(
        lines=[
            "neighbor {} peer group".format(eos_peer_group),
            "neighbor {} remote-as {}".format(eos_peer_group, dut_asn),
            "neighbor interface {} peer-group {}".format(
                neigh_intf, eos_peer_group),
        ],
        parents=bgp_parent)

    for af in ["ipv4", "ipv6"]:
        neigh_host.eos_config(
            lines=["neighbor {} activate".format(eos_peer_group)],
            parents=[bgp_parent,
                     "address-family {}".format(af)])

    # Verify config was accepted
    eos_bgp_cfg = neigh_host.eos_command(
        commands=["show running-config section bgp"])
    eos_cfg_text = eos_bgp_cfg['stdout'][0] if isinstance(
        eos_bgp_cfg['stdout'], list) else eos_bgp_cfg['stdout']
    logger.info("EOS BGP config after setup:\n%s", eos_cfg_text)
    pytest_assert(eos_peer_group in eos_cfg_text,
                  "EOS did not accept interface-based BGP config")
    return eos_peer_group


def remove_numbered_bgp(duthost, neigh_host, dut_asn, neigh_asn,
                        neigh_ipv4, neigh_ipv6, dut_ipv4, dut_ipv6):
    """Remove existing numbered BGP sessions on both DUT and EOS.

    Uses direct sonic-db-cli + vtysh instead of config commands to
    avoid config reconciliation side effects.
    """
    # Remove from CONFIG_DB
    duthost.shell(
        'sonic-db-cli CONFIG_DB DEL "BGP_NEIGHBOR|{}"'.format(neigh_ipv4),
        module_ignore_errors=True)
    if neigh_ipv6:
        duthost.shell(
            'sonic-db-cli CONFIG_DB DEL "BGP_NEIGHBOR|{}"'.format(
                neigh_ipv6),
            module_ignore_errors=True)

    # Remove from FRR
    vtysh_rm = ['config', 'router bgp {}'.format(dut_asn),
                'no neighbor {}'.format(neigh_ipv4)]
    if neigh_ipv6:
        vtysh_rm.append('no neighbor {}'.format(neigh_ipv6))
    cmd = 'vtysh ' + ' '.join(
        ['-c "{}"'.format(c) for c in vtysh_rm])
    duthost.shell(cmd, module_ignore_errors=True)

    # Remove on EOS
    remove_lines = []
    if dut_ipv4:
        remove_lines.append("no neighbor {}".format(dut_ipv4))
    if dut_ipv6:
        remove_lines.append("no neighbor {}".format(dut_ipv6))
    if remove_lines:
        neigh_host.eos_config(
            lines=remove_lines,
            parents="router bgp {}".format(neigh_asn))

    # Wait for removal
    def old_neighbor_gone():
        facts = duthost.bgp_facts()['ansible_facts']
        return neigh_ipv4 not in facts.get('bgp_neighbors', {})
    wait_until(30, 3, 0, old_neighbor_gone)


def restore_eos_bgp_config(neigh_host, neigh_asn):
    """Restore EOS BGP config by removing unnumbered and re-adding numbered.

    Since 'configure replace startup-config' fails on cEOS (deprecated
    'ipv6 nd ra suppress' in startup-config), we surgically remove
    the unnumbered config and re-add numbered neighbors from the saved
    backup captured before modifications.
    """
    # This is now handled by the full EOS restore in teardown.
    # Kept as a no-op for interface compatibility.
    pass


def restore_eos_full_config(neigh_host, saved_config_path):
    """Restore EOS to pre-test state using configure replace.

    Uses a saved copy of the running-config (captured before test
    modifications) to atomically restore the full EOS config.
    Running-config avoids deprecated syntax issues in startup-config.
    Waits for EOS BGP to re-establish after restore.
    """
    try:
        neigh_host.eos_command(commands=[
            "configure replace flash:{}".format(saved_config_path)
        ])
        logger.info("EOS config replaced from flash:%s",
                    saved_config_path)
    except Exception as e:
        logger.error("EOS config restore failed: %s", e)
        return

    # Wait for EOS BGP sessions to re-establish
    def eos_bgp_established():
        try:
            result = neigh_host.eos_command(
                commands=["show ip bgp summary | json"])
            bgp_data = result['stdout'][0] if isinstance(
                result['stdout'], list) else result['stdout']
            if isinstance(bgp_data, dict):
                peers = bgp_data.get('vrfs', {}).get(
                    'default', {}).get('peers', {})
                return all(
                    p.get('peerState') == 'Established'
                    for p in peers.values())
        except Exception:
            # EOS command or parsing failed; treat as not established
            pass
        return False

    if wait_until(120, 10, 0, eos_bgp_established):
        logger.info("EOS BGP sessions re-established after restore")
    else:
        logger.warning("EOS BGP sessions did not re-establish "
                       "within 120s after config restore")


def save_eos_running_config(neigh_host, filename="pre-test-config"):
    """Save EOS running-config to flash for later configure replace."""
    try:
        neigh_host.eos_command(commands=[
            "copy running-config flash:{}".format(filename)
        ])
        logger.info("Saved EOS running-config to flash:%s", filename)
        return filename
    except Exception as e:
        logger.error("Failed to save EOS running-config: %s", e)
        return None


def cleanup_eos_unnumbered(neigh_host, neigh_asn, dut_asn,
                           neigh_intf, dut_ipv4, dut_ipv6):
    """Remove unnumbered config from EOS and restore numbered neighbors."""
    eos_peer_group = "LINK_LOCAL_PG"
    try:
        neigh_host.eos_config(
            lines=["no neighbor interface {}".format(neigh_intf)],
            parents="router bgp {}".format(neigh_asn))
        for af in ["ipv4", "ipv6"]:
            neigh_host.eos_config(
                lines=[
                    "no neighbor {} activate".format(eos_peer_group)],
                parents=["router bgp {}".format(neigh_asn),
                         "address-family {}".format(af)])
        neigh_host.eos_config(
            lines=[
                "no neighbor {} peer group".format(eos_peer_group)],
            parents="router bgp {}".format(neigh_asn))
        restore_lines = []
        if dut_ipv4:
            restore_lines.append(
                "neighbor {} remote-as {}".format(dut_ipv4, dut_asn))
        if dut_ipv6:
            restore_lines.append(
                "neighbor {} remote-as {}".format(dut_ipv6, dut_asn))
        if restore_lines:
            neigh_host.eos_config(
                lines=restore_lines,
                parents="router bgp {}".format(neigh_asn))
    except Exception as e:
        logger.error("EOS cleanup failed: %s", e)


def break_lag_to_ethernet(duthost, neigh_host, setup_info):
    """Break PortChannel and move IPs to the member Ethernet interface.

    Returns the EOS Ethernet interface name to use for peering.
    """
    pc_intf = setup_info['pc_intf']
    eth_intf = setup_info['member_ethernet']
    dut_ipv4_prefix = setup_info['dut_ipv4_prefix']
    dut_ipv6_prefix = setup_info['dut_ipv6_prefix']
    neigh_intf = setup_info['neigh_intf']

    logger.info("Breaking %s: removing %s for direct Ethernet peering",
                pc_intf, eth_intf)
    duthost.shell(
        "sudo config portchannel member del {} {}".format(
            pc_intf, eth_intf))
    # Remove IPs from PortChannel (no longer has a member)
    if dut_ipv4_prefix:
        duthost.shell(
            "sudo config interface ip remove {} {}".format(
                pc_intf, dut_ipv4_prefix),
            module_ignore_errors=True)
    if dut_ipv6_prefix:
        duthost.shell(
            "sudo config interface ip remove {} {}".format(
                pc_intf, dut_ipv6_prefix),
            module_ignore_errors=True)
    # Do NOT add IPs to Ethernet — unnumbered BGP should use
    # link-local only. Adding IPv4 would allow FRR to fall back
    # to numbered peering, masking the v6only bug.

    # Wait for link-local address on Ethernet
    def _has_link_local():
        out = duthost.shell(
            "ip -6 addr show {} scope link".format(eth_intf),
            module_ignore_errors=True)['stdout']
        return 'inet6 fe80' in out

    pytest_assert(
        wait_until(30, 2, 0, _has_link_local),
        "No link-local on {} after LAG breakout".format(eth_intf))

    # EOS side: derive member Ethernet from Port-Channel.
    # Parse running-config to find which Ethernet has channel-group
    # for this Port-Channel (works on all cEOS versions).
    pc_num = neigh_intf.replace("Port-Channel", "")
    eos_run = neigh_host.eos_command(
        commands=["show running-config"])
    eos_full_cfg = eos_run['stdout'][0] if isinstance(
        eos_run['stdout'], list) else eos_run['stdout']
    eos_eth_intf = None
    current_intf = None
    for line in eos_full_cfg.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface Ethernet"):
            current_intf = stripped.split()[-1]
        elif (current_intf and
              "channel-group {}".format(pc_num) in stripped):
            eos_eth_intf = current_intf
            break
        elif stripped.startswith("interface ") and current_intf:
            current_intf = None
    if not eos_eth_intf:
        eos_eth_intf = "Ethernet1"
        logger.warning("Could not derive EOS member, falling back to %s",
                       eos_eth_intf)
    logger.info("Derived EOS member interface: %s from %s",
                eos_eth_intf, neigh_intf)

    # Detect VRF assignment on Port-Channel before removing it
    # (converged peers use VRFs like ARISTA01T1)
    pc_vrf = None
    pc_cfg_result = neigh_host.eos_command(
        commands=["show running-config interfaces {}".format(neigh_intf)])
    pc_cfg_out = pc_cfg_result['stdout'][0] if isinstance(
        pc_cfg_result['stdout'], list) else pc_cfg_result['stdout']
    for line in str(pc_cfg_out).splitlines():
        stripped = line.strip()
        if stripped.startswith("vrf "):
            pc_vrf = stripped.split()[1]
            break
    if pc_vrf:
        logger.info("Port-Channel %s is in VRF %s (converged mode)",
                    neigh_intf, pc_vrf)

    logger.info("Configuring EOS %s for direct Ethernet peering",
                eos_eth_intf)
    neigh_host.eos_config(
        lines=["no interface {}".format(neigh_intf)],
        module_ignore_errors=True)
    # After removing Port-Channel, EOS Ethernet reverts to switchport
    # mode (cEOS default). Must configure as routed port for L3 peering.
    eos_intf_lines = [
        "no switchport",
        "ipv6 enable",
    ]
    if pc_vrf:
        # Assign Ethernet to the same VRF as the original Port-Channel
        # so EOS BGP (configured under this VRF) can peer over it.
        eos_intf_lines.insert(0, "vrf {}".format(pc_vrf))
    neigh_host.eos_config(
        lines=eos_intf_lines,
        parents="interface {}".format(eos_eth_intf),
        module_ignore_errors=True)

    # Verify EOS Ethernet has link-local address
    eos_ll_result = neigh_host.eos_command(
        commands=["show ipv6 interface {} brief".format(eos_eth_intf)])
    eos_ll_out = eos_ll_result['stdout'][0] if isinstance(
        eos_ll_result['stdout'], list) else eos_ll_result['stdout']
    logger.info("EOS %s IPv6 status:\n%s", eos_eth_intf, eos_ll_out)

    # Get EOS link-local for ping test
    eos_ll_detail = neigh_host.eos_command(
        commands=["show ipv6 interface {}".format(eos_eth_intf)])
    eos_ll_detail_out = eos_ll_detail['stdout'][0] if isinstance(
        eos_ll_detail['stdout'], list) else eos_ll_detail['stdout']
    logger.info("EOS %s IPv6 detail:\n%s",
                eos_eth_intf, eos_ll_detail_out)

    # Also check DUT side link-local
    dut_ll = duthost.shell(
        "ip -6 addr show {} scope link".format(eth_intf),
        module_ignore_errors=True)
    logger.info("DUT %s link-local:\n%s",
                eth_intf, dut_ll.get('stdout', ''))

    # Try ping from DUT to EOS link-local (parse fe80 from EOS output)
    eos_ll_addr = None
    for line in str(eos_ll_detail_out).splitlines():
        if 'fe80' in line.lower():
            # Extract fe80::xxx address
            for token in line.split():
                if token.lower().startswith('fe80'):
                    eos_ll_addr = token.split('/')[0]
                    break
            if eos_ll_addr:
                break
    if eos_ll_addr:
        ping_result = duthost.shell(
            "ping6 -c 3 -I {} {}".format(eth_intf, eos_ll_addr),
            module_ignore_errors=True)
        logger.info("Ping DUT %s -> EOS %s (%s): rc=%d\n%s",
                    eth_intf, eos_eth_intf, eos_ll_addr,
                    ping_result['rc'],
                    ping_result.get('stdout', ''))
    else:
        logger.warning("No link-local found on EOS %s — cannot ping",
                       eos_eth_intf)

    return eos_eth_intf, pc_vrf


def restore_lag_on_eos(neigh_host, neigh_intf):
    """Restore EOS Port-Channel after LAG breakout test."""
    try:
        if "Port-Channel" in neigh_intf:
            neigh_host.eos_config(
                lines=[
                    "interface {}".format(neigh_intf),
                    "channel-group 1 mode active",
                ],
                module_ignore_errors=True)
    except Exception as e:
        logger.warning("EOS LAG restore attempt: %s", e)


def verify_bgp_established(duthost, intf_name, setup_info):
    """Wait for unnumbered BGP to establish; dump debug on failure."""
    logger.info(
        "Waiting for unnumbered BGP on %s to establish (timeout=%ds)",
        intf_name, WAIT_TIMEOUT)
    established = wait_until(
        WAIT_TIMEOUT, POLL_INTERVAL, 0,
        bgp_unnumbered_established, duthost, intf_name)

    if not established:
        debug_bgp_state(duthost, intf_name, setup_info)
        pytest.fail(
            "Unnumbered BGP session via {} did not establish within {}s"
            .format(intf_name, WAIT_TIMEOUT))

    logger.info("Unnumbered BGP session on %s established!", intf_name)


def verify_routes_received(duthost, intf_name):
    """Verify routes are received over the unnumbered session."""
    def routes_received():
        result = duthost.shell(
            "vtysh -c 'show bgp summary json'",
            module_ignore_errors=True)
        if result['rc'] != 0:
            return False
        try:
            bgp_summary = json.loads(result['stdout'])
            for af in ['ipv4Unicast', 'ipv6Unicast']:
                for peer, data in bgp_summary.get(
                        af, {}).get('peers', {}).items():
                    if (intf_name.lower() in peer.lower()
                            and data.get('pfxRcd', 0) > 0):
                        return True
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    pytest_assert(
        wait_until(30, 5, 0, routes_received),
        "No routes received via unnumbered BGP on {}".format(intf_name))
    logger.info("Routes received via unnumbered BGP on %s", intf_name)


@pytest.fixture(scope='function',
                params=['portchannel', 'ethernet',
                        'portchannel-frrtest'],
                ids=['portchannel', 'ethernet',
                     'portchannel-frrtest'])
def configure_unnumbered_bgp(request, setup_info):
    """Configure unnumbered BGP on a DUT interface.

    Params:
    - portchannel: unnumbered BGP on existing PortChannel (full stack)
    - ethernet: break LAG, unnumbered BGP on member Ethernet (full stack)
    - portchannel-frrtest: stops bgpcfgd to isolate FRR regression testing

    Steps:
    1. Wait for baseline numbered BGP to be established
    2. Remove existing numbered BGP sessions
    3. Remove IPv4/IPv6 addresses from test interface
    4. (ethernet only) Break LAG, configure EOS Ethernet as routed port
    5. Configure unnumbered BGP on DUT and EOS
    6. Yield the test interface name
    7. Teardown: restore EOS via configure replace, config_reload DUT
    """
    param = request.param
    stop_bgpcfgd = param.endswith('-frrtest')
    intf_type = param.replace('-frrtest', '')
    duthost = setup_info['duthost']
    neigh_host = setup_info['neigh_host']
    dut_asn = setup_info['dut_asn']
    neigh_asn = setup_info['neigh_asn']
    neigh_ipv4 = setup_info['neigh_ipv4']
    neigh_ipv6 = setup_info['neigh_ipv6']
    dut_ipv4 = setup_info['dut_ipv4']
    dut_ipv6 = setup_info['dut_ipv6']
    neigh_intf = setup_info['neigh_intf']

    # Wait for baseline BGP session
    logger.info("Waiting for BGP session to %s to be established",
                neigh_ipv4)
    pytest_assert(
        wait_until(60, 5, 0, lambda: duthost.bgp_facts()['ansible_facts']
                   .get('bgp_neighbors', {}).get(neigh_ipv4, {})
                   .get('state', '') == 'established'),
        "IPv4 BGP session to {} not established".format(neigh_ipv4))

    # Save EOS running-config before any modifications
    eos_config_backup = save_eos_running_config(neigh_host)

    # Track whether post-yield teardown ran, so addfinalizer
    # doesn't duplicate the cleanup.
    teardown_done = []

    # Register addfinalizer for full cleanup — runs even if fixture
    # crashes before yield (e.g. EOS command error during setup).
    # This ensures EOS config is restored and DUT is config_reloaded.
    def _full_cleanup():
        if teardown_done:
            return
        logger.info("addfinalizer: restoring EOS and DUT config")
        if eos_config_backup:
            restore_eos_full_config(neigh_host, eos_config_backup)
        if stop_bgpcfgd:
            duthost.shell("docker exec bgp supervisorctl start bgpcfgd",
                          module_ignore_errors=True)
        config_reload(duthost, wait=120)
    request.addfinalizer(_full_cleanup)

    # Optionally stop bgpcfgd to isolate FRR behavior for regression testing.
    # When bgpcfgd is running, it may inject config that masks FRR issues.
    if stop_bgpcfgd:
        logger.info("Stopping bgpcfgd (FRR isolation mode)")
        duthost.shell("docker exec bgp supervisorctl stop bgpcfgd",
                      module_ignore_errors=True)

    # Remove numbered BGP
    remove_numbered_bgp(duthost, neigh_host, dut_asn, neigh_asn,
                        neigh_ipv4, neigh_ipv6, dut_ipv4, dut_ipv6)

    # Remove IPv4/IPv6 addresses from test interface to prevent FRR
    # from falling back to numbered peering (ignoring v6only keyword).
    # This makes the test deterministic — only link-local can be used.
    if intf_type == 'portchannel':
        dut_test_intf = setup_info['pc_intf']
        if setup_info.get('dut_ipv4_prefix'):
            duthost.shell(
                "sudo config interface ip remove {} {}".format(
                    dut_test_intf, setup_info['dut_ipv4_prefix']),
                module_ignore_errors=True)
        if setup_info.get('dut_ipv6_prefix'):
            duthost.shell(
                "sudo config interface ip remove {} {}".format(
                    dut_test_intf, setup_info['dut_ipv6_prefix']),
                module_ignore_errors=True)
        # Remove IPs on EOS side too
        neigh_host.eos_config(
            lines=[
                "no ip address",
                "no ipv6 address",
            ],
            parents="interface {}".format(neigh_intf),
            module_ignore_errors=True)

    # Determine DUT and EOS interfaces based on scenario
    eos_intf = neigh_intf
    eos_vrf = None
    if intf_type == 'portchannel':
        dut_intf = setup_info['pc_intf']
    else:
        dut_intf = setup_info['member_ethernet']
        eos_intf, eos_vrf = break_lag_to_ethernet(
            duthost, neigh_host, setup_info)

    # Configure unnumbered BGP
    if stop_bgpcfgd:
        # FRR isolation: configure directly via vtysh
        configure_unnumbered_dut(duthost, dut_asn, dut_intf, neigh_asn)
    else:
        # Production path: configure via CONFIG_DB (bgpcfgd renders FRR)
        configure_unnumbered_dut_configdb(
            duthost, dut_asn, dut_intf, neigh_asn)
    configure_unnumbered_eos(
        neigh_host, neigh_asn, dut_asn, eos_intf, eos_vrf=eos_vrf)

    yield {'dut_intf': dut_intf, 'intf_type': intf_type}

    # Teardown — restore full EOS config from saved backup.
    # This handles both BGP config and interface/Port-Channel restoration,
    # which is critical for the ethernet variant that breaks the LAG.
    logger.info("Teardown [%s]: restoring full EOS config from backup",
                intf_type)
    restore_eos_full_config(neigh_host, eos_config_backup)
    config_reload(duthost, wait=120)
    original_neighbors = [neigh_ipv4]
    if neigh_ipv6:
        original_neighbors.append(neigh_ipv6)
    if not wait_until(WAIT_TIMEOUT, POLL_INTERVAL, 0,
                      duthost.check_bgp_session_state,
                      original_neighbors):
        logger.error("BGP sessions did not re-establish after restore")
    teardown_done.append(True)


@pytest.mark.disable_loganalyzer
def test_bgp_link_local(setup_info, configure_unnumbered_bgp):
    """Test unnumbered BGP peering via link-local addresses.

    Parametrized variants:
    - [portchannel]: unnumbered BGP on LAG interface (full stack)
    - [ethernet]: break LAG, unnumbered BGP on plain Ethernet (full stack)
    - [portchannel-frrtest]: bgpcfgd stopped, isolates FRR regressions
    """
    duthost = setup_info['duthost']
    dut_intf = configure_unnumbered_bgp['dut_intf']

    verify_bgp_established(duthost, dut_intf, setup_info)
    verify_routes_received(duthost, dut_intf)
