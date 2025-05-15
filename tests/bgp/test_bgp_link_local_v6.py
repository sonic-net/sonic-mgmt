"""
Test BGP functionality using IPv6 link-local addresses for peering.
"""
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.config_reload import config_reload
from tests.common.gu_utils import (
    generate_tmpfile,
    delete_tmpfile,
    apply_patch,
    expect_op_success,
    format_json_patch_for_multiasic
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
]


def configure_bgp_link_local(host, local_asn, peer_asn, interface, is_dut=False):
    """
    Configure BGP link-local peering
    """
    if is_dut and host.get_frr_mgmt_framework_config():
        # Use JSON patch for DUT when FRR management framework is enabled
        json_patch = [
            {
                "op": "add",
                "path": f"/BGP_NEIGHBOR/{interface}",
                "value": {
                    "asn": str(peer_asn),
                    "local_addr": {interface},
                    "name": interface,
                    "peer_type": "dynamic"
                }
            }
        ]

        json_patch = format_json_patch_for_multiasic(duthost=host, json_data=json_patch, is_asic_specific=True)
        tmpfile = generate_tmpfile(host)

        try:
            output = apply_patch(host, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(host, output)
        finally:
            delete_tmpfile(host, tmpfile)
    else:
        # Use existing vtysh commands for non-DUT or when FRR management is disabled
        commands = [
            "configure terminal",
            f"router bgp {local_asn}",
            f"neighbor {interface} interface v6only",
            f"neighbor {interface} remote-as {peer_asn}",
            "address-family ipv6 unicast",
            f"neighbor {interface} activate"
        ]

        commands.append("end")

        if isinstance(host, EosHost):
            host.run_command_list(commands)
        elif isinstance(host, dict) and 'host' in host:
            host['host'].command("vtysh -c '" + "' -c '".join(commands) + "'")
        else:
            host.shell("vtysh -c '" + "' -c '".join(commands) + "'")


def check_bgp_session_state(host, neighbor_addr, interface):
    """
    Check if BGP session is established
    """
    cmd = "show bgp ipv6 unicast summary json"
    logger.info("Checking BGP session state...")
    if isinstance(host, EosHost):
        # For EOS neighbors
        result = json.loads(host.run_command_list([cmd])[0])
    elif isinstance(host, dict) and 'host' in host:
        # For Sonic neighbors
        result = json.loads(host['host'].command(f"vtysh -c '{cmd}'")['stdout'])
    else:
        # For DUT
        result = json.loads(host.shell(f"vtysh -c '{cmd}'")['stdout'])

    logger.info(f"Checking BGP session state for interface {interface}")
    logger.info(f"BGP summary result: {result}")

    # Get peers directly from the result
    peers = result.get('peers', {})
    logger.info(f"Found peers: {peers}")

    # Check if the interface is directly in peers
    if interface in peers:
        peer_data = peers[interface]
        logger.info(f"Found peer data for {interface}: {peer_data}")
        return peer_data['state'] == 'Established'

    logger.info(f"No matching peer found for interface {interface}")
    return False


def get_first_ipv6_ethernet_interface(duthost):
    """
    Get the first Ethernet interface that has IPv6 enabled and is up
    Returns tuple of (interface_name, success)
    """
    try:
        ipv6_interfaces = duthost.show_and_parse("show ipv6 interfaces")

        for iface_info in ipv6_interfaces:
            interface = iface_info["interface"]
            if interface.startswith("Ethernet") and iface_info["admin/oper"] == "up/up":
                return interface, True

        return None, False
    except Exception as e:
        logger.error(f"Failed to get IPv6 interface information: {str(e)}")
        return None, False


def cleanup_bgp_config(duthost, peer_host, peer_name):
    """
    Cleanup configuration by performing config reload on both DUT and affected peer
    """
    logger.info("Cleaning up configuration with config reload")

    # Cleanup DUT configuration
    try:
        config_reload(duthost, config_source='config_db', wait=60)
        logger.info("Successfully reloaded DUT configuration")
    except Exception as e:
        logger.error(f"Failed to reload DUT configuration: {str(e)}")

    # Cleanup peer configuration
    try:
        if isinstance(peer_host, dict) and 'host' in peer_host:
            host = peer_host['host']
        else:
            host = peer_host

        config_reload(host, config_source='config_db', wait=60, is_dut=False)
        logger.info(f"Successfully reloaded peer {peer_name} configuration")
    except Exception as e:
        logger.error(f"Failed to reload peer {peer_name} configuration: {str(e)}")


def deactivate_global_bgp_neighbor(host, asn, neighbor_addr, is_dut=False):
    """
    Deactivate a global BGP neighbor configuration
    """
    logger.info(f"Deactivating global BGP neighbor {neighbor_addr}")

    if is_dut and host.get_frr_mgmt_framework_config():
        # Use JSON patch for DUT when FRR management framework is enabled
        json_patch = [
            {
                "op": "replace",
                "path": f"/BGP_NEIGHBOR/{neighbor_addr}/admin_status",
                "value": "down"
            }
        ]
        tmpfile = generate_tmpfile(host)
        try:
            output = apply_patch(host, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(host, output)
        finally:
            delete_tmpfile(host, tmpfile)
    else:
        commands = [
            "configure terminal",
            f"router bgp {asn}",
            "address-family ipv6 unicast",
            f"no neighbor {neighbor_addr} activate",
            "end"
        ]
        if isinstance(host, dict) and 'host' in host:
            host['host'].command("vtysh -c '" + "' -c '".join(commands) + "'")
        else:
            host.shell("vtysh -c '" + "' -c '".join(commands) + "'")


def test_bgp_link_local_peer(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Test BGP peering over IPv6 link-local address.
    """
    # Skip if neighbors are not sonic hosts
    for nbr in nbrhosts.values():
        if not isinstance(nbr['host'], SonicHost):
            pytest.skip("Test requires sonic neighbors")

    duthost = duthosts[rand_one_dut_hostname]

    # Get first available IPv6 Ethernet interface
    dut_interface, success = get_first_ipv6_ethernet_interface(duthost)
    pytest_assert(success and dut_interface,
                  "Failed to find an Ethernet interface with IPv6 enabled and up")

    # Log testbed information for debugging
    logger.info(f"Testing with DUT: {duthost.hostname}")
    logger.info(f"Available neighbor hosts: {list(nbrhosts.keys())}")
    logger.info(f"Selected DUT interface: {dut_interface}")

    config_facts = duthost.get_running_config_facts()
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']

    # Get peer ASN and host from minigraph
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    bgp_neighbors = mg_facts.get('minigraph_bgp', [])

    peer_asn = None
    peer_name = None
    for neighbor in bgp_neighbors:
        if neighbor['name'] in nbrhosts:
            peer_asn = neighbor['asn']
            peer_name = neighbor['name']
            break

    pytest_assert(peer_asn is not None, "Could not determine peer ASN")
    pytest_assert(peer_name is not None, "Could not find peer name")

    logger.info(f"Selected peer: {peer_name} (ASN: {peer_asn})")

    # Get the corresponding peer interface
    peer_interfaces = mg_facts['minigraph_neighbors']

    peer_interface = None
    if dut_interface in peer_interfaces:
        peer_data = peer_interfaces[dut_interface]
        if peer_data['name'] in nbrhosts:
            peer_interface = peer_data['port']

    pytest_assert(peer_interface,
                  f"Failed to find peer interface corresponding to DUT interface {dut_interface}")

    logger.info(f"Selected peer interface: {peer_interface}")

    try:
        # Find and deactivate the global BGP neighbor for our test peer
        for neighbor in bgp_neighbors:
            if neighbor['name'] == peer_name and ':' in neighbor['addr']:  # IPv6 peer we're testing
                logger.info(f"Deactivating global BGP neighbor for test peer {peer_name}")
                deactivate_global_bgp_neighbor(duthost, dut_asn, neighbor['addr'], is_dut=True)
                deactivate_global_bgp_neighbor(nbrhosts[peer_name], neighbor['asn'],
                                               neighbor['peer_addr'], is_dut=False)
                break

        # Configure BGP on DUT
        logger.info(f"Configuring BGP on DUT (interface: {dut_interface})")
        configure_bgp_link_local(duthost, dut_asn, peer_asn, dut_interface, is_dut=True)

        # Configure BGP on peer
        logger.info(f"Configuring BGP on peer (interface: {peer_interface})")
        configure_bgp_link_local(nbrhosts[peer_name], peer_asn, dut_asn, peer_interface, is_dut=False)

        # Wait for BGP session to establish on DUT
        logger.info("Waiting for BGP session to establish on DUT...")
        dut_established = wait_until(30, 1, 0, lambda: check_bgp_session_state(duthost, None, dut_interface))
        logger.info(f"DUT BGP session established: {dut_established}")

        # Wait for BGP session to establish on peer
        logger.info("Waiting for BGP session to establish on peer...")
        peer_established = wait_until(
            30, 1, 0,
            lambda: check_bgp_session_state(
                nbrhosts[peer_name],
                None,
                peer_interface
            )
        )
        logger.info(f"Peer BGP session established: {peer_established}")

        pytest_assert(dut_established, f"BGP session failed to establish on DUT (interface {dut_interface})")
        pytest_assert(peer_established, f"BGP session failed to establish on peer (interface {peer_interface})")

        # Verify route exchange
        def check_received_prefixes():
            dut_cmd = f"show bgp ipv6 unicast neighbor {dut_interface} prefix-count json"
            logger.info(f"Checking DUT received prefixes with command: {dut_cmd}")

            dut_neighbor_info = json.loads(duthost.shell(f"vtysh -c '{dut_cmd}'")['stdout'])
            logger.info(f"DUT neighbor info: {json.dumps(dut_neighbor_info, indent=2)}")

            dut_received_prefixes = int(dut_neighbor_info.get('pfxCounter', 0))
            logger.info(f"DUT received {dut_received_prefixes} prefixes from peer")

            return dut_received_prefixes > 0

        logger.info("Waiting for DUT to receive prefixes from peer...")
        pytest_assert(
            wait_until(30, 5, 0, check_received_prefixes),
            "No prefixes received on DUT from peer after 60 seconds"
        )

    finally:
        # Config reload will restore original configuration
        cleanup_bgp_config(duthost, nbrhosts[peer_name], peer_name)
        logger.info("Cleanup completed")
