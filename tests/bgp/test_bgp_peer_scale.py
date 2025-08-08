"""
Test BGP peer scaling by adding multiple BGP peers using loopback interfaces on SONiC DUTs.
"""
import json
import logging
import pytest
from tests.common.devices.eos import EosHost
from tests.common.devices.multi_asic import MultiAsicSonicHost
from tests.common.devices.sonic import SonicHost
from tests.bgp.bgp_helpers import configure_bgp_peer
from tests.common.helpers.ip_helpers import (
    configure_loopback,
    unconfigure_loopback,
    configure_static_route,
    unconfigure_static_route,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1"),
]

# Constants for BGP peer scaling
BASE_LOOPBACK_ID = 1  # Starting Loopback ID
PEERS_PER_DUT = 8  # Default number of additional peers to configure per DUT
MAX_PEERS_PER_DUT = 99  # Maximum peers per neighbor (limited by 100 ID allocation per neighbor)

# SONiC supports loopback IDs 0-999, so we need to stay within this range
SONIC_MAX_LOOPBACK_ID = 999


# Define regex patterns to ignore harmless loopback interface errors
LOOPBACK_IGNORE_REGEX = [
    # Ignore errors about adding IPv4 addresses to loopback interfaces that already exist
    r".*ERR swss#intfmgrd: :- setIntfIp: Command '/sbin/ip address \"add\" \".*\"" \
    r" dev \"Loopback.*\"' failed with rc 2.*",
    # Ignore errors about adding IPv6 addresses to loopback interfaces that already exist
    r".*ERR swss#intfmgrd: :- setIntfIp: Command '/sbin/ip -6 address \"add\" \".*\"" \
    r" dev \"Loopback.*\"' failed with rc 2.*",
    # Ignore RTNETLINK answers: File exists errors
    r".*swss#supervisord: intfmgrd RTNETLINK answers: File exists.*"
]


def get_neighbor_ip_pairs(duthost, nbrhost, tbinfo, addr_family="ipv4"):
    """Get the IP address pairs between DUT and neighbor host.

    Args:
        duthost: DUT host object
        nbrhost: Neighbor host object
        tbinfo: Testbed info fixture
        addr_family: Address family ("ipv4" or "ipv6")

    Returns:
        tuple: (dut_nbr_ip, nbr_dut_ip) - IP addresses on DUT and neighbor sides
    """
    try:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # Get the VM base number (e.g., 100 from VM0100)
        current_vm = int(nbrhost.hostname[2:])  # Extract number from VMxxxx

        # Find the topology name for this neighbor
        topo_name = None
        for _, neigh in mg_facts['minigraph_neighbors'].items():
            vm_offset = tbinfo['topo']['properties']['topology']['VMs'][neigh['name']]['vm_offset']
            base_vm = current_vm - vm_offset  # Calculate what the base VM should be
            # Check if this neighbor's base VM matches
            if base_vm == int(tbinfo['vm_base'][2:]):  # Compare with actual base VM number
                topo_name = neigh['name']
                break

        if not topo_name:
            logger.error(f"Could not find topology name for VM {nbrhost.hostname}")
            return None, None

        # Find BGP neighbor information
        for bgp_peer in mg_facts['minigraph_bgp']:
            if bgp_peer['name'] == topo_name:
                # Check if it's the right address family
                if addr_family == "ipv4" and '.' in bgp_peer['addr']:
                    return bgp_peer['addr'], bgp_peer['peer_addr']
                elif addr_family == "ipv6" and ':' in bgp_peer['addr']:
                    return bgp_peer['addr'], bgp_peer['peer_addr']

        logger.error(f"No {addr_family} BGP connection found between {duthost.hostname} and {topo_name}")
        return None, None

    except Exception as e:
        logger.warning(f"Failed to get neighbor IP pairs: {str(e)}")
        return None, None


def calculate_loopback_id(dut_index, neighbor_index, peer_index):
    """Get a unique loopback ID based on DUT, neighbor, and peer indices.

    This function ensures loopback IDs stay within SONiC's 0-999 range while maintaining uniqueness.

    Args:
        dut_index (int): Index of the DUT
        neighbor_index (int): Index of the neighbor
        peer_index (int): Index of the peer

    Returns:
        int: A unique loopback ID within SONiC's supported range (100-999)

    Raises:
        ValueError: If the calculated ID would exceed available range and cause collisions
    """
    # Calculate a sequential ID that guarantees uniqueness
    # Formula: BASE_ID + (dut_index * 800) + (neighbor_index * 100) + peer_index
    # This supports: 1 DUT, 8 neighbors, up to 99 peers per neighbor cleanly
    # ID ranges: neighbor 0 (100-199), neighbor 1 (200-299), etc.
    sequential_id = (dut_index * 800) + (neighbor_index * 100) + peer_index
    loopback_id = BASE_LOOPBACK_ID + sequential_id

    # Check if we exceed SONiC's limit
    if loopback_id > SONIC_MAX_LOOPBACK_ID:
        available_ids = SONIC_MAX_LOOPBACK_ID - BASE_LOOPBACK_ID + 1  # 900 available IDs
        max_neighbors_single_dut = available_ids // 100  # 9 neighbors max for single DUT
        max_peers_last_neighbor = available_ids - (neighbor_index * 100)  # Remaining for this neighbor
        error_msg = (
            f"Loopback ID {loopback_id} exceeds SONiC limit of {SONIC_MAX_LOOPBACK_ID}. "
            f"Current config: DUT {dut_index}, neighbor {neighbor_index}, peer {peer_index}. "
            f"With current allocation (100 IDs per neighbor): "
            f"Max {max_neighbors_single_dut} neighbors for single DUT, "
            f"or max {max_peers_last_neighbor} peers for neighbor {neighbor_index}. "
            f"Consider reducing peers_per_dut or using fewer neighbors."
        )
        raise ValueError(error_msg)

    return loopback_id


def get_loopback_ip_pair(loopback_id):
    """Get a pair of non-overlapping IP addresses for local and neighbor loopback use."""
    # Use loopback ID directly in the third octet to ensure each loopback gets a unique subnet
    # For example:
    # Loopback 1 -> 172.16.1.1/32 and 172.16.1.2/32
    # Loopback 2 -> 172.16.2.1/32 and 172.16.2.2/32
    # This supports up to 254 unique loopback IDs

    # Ensure loopback ID doesn't exceed 254 (reserve 255 for future use)
    if loopback_id > 254:
        # For loopback IDs > 254, use a different second octet
        # This extends support to 254 * 255 = 64,770 unique loopback IDs
        second_octet = 16 + (loopback_id // 255)
        third_octet = loopback_id % 255
        if third_octet == 0:  # Avoid 0 in third octet
            third_octet = 255
            second_octet -= 1

        # Ensure second octet doesn't exceed 254
        if second_octet > 254:
            logger.warning(f"Loopback ID {loopback_id} exceeds maximum supported value (64,770)")
            second_octet = 254
            third_octet = loopback_id % 255  # Use modulo to get a unique third octet
            if third_octet == 0:  # Avoid 0 in third octet
                third_octet = 255

        # Create IP addresses
        local_ip = f"172.{second_octet}.{third_octet}.1"
        neighbor_ip = f"172.{second_octet}.{third_octet}.2"
    else:
        # For loopback IDs <= 254, use the original scheme
        local_ip = f"172.16.{loopback_id}.1"
        neighbor_ip = f"172.16.{loopback_id}.2"

    return local_ip, neighbor_ip


def get_loopback_ipv6_pair(loopback_id):
    """Get a pair of non-overlapping IPv6 addresses for local and neighbor loopback use."""
    # Use loopback ID directly in the IPv6 address to ensure each loopback gets a unique subnet
    # For example:
    # Loopback 1 -> fc00:1::1/128 and fc00:1::2/128
    # Loopback 2 -> fc00:2::1/128 and fc00:2::2/128
    # This supports up to 65,535 unique loopback IDs

    # Ensure loopback_id is within valid range for IPv6 hex notation
    if loopback_id > 65535:
        # For larger loopback IDs, use multiple segments
        first_segment = loopback_id // 65536
        second_segment = loopback_id % 65536

        # Create IPv6 addresses
        local_ip = f"fc00:{first_segment:x}:{second_segment:x}::1"
        neighbor_ip = f"fc00:{first_segment:x}:{second_segment:x}::2"
    else:
        # For smaller loopback IDs, use a single segment
        local_ip = f"fc00:{loopback_id:x}::1"
        neighbor_ip = f"fc00:{loopback_id:x}::2"

    return local_ip, neighbor_ip


def get_asn_values(host):
    """Get the local and remote ASN values from existing BGP neighbors or config.
    Returns tuple of (local_asn, remote_asn)
    """
    if isinstance(host, EosHost):
        return get_asn_values_eos(host)
    elif isinstance(host, (SonicHost, MultiAsicSonicHost)):
        return get_asn_values_sonic(host)
    else:
        logger.error(f"Unsupported host type: {type(host)}")
        return None, None


def get_asn_values_eos(eoshost):
    """Get ASN values from EosHost using eos_command"""
    try:
        # Get BGP summary for IPv4 and IPv6
        out_v4 = eoshost.eos_command(commands=['show ip bgp summary | json'])
        out_v6 = eoshost.eos_command(commands=['show ipv6 bgp summary | json'])

        logger.debug(f"EOS IPv4 BGP summary: {out_v4}")
        logger.debug(f"EOS IPv6 BGP summary: {out_v6}")

        # Check if BGP is active
        if ('BGP inactive' in out_v4['stdout'][0].get('warnings', []) and
                'BGP inactive' in out_v6['stdout'][0].get('warnings', [])):
            logger.warning("BGP is inactive on EOS host")
            return None, None

        local_asn = None
        remote_asn = None

        # Try to get ASN from IPv4 BGP summary
        try:
            v4_data = out_v4['stdout'][0]
            if 'vrfs' in v4_data and 'default' in v4_data['vrfs']:
                vrf_data = v4_data['vrfs']['default']
                if 'asn' in vrf_data:
                    local_asn = vrf_data['asn']
                    logger.info(f"Found local ASN {local_asn} from EOS IPv4 BGP")

                # Look for remote ASN from peers
                if 'peers' in vrf_data:
                    for peer_ip, peer_data in vrf_data['peers'].items():
                        peer_asn = peer_data.get('asn')
                        if peer_asn is not None and peer_asn != local_asn:
                            remote_asn = peer_asn
                            logger.info(f"Found remote ASN {remote_asn} from EOS IPv4 peer {peer_ip}")
                            break
        except (KeyError, TypeError) as e:
            logger.debug(f"Could not extract ASN from IPv4 BGP summary: {str(e)}")

        # If we didn't get ASN from IPv4, try IPv6
        if local_asn is None:
            try:
                v6_data = out_v6['stdout'][0]
                if 'vrfs' in v6_data and 'default' in v6_data['vrfs']:
                    vrf_data = v6_data['vrfs']['default']
                    if 'asn' in vrf_data:
                        local_asn = vrf_data['asn']
                        logger.info(f"Found local ASN {local_asn} from EOS IPv6 BGP")
            except (KeyError, TypeError) as e:
                logger.debug(f"Could not extract ASN from IPv6 BGP summary: {str(e)}")

        # If we didn't get remote ASN from IPv4, try IPv6
        if remote_asn is None and local_asn is not None:
            try:
                v6_data = out_v6['stdout'][0]
                if 'vrfs' in v6_data and 'default' in v6_data['vrfs']:
                    vrf_data = v6_data['vrfs']['default']
                    if 'peers' in vrf_data:
                        for peer_ip, peer_data in vrf_data['peers'].items():
                            peer_asn = peer_data.get('asn')
                            if peer_asn is not None and peer_asn != local_asn:
                                remote_asn = peer_asn
                                logger.info(f"Found remote ASN {remote_asn} from EOS IPv6 peer {peer_ip}")
                                break
            except (KeyError, TypeError) as e:
                logger.debug(f"Could not extract remote ASN from IPv6 BGP summary: {str(e)}")

        if local_asn is None:
            logger.error("Could not determine local ASN from EOS BGP summary")
            return None, None

        if remote_asn is None:
            logger.error("Could not determine remote ASN from EOS BGP peers")
            return None, None

        return local_asn, remote_asn

    except Exception as e:
        logger.error(f"Failed to get ASN values from EOS host: {str(e)}")
        return None, None


def get_asn_values_sonic(duthost):
    """Get ASN values from SonicHost using vtysh commands"""
    try:
        # Use vtysh to get BGP summary in JSON format for both IPv4 and IPv6
        result = duthost.shell("vtysh -c 'show bgp summary json'", module_ignore_errors=True)

        if result['rc'] == 0:
            try:
                # Parse the JSON output
                bgp_summary = json.loads(result['stdout'])
                logger.debug(f"BGP summary JSON: {bgp_summary}")

                # Get the local ASN from either IPv4 or IPv6 unicast
                local_asn = None
                if 'ipv4Unicast' in bgp_summary and bgp_summary['ipv4Unicast'].get('as') is not None:
                    local_asn = bgp_summary['ipv4Unicast'].get('as')
                    logger.info(f"Found BGP already running with ASN {local_asn} from IPv4 unicast")
                elif 'ipv6Unicast' in bgp_summary and bgp_summary['ipv6Unicast'].get('as') is not None:
                    local_asn = bgp_summary['ipv6Unicast'].get('as')
                    logger.info(f"Found BGP already running with ASN {local_asn} from IPv6 unicast")

                if local_asn is None:
                    logger.warning("Could not find local ASN in BGP summary")
                    return None, None

                # Look for a peer with a different ASN in either IPv4 or IPv6 unicast
                remote_asn = None

                # Check IPv4 peers first
                if 'ipv4Unicast' in bgp_summary:
                    peers = bgp_summary['ipv4Unicast'].get('peers', {})
                    for peer_ip, peer_data in peers.items():
                        peer_remote_asn = peer_data.get('remoteAs')
                        if peer_remote_asn is not None and peer_remote_asn != local_asn:
                            remote_asn = peer_remote_asn
                            logger.info(f"Found remote ASN {remote_asn} for IPv4 peer {peer_ip}")
                            return local_asn, remote_asn

                # If no IPv4 peer with different ASN, check IPv6 peers
                if 'ipv6Unicast' in bgp_summary:
                    peers = bgp_summary['ipv6Unicast'].get('peers', {})
                    for peer_ip, peer_data in peers.items():
                        peer_remote_asn = peer_data.get('remoteAs')
                        if peer_remote_asn is not None and peer_remote_asn != local_asn:
                            remote_asn = peer_remote_asn
                            logger.info(f"Found remote ASN {remote_asn} for IPv6 peer {peer_ip}")
                            return local_asn, remote_asn

                logger.warning("Could not find a peer with a different ASN in BGP summary")
                return None, None
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON output: {str(e)}")
            except Exception as e:
                logger.warning(f"Error processing BGP summary JSON: {str(e)}")
    except Exception as e:
        logger.warning(f"Failed to get ASN values from BGP summary: {str(e)}")

    # If vtysh method fails, try config facts
    try:
        # Try to get from config facts
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        local_asn = config_facts.get('DEVICE_METADATA', {}).get('localhost', {}).get('bgp_asn')

        if local_asn is None:
            logger.error("Could not determine local ASN from config facts")
            return None, None

        # Try to get remote ASN from existing BGP neighbors
        bgp_config = config_facts.get('BGP_NEIGHBOR', {})
        for peer_data in bgp_config.values():
            if 'asn' in peer_data and peer_data['asn'] != local_asn:
                return local_asn, peer_data['asn']

        logger.error("Could not determine remote ASN from BGP neighbors")
        return None, None

    except Exception as e:
        logger.error(f"Failed to get ASN values from config: {str(e)}")
        return None, None


def run_bgp_peer_scale(duthosts, _, nbrhosts, tbinfo, addr_family="ipv4", peers_per_dut=PEERS_PER_DUT):
    """
    Common helper function to run BGP peer scale tests for IPv4 or IPv6.

    Args:
        duthosts: DUT host objects
        enum_rand_one_per_hwsku_hostname: Test fixture
        nbrhosts: Neighbor host objects
        tbinfo: Testbed information dictionary containing topology details
        addr_family: Address family ("ipv4" or "ipv6")
        peers_per_dut: Number of additional BGP peers to configure per DUT (default: PEERS_PER_DUT)
    """
    # Check if peers_per_dut will fit within our loopback ID allocation scheme
    # With current multipliers: max MAX_PEERS_PER_DUT peers per neighbor
    if peers_per_dut > MAX_PEERS_PER_DUT:
        error_msg = (
            f"peers_per_dut ({peers_per_dut}) exceeds maximum of {MAX_PEERS_PER_DUT} "
            f"peers per neighbor (limited by loopback ID allocation)"
        )
        logger.error(error_msg)
        pytest.fail(error_msg)

    configs = []
    try:
        for dut_index, duthost in enumerate(duthosts):
            # Get local and remote asn values for the DUT
            dut_local_asn, dut_remote_asn = get_asn_values(duthost)

            if dut_local_asn is None or dut_remote_asn is None:
                pytest.fail(f"Could not determine ASN values for DUT {duthost.hostname}")

            logger.info(f"DUT {duthost.hostname} has local ASN {dut_local_asn} and remote ASN {dut_remote_asn}")

            # Get all current BGP neighbors for this DUT
            current_neighbors = [nbr["host"] for nbr in nbrhosts.values()]

            if not current_neighbors:
                pytest.fail(f"No existing BGP neighbors found for DUT {duthost.hostname}")

            # Get port connections between DUT and neighbors
            for neighbor_index, nbrhost in enumerate(current_neighbors):
                # Get neighbor IPs for connectivity
                dut_nbr_ip, nbr_dut_ip = get_neighbor_ip_pairs(duthost, nbrhost, tbinfo, addr_family=addr_family)

                if not dut_nbr_ip or not nbr_dut_ip:
                    pytest.fail(f"Failed to get neighbor IP addresses for {duthost.hostname} and {nbrhost.hostname}")

                # Get ASN values for the neighbor
                nbr_local_asn, nbr_remote_asn = get_asn_values(nbrhost)

                if nbr_local_asn is None or nbr_remote_asn is None:
                    pytest.fail(f"Could not determine ASN values for neighbor {nbrhost.hostname}")

                logger.info(f"Neighbor {nbrhost.hostname} has local ASN {nbr_local_asn}, remote ASN {nbr_remote_asn}")

                # Configure additional peers for this neighbor
                for peer_index in range(peers_per_dut):
                    # Calculate a unique loopback ID
                    loopback_id = calculate_loopback_id(dut_index, neighbor_index, peer_index)

                    if addr_family == "ipv4":
                        local_ip, neighbor_ip = get_loopback_ip_pair(loopback_id)
                    else:
                        local_ip, neighbor_ip = get_loopback_ipv6_pair(loopback_id)

                    # Configure loopback interfaces on DUT and neighbor
                    # Be little paranoid and verify that the IP addresses are different
                    if local_ip == neighbor_ip:
                        pytest.fail(f"IP conflict detected: Both DUT and neighbor would use {local_ip}")

                    logger.info(f"Configuring loopback {loopback_id} with IP {local_ip} on {duthost.hostname}")
                    if not configure_loopback(duthost, loopback_id, local_ip):
                        pytest.fail(
                            f"Failed to configure loopback {loopback_id} with IP {local_ip} on {duthost.hostname}"
                        )

                    logger.info(f"Configuring loopback {loopback_id} with IP {neighbor_ip} on {nbrhost.hostname}")
                    if not configure_loopback(nbrhost, loopback_id, neighbor_ip):
                        pytest.fail(
                            f"Failed to configure loopback {loopback_id} with IP {neighbor_ip} on {nbrhost.hostname}"
                        )

                    logger.info(
                        f"Successfully configured loopback {loopback_id} with IP {local_ip} on {duthost.hostname}"
                    )
                    logger.info(
                        f"Successfully configured loopback {loopback_id} with IP {neighbor_ip} on {nbrhost.hostname}"
                    )

                    # Configure routes to reach each other's loopbacks
                    prefix_len = '128' if addr_family == "ipv6" else '32'
                    if not configure_static_route(duthost, f"{neighbor_ip}/{prefix_len}", dut_nbr_ip):
                        pytest.fail(f"Failed to configure route to peer loopback on {duthost.hostname}")
                    if not configure_static_route(nbrhost, f"{local_ip}/{prefix_len}", nbr_dut_ip):
                        pytest.fail(f"Failed to configure route to peer loopback on {nbrhost.hostname}")
                    logger.info(
                        f"Configured static route on {duthost.hostname} to reach {neighbor_ip} via {dut_nbr_ip}"
                    )
                    logger.info(
                        f"Configured static route on {nbrhost.hostname} to reach {local_ip} via {nbr_dut_ip}"
                    )

                    # Configure eBGP peers
                    loopback_name = f"Loopback{loopback_id}"

                    # Configure BGP peer on DUT using DUT's ASN values
                    # DUT peers with neighbor's IP
                    logger.info(
                        f"Configuring BGP peer on {duthost.hostname} to peer with {neighbor_ip} "
                        f"(using loopback {loopback_name})"
                    )
                    if not configure_bgp_peer(duthost, neighbor_ip, dut_local_asn,
                                              nbr_local_asn, afi=addr_family,
                                              update_source_intf=loopback_name):
                        pytest.fail(
                            f"Failed to configure BGP peer on {duthost.hostname} to peer with {neighbor_ip}"
                        )
                    logger.info(
                        f"Successfully configured BGP peer on {duthost.hostname} to peer with {neighbor_ip}"
                    )

                    # Configure BGP peer on neighbor using neighbor's ASN values
                    # Neighbor peers with DUT's IP
                    logger.info(
                        f"Configuring BGP peer on {nbrhost.hostname} to peer with {local_ip} "
                        f"(using loopback {loopback_name})"
                    )
                    if not configure_bgp_peer(nbrhost, local_ip, nbr_local_asn,
                                              dut_local_asn, afi=addr_family,
                                              update_source_intf=loopback_name):
                        pytest.fail(
                            f"Failed to configure {addr_family} BGP peer on {nbrhost.hostname} to peer with {local_ip}"
                        )
                    logger.info(
                        f"Successfully configured BGP peer on {nbrhost.hostname} to peer with {local_ip}"
                    )

                    configs.append({
                        'duthost': duthost,
                        'nbrhost': nbrhost,
                        'loopback_id': loopback_id,
                        'local_ip': local_ip,
                        'neighbor_ip': neighbor_ip,
                        'dut_local_asn': dut_local_asn,
                        'nbr_local_asn': nbr_local_asn,
                        'addr_family': addr_family
                    })

        # Verify BGP peer configuration and status
        verify_bgp_peer_scale(duthosts, configs, addr_family=addr_family)
    finally:
        # Clean up configurations
        for config in configs:
            duthost = config['duthost']
            nbrhost = config['nbrhost']
            loopback_id = config['loopback_id']
            local_ip = config['local_ip']
            neighbor_ip = config['neighbor_ip']
            addr_family = config['addr_family']

            # Remove BGP neighbors added by this test
            duthost.shell(
                f"vtysh -c 'configure terminal' "
                f"-c 'router bgp {config['dut_local_asn']}' "
                f"-c 'no neighbor {neighbor_ip}'",
                module_ignore_errors=True
            )
            nbrhost.shell(
                f"vtysh -c 'configure terminal' "
                f"-c 'router bgp {config['nbr_local_asn']}' "
                f"-c 'no neighbor {local_ip}'",
                module_ignore_errors=True
            )

            # Delete routes to peer loopbacks
            prefix_len = '128' if addr_family == "ipv6" else '32'
            if not unconfigure_static_route(duthost, f"{neighbor_ip}/{prefix_len}"):
                logger.error(f"Failed to delete route to peer loopback on {duthost.hostname}")
            if not unconfigure_static_route(nbrhost, f"{local_ip}/{prefix_len}"):
                logger.error(f"Failed to delete route to peer loopback on {nbrhost.hostname}")

            # Remove loopback interfaces
            if not unconfigure_loopback(duthost, loopback_id):
                logger.error(f"Failed to unconfigure loopback {loopback_id} on {duthost.hostname}")
            if not unconfigure_loopback(nbrhost, loopback_id):
                logger.error(f"Failed to unconfigure loopback {loopback_id} on {nbrhost.hostname}")


def test_bgp_peer_scale_v4(duthosts, enum_rand_one_per_hwsku_hostname, nbrhosts, tbinfo, loganalyzer, request):
    # Configure loganalyzer to ignore loopback interface errors
    for duthost in duthosts:
        if duthost.hostname in loganalyzer:
            loganalyzer[duthost.hostname].ignore_regex.extend(LOOPBACK_IGNORE_REGEX)
    """
    Verify BGP IPv4 peer scaling by checking:
    1. All VLAN interfaces are properly configured and up
    2. All BGP peers are configured
    3. All BGP sessions are established
    """
    # Get the number of peers per DUT from command-line argument
    peers_per_dut = request.config.getoption("--peers-per-dut")
    run_bgp_peer_scale(duthosts, enum_rand_one_per_hwsku_hostname, nbrhosts,
                       tbinfo, addr_family="ipv4", peers_per_dut=peers_per_dut)


def test_bgp_peer_scale_v6(duthosts, enum_rand_one_per_hwsku_hostname, nbrhosts, tbinfo, loganalyzer, request):
    # Configure loganalyzer to ignore loopback interface errors
    for duthost in duthosts:
        if duthost.hostname in loganalyzer:
            loganalyzer[duthost.hostname].ignore_regex.extend(LOOPBACK_IGNORE_REGEX)
    """
    Verify BGP IPv6 peer scaling by checking:
    1. All VLAN interfaces are properly configured and up
    2. All BGP peers are configured
    3. All BGP sessions are established
    """
    # Get the number of peers per DUT from command-line argument
    peers_per_dut = request.config.getoption("--peers-per-dut")
    run_bgp_peer_scale(duthosts, enum_rand_one_per_hwsku_hostname, nbrhosts,
                       tbinfo, addr_family="ipv6", peers_per_dut=peers_per_dut)


def verify_bgp_peer_scale(duthosts, configs, addr_family="ipv4"):
    """
    Verify BGP peer scale configuration and status for all DUTs

    Args:
        duthosts: List of DUT host objects
        configs: List of configuration dictionaries containing neighbor information
        addr_family: Address family ("ipv4" or "ipv6")
    """
    if not configs:
        return

    ipcmd = 'ipv6' if addr_family == "ipv6" else 'ip'

    # Verify configuration for each DUT
    for duthost in duthosts:
        # Get DUT-specific configs
        dut_configs = [config for config in configs if config['duthost'] == duthost]
        if not dut_configs:
            continue

        # Get interface info once per DUT
        output = duthost.shell(f"show {ipcmd} interfaces")["stdout"]

        # Get BGP facts once per DUT
        bgp_facts = duthost.bgp_facts()['ansible_facts']

        # Verify all loopback interfaces for this DUT
        neighbor_ips = []
        for config in dut_configs:
            loopback_name = f"Loopback{config['loopback_id']}"
            interface_found = False
            ip_configured = False
            status_up = False

            for line in output.split('\n'):
                if loopback_name in line:
                    interface_found = True
                    ip_configured = config['local_ip'] in line
                    status_up = 'up/up' in line.lower()
                    break

            pytest_assert(
                interface_found,
                f"Loopback interface {loopback_name} not found in show ip interfaces output on {duthost.hostname}"
            )

            pytest_assert(
                ip_configured,
                f"Incorrect IP address configured on {loopback_name}. Expected {config['local_ip']}"
            )

            pytest_assert(
                status_up,
                f"Interface {loopback_name} is not up on {duthost.hostname}"
            )

            # Verify BGP peer configuration
            pytest_assert(
                config['neighbor_ip'] in bgp_facts['bgp_neighbors'],
                f"BGP peer {config['neighbor_ip']} not found in BGP neighbors on {duthost.hostname}"
            )

            neighbor_ips.append(config['neighbor_ip'])

        # Check all BGP sessions
        timeout = 120
        pytest_assert(
            wait_until(timeout, 5, 0, duthost.check_bgp_session_state, neighbor_ips),
            f"Not all BGP sessions are established after {timeout} seconds on {duthost.hostname}"
        )
