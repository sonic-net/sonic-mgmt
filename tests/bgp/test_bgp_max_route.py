"""
Test BGP max-prefix behavior for IPv4 and IPv6 peers.
"""

import logging
import pytest
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, generate_tmpfile, delete_tmpfile, format_json_patch_for_multiasic
from tests.common.utilities import wait_until
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.bgp.bgp_helpers import restart_bgp_session
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]


def configure_max_prefix(duthost, neighbor, max_prefix_limit, warning_only=False, use_frr=None):
    """Configure BGP maximum prefix limit for a neighbor.

    Args:
        duthost: DUT host object
        neighbor (str): BGP neighbor IP address
        max_prefix_limit (int): Maximum prefix limit to configure
        warning_only (bool, optional): If True, only warn when limit is exceeded. Defaults to False.
        use_frr (bool, optional): Whether to use FRR management framework.
                                If None, will auto-detect using get_frr_mgmt_framework_config()

    Returns:
        bool: True if configuration was successful
    """
    if use_frr is None:
        use_frr = duthost.get_frr_mgmt_framework_config()

    logger.info(f"Configuring max-prefix {max_prefix_limit} for neighbor {neighbor} (use_frr={use_frr})")

    if use_frr:
        warning_flag = "true" if warning_only else "false"

        # Check if the neighbor exists in BGP_NEIGHBOR table
        cmd = f"sonic-db-cli CONFIG_DB HGETALL \"BGP_NEIGHBOR|default|{neighbor}\""
        result = duthost.shell(cmd)
        neighbor_exists = bool(result['stdout'].strip())
        logger.info(f"Neighbor exists in CONFIG_DB: {neighbor_exists}")

        if neighbor_exists:
            # Determine address family from neighbor IP
            af = "ipv4" if ipaddress.ip_address(neighbor).version == 4 else "ipv6"
            af_suffix = f"{af}_unicast"

            # Check if BGP_NEIGHBOR_AF table exists
            cmd = "sonic-db-cli CONFIG_DB KEYS \"BGP_NEIGHBOR_AF*\""
            result = duthost.shell(cmd)
            has_bgp_neighbor_af = bool(result['stdout'].strip())
            logger.info(f"BGP_NEIGHBOR_AF exists: {has_bgp_neighbor_af}")

            if has_bgp_neighbor_af:
                # Check if the specific AF entry exists
                cmd = f"sonic-db-cli CONFIG_DB HGETALL \"BGP_NEIGHBOR_AF|default|{neighbor}|{af_suffix}\""
                result = duthost.shell(cmd)
                af_entry_exists = bool(result['stdout'].strip())
                logger.info(f"AF entry exists: {af_entry_exists}")

                if af_entry_exists:
                    # Update the existing AF entry with both settings in one patch
                    json_patch = [
                        {
                            "op": "add",
                            "path": f"/BGP_NEIGHBOR_AF/default|{neighbor}|{af_suffix}/max_prefix_limit",
                            "value": str(max_prefix_limit)
                        },
                        {
                            "op": "add",
                            "path": f"/BGP_NEIGHBOR_AF/default|{neighbor}|{af_suffix}/max_prefix_warning_only",
                            "value": warning_flag
                        }
                    ]
                else:
                    # Create the BGP_NEIGHBOR_AF entry with both settings in one patch
                    json_patch = [
                        {
                            "op": "add",
                            "path": f"/BGP_NEIGHBOR_AF/default|{neighbor}|{af_suffix}",
                            "value": {
                                "max_prefix_limit": str(max_prefix_limit),
                                "max_prefix_warning_only": warning_flag
                            }
                        }
                    ]

            logger.info(f"Generated JSON patch: {json_patch}")

            json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch, is_asic_specific=True)
            logger.info(f"Formatted JSON patch for multiasic: {json_patch}")

            tmpfile = generate_tmpfile(duthost)
            try:
                result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                logger.info(f"Patch application result: {result}")
                return result['rc'] == 0 and "Patch applied successfully" in result['stdout']
            finally:
                delete_tmpfile(duthost, tmpfile)
        else:
            logger.error(f"Neighbor {neighbor} not found")
            return False
    else:
        # Get local ASN from config facts
        config_facts = duthost.get_running_config_facts()
        local_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']

        # Determine address family from neighbor IP
        af = "ipv4" if ipaddress.ip_address(neighbor).version == 4 else "ipv6"
        af_cmd = "ipv4" if af == "ipv4" else "ipv6"

        warning_str = " warning-only" if warning_only else ""
        commands = [
            "configure terminal",
            f"router bgp {local_asn}",
            f"address-family {af_cmd} unicast",
            f"neighbor {neighbor} maximum-prefix {max_prefix_limit}{warning_str}",
            "end"
        ]

        result = duthost.shell("vtysh -c '" + "' -c '".join(commands) + "'")
        return result['rc'] == 0


def remove_max_prefix_config(duthost, neighbor, use_frr=None):
    """Remove max-prefix configuration for a neighbor.

    Args:
        duthost: DUT host object
        neighbor (str): BGP neighbor IP address
        use_frr (bool, optional): Whether to use FRR management framework
    """
    if use_frr is None:
        use_frr = duthost.get_frr_mgmt_framework_config()

    logger.info(f"Removing max-prefix config for neighbor {neighbor} (use_frr={use_frr})")

    if use_frr:
        # Determine address family from neighbor IP
        af = "ipv4" if ipaddress.ip_address(neighbor).version == 4 else "ipv6"
        af_suffix = f"{af}_unicast"

        # Check if BGP_NEIGHBOR_AF table exists
        cmd = "sonic-db-cli CONFIG_DB KEYS \"BGP_NEIGHBOR_AF*\""
        result = duthost.shell(cmd)
        has_bgp_neighbor_af = bool(result['stdout'].strip())

        if has_bgp_neighbor_af:
            # Check if the specific AF entry exists
            cmd = f"sonic-db-cli CONFIG_DB HGETALL \"BGP_NEIGHBOR_AF|default|{neighbor}|{af_suffix}\""
            result = duthost.shell(cmd)
            af_entry_exists = bool(result['stdout'].strip())

            if af_entry_exists:
                # Always just remove the max-prefix settings, not the entire entry
                json_patch = [
                    {
                        "op": "remove",
                        "path": f"/BGP_NEIGHBOR_AF/default|{neighbor}|{af_suffix}/max_prefix_limit"
                    },
                    {
                        "op": "remove",
                        "path": f"/BGP_NEIGHBOR_AF/default|{neighbor}|{af_suffix}/max_prefix_warning_only"
                    }
                ]

                logger.info(f"Generated JSON patch: {json_patch}")

                json_patch = format_json_patch_for_multiasic(duthost=duthost,
                                                             json_data=json_patch,
                                                             is_asic_specific=True)
                logger.info(f"Formatted JSON patch for multiasic: {json_patch}")

                tmpfile = generate_tmpfile(duthost)
                try:
                    result = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                    logger.info(f"Patch application result: {result}")
                    return result['rc'] == 0 and "Patch applied successfully" in result['stdout']
                finally:
                    delete_tmpfile(duthost, tmpfile)
            else:
                logger.info(f"No BGP_NEIGHBOR_AF entry found for {neighbor}, nothing to remove")
                return True
        else:
            logger.info("BGP_NEIGHBOR_AF table doesn't exist, nothing to remove")
            return True
    else:
        config_facts = duthost.get_running_config_facts()
        local_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
        af = "ipv4" if ipaddress.ip_address(neighbor).version == 4 else "ipv6"
        af_cmd = "ipv4" if af == "ipv4" else "ipv6"

        commands = [
            "configure terminal",
            f"router bgp {local_asn}",
            f"address-family {af_cmd} unicast",
            f"no neighbor {neighbor} maximum-prefix",
            "end"
        ]
        result = duthost.shell("vtysh -c '" + "' -c '".join(commands) + "'")
        return result['rc'] == 0


def check_bgp_session_state(duthost, neighbor, state="established"):
    """Check if BGP session is in the specified state.

    Args:
        duthost: DUT host object
        neighbor (str): BGP neighbor IP address
        state (str, optional): Expected BGP state. Defaults to "established".

    Returns:
        bool: True if session is in expected state
    """
    bgp_neighbors = {DEFAULT_NAMESPACE: {neighbor: {}}}
    return duthost.check_bgp_session_state_all_asics(bgp_neighbors, state=state)


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_bgp_max_prefix_behavior(duthosts, rand_one_dut_hostname, af):
    """
    Test BGP max-prefix behavior for IPv4 and IPv6 peers:
    1. Find a neighbor with active routes
    2. Configure strict max-prefix limit below current routes
    3. Verify session goes down
    4. Remove strict max-prefix config and clear session
    5. Apply warning-only configuration
    6. Verify session stays up and continues to receive routes above limit
    """
    duthost = duthosts[rand_one_dut_hostname]
    use_frr = duthost.get_frr_mgmt_framework_config()

    # Get current route count and find suitable neighbor
    bgp_summary = duthost.get_route(prefix=None)

    target_neighbor = None
    route_count = 0

    # Parse BGP summary based on address family
    peers = bgp_summary.get(f'{af}Unicast', {}).get('peers', {})
    if not peers:
        pytest.skip(f"No BGP peers found for {af} address family")

    for peer_ip, peer_data in peers.items():
        curr_routes = int(peer_data.get('pfxRcd', 0))
        if curr_routes > 1:
            target_neighbor = peer_ip
            route_count = curr_routes
            break

    pytest_assert(target_neighbor is not None,
                  f"No suitable {af} neighbor found with more than 1 route")

    try:
        # Test 1: Strict max-prefix behavior
        max_prefix_limit = max(1, route_count - 100)
        pytest_assert(
            configure_max_prefix(duthost, target_neighbor, max_prefix_limit, use_frr=use_frr),
            f"Failed to configure max-prefix limit for {target_neighbor}"
        )

        # Wait for session to go down
        pytest_assert(
            wait_until(30, 1, 0, check_bgp_session_state, duthost, target_neighbor, "idle"),
            f"BGP session for {target_neighbor} should be down due to max-prefix violation"
        )

        # Remove max-prefix config and restart BGP session
        remove_max_prefix_config(duthost, target_neighbor, use_frr=use_frr)

        # Test 2: Warning-only behavior
        max_prefix_limit = max(1, route_count - 1)

        # Initialize LogAnalyzer with the additional log file
        loganalyzer = LogAnalyzer(
            ansible_host=duthost,
            marker_prefix="bgp_max_prefix",
            additional_files={"/var/log/frr/bgpd.log": ""}
        )

        # Configure log analyzer
        loganalyzer.load_common_config()

        # Configure log analyzer to look for max prefix exceed message
        warning_pattern = ".*%MAXPFXEXCEED.*"

        # Configure log analyzer expectations
        loganalyzer.expect_regex = [warning_pattern]
        loganalyzer.match_regex = []

        with loganalyzer:  # Start monitoring logs

            pytest_assert(
                configure_max_prefix(duthost, target_neighbor, max_prefix_limit, warning_only=True, use_frr=use_frr),
                f"Failed to configure warning-only max-prefix limit for {target_neighbor}"
            )

            restart_bgp_session(duthost, neighbor=target_neighbor)

            # Wait for session to come back up
            pytest_assert(
                wait_until(30, 1, 0, check_bgp_session_state, duthost, target_neighbor),
                f"BGP session for {target_neighbor} failed to re-establish"
            )

            def check_routes_exceed_limit():
                bgp_summary = duthost.get_route(prefix=None)

                current_routes = int(bgp_summary[f'{af}Unicast']['peers'][target_neighbor]['pfxRcd'])
                logger.info(f"Current routes: {current_routes}, Max limit: {max_prefix_limit}")
                return current_routes > max_prefix_limit

            pytest_assert(
                wait_until(30, 2, 0, check_routes_exceed_limit),
                f"Route count did not exceed max-prefix limit {max_prefix_limit} after 30 seconds"
            )

    finally:
        # Cleanup
        remove_max_prefix_config(duthost, target_neighbor, use_frr=use_frr)
        restart_bgp_session(duthost, neighbor=target_neighbor)
        wait_until(30, 1, 0, check_bgp_session_state, duthost, target_neighbor)
