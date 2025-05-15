"""
Test BGP route-map functionality for community matching and local preference modification.
"""
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
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


def configure_community_route_map(host, route_map_name="COMM_LOCAL_PREF", community="1234:5678", is_dut=False):
    """
    Configure route-map to match on community and set local preference
    """
    logger.info(f"Configuring route-map {route_map_name} to match community {community}")
    community_name = "LOCAL_PREF_TEST"

    if is_dut and host.get_frr_mgmt_framework_config():
        # Use JSON patch for DUT when FRR management framework is enabled
        json_patch = [
            {
                "op": "add",
                "path": f"/COMMUNITY_LIST/{community_name}",
                "value": {
                    "type": "standard",
                    "members": [
                        {
                            "action": "permit",
                            "community": community,
                            "seq": "5"
                        }
                    ]
                }
            },
            {
                "op": "add",
                "path": f"/ROUTE_MAP/{route_map_name}|10",
                "value": {
                    "route_operation": "permit",
                    "match_community_list": community_name,
                    "set_local_pref": "0"
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
        # Use vtysh commands
        commands = [
            "configure terminal",
            f"bgp community-list standard LOCAL_PREF_TEST seq 5 permit {community}",
            f"route-map {route_map_name} permit 10",
            f"match community {community_name}",
            "set local-preference 0",
            "end"
        ]
        host.shell("vtysh -c '" + "' -c '".join(commands) + "'")


def get_multi_path_routes(host, peer_addr):
    """
    Get routes that are learned from multiple peers, including the specified peer
    """
    cmd = "show ip bgp json"
    logger.info(f"Executing command: {cmd}")
    output = json.loads(host.shell(f"vtysh -c '{cmd}'")['stdout'])
    multi_path_routes = []

    routes = output.get('routes', {})
    for prefix, paths in routes.items():
        # paths is a list of path entries
        if len(paths) > 1:  # Multiple paths exist for this prefix
            # Check if our target peer is one of the path sources
            peer_path = None
            other_paths = []

            for path in paths:
                # Extract peer ID from nexthops
                nexthops = path.get('nexthops', [])
                if nexthops:
                    path_peer_ip = nexthops[0].get('ip')
                    if path_peer_ip == peer_addr:
                        peer_path = path
                    else:
                        other_paths.append(path)

            if peer_path and other_paths:
                multi_path_routes.append({
                    'prefix': prefix,
                    'peer_path': peer_path,
                    'other_paths': other_paths
                })

    logger.info(f"Found {len(multi_path_routes)} multi-path routes including peer {peer_addr}")
    return multi_path_routes


def test_bgp_community_local_pref(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo):
    """
    Test BGP route-map matching on community and setting local preference

    Test steps:
    1. Find routes that are learned from multiple peers
    2. Configure route-map on DUT to match existing communities and set local-pref to 0
    3. Apply route-map to target peer
    4. Verify routes are still being learned from other peers with original local preference

    Expected results:
    - Routes from the target peer should have local preference 0
    - Routes should still be learned from other peers with original local preference
    - Best path selection should prefer paths from other peers
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get configuration facts
    config_facts = duthost.get_running_config_facts()
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    # Get peer information
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    bgp_neighbors = mg_facts.get('minigraph_bgp', [])

    # Find a suitable peer
    peer_name = None
    peer_addr = None
    for neighbor in bgp_neighbors:
        if neighbor['name'] in nbrhosts:
            peer_name = neighbor['name']
            peer_addr = neighbor['addr']
            break

    pytest_assert(peer_name is not None, "Could not find suitable peer")

    # Get multi-path routes that include our target peer
    multi_path_routes = get_multi_path_routes(duthost, peer_addr)
    pytest_assert(multi_path_routes, "No multi-path routes found")

    test_route = multi_path_routes[0]
    logger.info(f"Using multi-path route {test_route['prefix']} for testing")

    # Get existing communities from the peer's routes
    # Use the get_route method from SonicHost to get route information
    route_info = duthost.get_route(test_route['prefix'])

    # Find path from our target peer and get its communities
    peer_path = None
    for path in route_info.get('paths', []):
        nexthops = path.get('nexthops', [])
        if nexthops and any(nh.get('ip') == peer_addr for nh in nexthops):
            peer_path = path
            break

    pytest_assert(peer_path is not None, f"Could not find path from peer {peer_addr}")

    # Get community from the path - handle the specific format
    communities = peer_path.get('community', {})
    community = communities['list'][0] if communities and 'list' in communities else None

    pytest_assert(community is not None, f"No communities found in routes from peer {peer_addr}")
    logger.info(f"Using existing community {community} for route-map")

    try:
        # Configure route-map to match existing community
        route_map_name = "COMM_LOCAL_PREF"
        configure_community_route_map(duthost, route_map_name, community, is_dut=True)

        # Apply route-map to peer
        if duthost.get_frr_mgmt_framework_config():
            json_patch = [
                {
                    "op": "add",
                    "path": f"/BGP_NEIGHBOR/{peer_addr}",
                    "value": {
                        "route_map_in": route_map_name
                    }
                }
            ]
            tmpfile = generate_tmpfile(duthost)
            try:
                output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
                expect_op_success(duthost, output)
            finally:
                delete_tmpfile(duthost, tmpfile)
        else:
            commands = [
                "configure terminal",
                f"router bgp {dut_asn}",
                "address-family ipv4 unicast",
                f"neighbor {peer_addr} route-map {route_map_name} in",
                "end"
            ]
            duthost.shell("vtysh -c '" + "' -c '".join(commands) + "'")

        # Wait for route changes and verify
        def check_route_paths():
            # Use the get_route method from SonicHost to get route information
            output = duthost.get_route(test_route['prefix'])

            paths = output.get('paths', [])
            if not paths:
                logger.warning("No paths found")
                return False

            target_peer_path = None
            other_paths = []

            for path in paths:
                peer_info = path.get('peer', {})
                peer_id = peer_info.get('peerId')

                if peer_id == peer_addr:
                    target_peer_path = path
                else:
                    other_paths.append(path)

            if target_peer_path is None:
                logger.warning(f"No path found from target peer {peer_addr}")
                return False

            # Verify target peer path has local_pref 0
            local_pref = target_peer_path.get('locPrf')
            if local_pref != 0:
                logger.warning(f"Target peer path local_pref is {local_pref}, expected 0")
                return False

            # Verify other paths still have original local_pref
            for path in other_paths:
                if path.get('locPrf') == 0:
                    logger.warning(f"Non-target path has local_pref 0: {path}")
                    return False

            # Verify best path is not from target peer
            best_path = next((p for p in paths if p.get('bestpath', {}).get('overall')), None)
            if not best_path:
                logger.warning("No best path found")
                return False

            best_path_peer = best_path.get('peer', {}).get('peerId')
            is_valid = (best_path_peer != peer_addr)
            logger.info(f"Best path check {'passed' if is_valid else 'failed'} "
                        f"(best path peer: {best_path_peer}, target peer: {peer_addr})")

            return is_valid

        result = wait_until(30, 5, 0, check_route_paths)
        if not result:
            cmd = f"show ip bgp {test_route['prefix']} json"
            current_paths = json.loads(duthost.shell(f"vtysh -c '{cmd}'")['stdout'])
            logger.error(f"Final BGP path state: {json.dumps(current_paths, indent=2)}")
            pytest.fail("Route path verification failed")

    finally:
        # Config reload will restore original configuration
        config_reload(duthost, config_source='config_db', wait=60)
