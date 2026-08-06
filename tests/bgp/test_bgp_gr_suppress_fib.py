"""
Test BGP Graceful Restart with suppress-fib-pending enabled.

Covers test gap issue #21249: Missing GR/EOR test cases with suppress FIB enabled.

When suppress-fib-pending is enabled, FRR should not send EOR to peers until all
routes are programmed into the forwarding plane (FIB). This test verifies:

1. With suppress-fib-pending enabled, BGP GR completes successfully
2. Routes from neighbors are preserved during GR (stale state)
3. After GR recovery, all routes are restored and no longer stale
4. BGP sessions re-establish cleanly after restart
"""

import pytest
import logging
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def enable_suppress_fib(duthosts, rand_one_dut_hostname):
    """Enable suppress-fib-pending on DUT and restore after test."""
    duthost = duthosts[rand_one_dut_hostname]

    # Check current state / capability
    original_enabled = False
    try:
        result = duthost.shell('show suppress-fib-pending', module_ignore_errors=True)
    except Exception:
        pytest.skip("suppress-fib-pending is not supported or probe command failed")

    if result.get('rc', 1) != 0:
        pytest.skip("suppress-fib-pending is not supported on this platform")

    if 'Enabled' in result.get('stdout', ''):
        original_enabled = True

    # Enable suppress-fib-pending
    if not original_enabled:
        logger.info("Enabling suppress-fib-pending on DUT")
        duthost.shell('sudo config suppress-fib-pending enabled')
        # Verify it's enabled
        result = duthost.shell('show suppress-fib-pending')
        pytest_assert('Enabled' in result['stdout'],
                      "Failed to enable suppress-fib-pending")

    yield

    # Restore original state
    if not original_enabled:
        logger.info("Restoring suppress-fib-pending to disabled")
        duthost.shell('sudo config suppress-fib-pending disabled', module_ignore_errors=True)


def _get_bgp_routes_summary(duthost):
    """Get total number of received BGP routes (IPv4 + IPv6).

    Counts routes per-namespace and sums across all namespaces. On multi-ASIC
    systems, the same prefix may exist in multiple ASICs (each has its own
    forwarding table), so we count each occurrence independently.
    """
    total_routes = 0
    namespaces = duthost.get_frontend_asic_namespace_list() or ['']
    for namespace in namespaces:
        for af, af_key in [('ipv4', 'ipv4Unicast'), ('ipv6', 'ipv6Unicast')]:
            cmd = duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c 'show bgp {} summary json'".format(af), namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                # FRR nests peers under address-family key (e.g. ipv4Unicast)
                peers = result.get(af_key, result).get('peers', {})
                for peer_info in peers.values():
                    total_routes += peer_info.get('pfxRcd', 0)
            except Exception as e:
                logger.warning("Failed to get BGP routes for %s in namespace '%s': %s",
                               af, namespace, e)
    return total_routes


def _get_neighbor_route_counts(duthost, bgp_neighbors):
    """Get route counts from each BGP neighbor.

    On multi-ASIC platforms, aggregates counts across namespaces for each neighbor.
    """
    counts = {}
    for neighbor in bgp_neighbors:
        for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
            if '.' in neighbor:
                cmd = "vtysh -c 'show bgp ipv4 neighbor %s prefix-counts json'" % neighbor
            else:
                cmd = "vtysh -c 'show bgp ipv6 neighbor %s prefix-counts json'" % neighbor
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                counters = result.get('ribTableWalkCounters', {})
                entry = {
                    'all': counters.get('All RIB', 0),
                    'valid': counters.get('Valid', 0),
                    'stale': counters.get('Stale', 0),
                }
                if neighbor in counts:
                    # Aggregate across namespaces
                    for key in ('all', 'valid', 'stale'):
                        counts[neighbor][key] += entry[key]
                else:
                    counts[neighbor] = entry
            except Exception:
                logger.warning("Failed to get route counts for neighbor %s in namespace '%s'",
                               neighbor, namespace)
    return counts


def _get_neighbor_routes_per_namespace(duthost, neighbor_ips):
    """Get routes from neighbors, counted per-namespace.

    Returns a dict of {(namespace, neighbor_ip): {prefix: route_data}}.
    On multi-ASIC systems, the same prefix in different ASICs is counted
    separately since each ASIC maintains its own forwarding table.
    """
    routes = {}
    for neighbor_ip in neighbor_ips:
        for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
            if '.' in neighbor_ip:
                cmd = "vtysh -c 'show bgp ipv4 neighbor %s routes json'" % neighbor_ip
            else:
                cmd = "vtysh -c 'show bgp ipv6 neighbor %s routes json'" % neighbor_ip
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                routes[(namespace, neighbor_ip)] = result.get('routes', {})
            except Exception as e:
                logger.warning("Failed to get routes for neighbor %s in namespace '%s': %s",
                               neighbor_ip, namespace, e)
    return routes


def _count_total_routes(routes_dict):
    """Count total routes across all (namespace, neighbor) pairs."""
    return sum(len(v) for v in routes_dict.values())


def _check_all_bgp_sessions_established(duthost, bgp_neighbor_ips):
    """Check that all BGP sessions are established.

    Returns False if any expected neighbor is missing from BGP summary
    or not in Established state.
    """
    found_neighbors = set()
    for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
        cmd = duthost.get_vtysh_cmd_for_namespace(
            "vtysh -c 'show bgp summary json'", namespace)
        try:
            result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
            for af_key in ['ipv4Unicast', 'ipv6Unicast']:
                af = result.get(af_key, {})
                peers = af.get('peers', {})
                for neighbor_ip in bgp_neighbor_ips:
                    if neighbor_ip in peers:
                        found_neighbors.add(neighbor_ip)
                        state = peers[neighbor_ip].get('state', '')
                        if state != 'Established':
                            return False
        except Exception:
            return False
    # Verify all expected neighbors were found in at least one namespace
    missing = set(bgp_neighbor_ips) - found_neighbors
    if missing:
        logger.debug("BGP neighbors not found in summary: %s", ", ".join(missing))
        return False
    return True


def _check_no_stale_routes(duthost, bgp_neighbor_ips):
    """Check that no routes from any neighbor are stale."""
    counts = _get_neighbor_route_counts(duthost, bgp_neighbor_ips)

    # Ensure we collected counts for every neighbor
    missing_neighbors = [n for n in bgp_neighbor_ips if n not in counts]
    if missing_neighbors:
        logger.debug("Failed to collect route counts for neighbors: %s", ",".join(missing_neighbors))
        return False

    for neighbor, count_info in counts.items():
        if count_info.get('stale', 0) > 0:
            logger.debug("Neighbor %s still has %d stale routes", neighbor, count_info['stale'])
            return False
        if count_info.get('valid', 0) == 0:
            logger.debug("Neighbor %s has 0 valid routes", neighbor)
            return False
    return True


def _get_asic_db_route_count(duthost):
    """Get route count from ASIC_DB.

    Counts ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY keys across all namespaces.
    Returns total count or None on failure.
    """
    total = 0
    for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
        if namespace:
            cmd = ("sonic-db-cli -n {} ASIC_DB eval "
                   "\"return #redis.call('keys','ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*')\" 0"
                   ).format(namespace)
        else:
            cmd = ("sonic-db-cli ASIC_DB eval "
                   "\"return #redis.call('keys','ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*')\" 0")
        try:
            result = duthost.shell(cmd, verbose=False)
            if result.get('rc', 1) != 0:
                logger.warning("Failed to query ASIC_DB routes in namespace '%s' (rc=%d)",
                               namespace, result.get('rc'))
                return None
            total += int(result['stdout'].strip())
        except Exception as e:
            logger.warning("Failed to get ASIC_DB route count in namespace '%s': %s", namespace, e)
            return None
    return total


def _get_gr_restart_timer(duthost, bgp_neighbor_ips):
    """Get the negotiated GR restart timer from FRR for the given neighbors.

    Returns the maximum restart timer across all neighbors (in seconds),
    or a default of 120s if the timer cannot be determined.
    """
    max_timer = 0
    default_timer = 120
    for neighbor_ip in bgp_neighbor_ips:
        for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
            cmd = duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c 'show bgp neighbor %s json'" % neighbor_ip, namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                neighbor_data = result.get(neighbor_ip, {})
                gr_info = neighbor_data.get('gracefulRestartInfo', {})
                # FRR reports the received restart timer from the peer
                timer = gr_info.get('timers', {}).get('receivedRestartTimer', 0)
                if timer > max_timer:
                    max_timer = timer
            except Exception as e:
                logger.warning("Failed to get GR timer for neighbor %s in namespace '%s': %s",
                               neighbor_ip, namespace, e)
    if max_timer > 0:
        logger.info("Negotiated GR restart timer: %ds (max across neighbors)", max_timer)
        return max_timer
    logger.info("Could not determine GR restart timer, using default %ds", default_timer)
    return default_timer


def test_bgp_gr_with_suppress_fib(duthosts, rand_one_dut_hostname, nbrhosts,
                                  setup_bgp_graceful_restart, enable_suppress_fib, tbinfo):
    """
    Test BGP Graceful Restart works correctly when suppress-fib-pending is enabled.

    This verifies the fix for the issue where EOR was sent before all routes were
    programmed into FIB when suppress-fib-pending was enabled (FRR PR #19522).

    Test steps:
    1. Enable suppress-fib-pending on DUT
    2. Enable GR on all neighbors
    3. Record routes and ASIC_DB route count before restart
    4. Restart BGP on DUT (systemctl restart bgp)
    5. Verify BGP sessions re-establish (using negotiated GR timer)
    6. Verify all routes are restored and not stale
    7. Verify ASIC_DB route count restored (FIB programmed)
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    bgp_neighbor_ips = list(bgp_neighbors.keys())

    if not bgp_neighbor_ips:
        pytest.skip("No BGP neighbors configured")

    # Step 1: Verify suppress-fib-pending is enabled
    result = duthost.shell('show suppress-fib-pending')
    pytest_assert('Enabled' in result['stdout'],
                  "suppress-fib-pending is not enabled")
    logger.info("suppress-fib-pending is enabled")

    # Step 2: Verify all BGP sessions are established before restart
    pytest_assert(
        wait_until(120, 10, 0, _check_all_bgp_sessions_established, duthost, bgp_neighbor_ips),
        "Not all BGP sessions are established before test"
    )
    logger.info("All %d BGP sessions are established", len(bgp_neighbor_ips))

    # Get the negotiated GR restart timer for appropriate wait timeouts
    gr_timer = _get_gr_restart_timer(duthost, bgp_neighbor_ips)
    # Buffer: GR timer + 60s for FIB programming and convergence
    gr_wait_timeout = gr_timer + 60

    # Step 3: Wait for routes to stabilize (all sessions fully converged)
    # After setup_bgp_graceful_restart configures neighbors, sessions may flap.
    # Wait until all sessions re-establish and route count stabilizes.
    pytest_assert(
        wait_until(180, 10, 30, _check_all_bgp_sessions_established, duthost, bgp_neighbor_ips),
        "BGP sessions not re-established after GR config"
    )
    pytest_assert(
        wait_until(120, 10, 0, lambda: _get_bgp_routes_summary(duthost) > 0),
        "No BGP routes received after sessions established"
    )

    # Wait for route count to stabilize: two consecutive reads must match
    def _routes_stabilized():
        count1 = _get_bgp_routes_summary(duthost)
        import time as _time
        _time.sleep(5)
        count2 = _get_bgp_routes_summary(duthost)
        return count1 == count2 and count1 > 0

    pytest_assert(
        wait_until(60, 10, 0, _routes_stabilized),
        "BGP route count did not stabilize after sessions established"
    )
    routes_before = _get_bgp_routes_summary(duthost)

    # Capture ASIC_DB route count before restart (ground truth for FIB)
    asic_db_before = _get_asic_db_route_count(duthost)
    if asic_db_before is None:
        logger.warning("Could not query ASIC_DB route count before restart")
        asic_db_before = 0
    logger.info("Before restart: %d BGP routes, %d ASIC_DB routes", routes_before, asic_db_before)

    # Step 4: Restart BGP on DUT
    logger.info("Restarting BGP service on DUT with suppress-fib-pending enabled")
    duthost.shell('sudo systemctl restart bgp')

    # Step 5: Wait for BGP sessions to re-establish
    # Use negotiated GR timer + buffer
    logger.info("Waiting for BGP sessions to re-establish (timeout: %ds)...", gr_wait_timeout)
    pytest_assert(
        wait_until(gr_wait_timeout, 10, 30, _check_all_bgp_sessions_established, duthost, bgp_neighbor_ips),
        "BGP sessions did not re-establish after restart with suppress-fib-pending enabled "
        "(GR timer: %ds)" % gr_timer
    )
    logger.info("All BGP sessions re-established after restart")

    # Step 6: Verify no stale routes remain (EOR was properly exchanged)
    logger.info("Verifying no stale routes remain...")
    pytest_assert(
        wait_until(180, 10, 10, _check_no_stale_routes, duthost, bgp_neighbor_ips),
        "Stale routes remain after BGP restart with suppress-fib-pending - "
        "EOR may have been sent prematurely before routes were programmed"
    )

    # Step 7: Wait for BGP route count to fully converge
    pytest_assert(
        wait_until(180, 10, 0, lambda: _get_bgp_routes_summary(duthost) >= routes_before),
        "Routes did not fully recover to pre-restart count (%d) "
        "after BGP restart with suppress-fib-pending" % routes_before
    )
    routes_after = _get_bgp_routes_summary(duthost)
    logger.info("After restart: %d BGP routes (before: %d)", routes_after, routes_before)

    # Verify each neighbor has contributed routes
    neighbor_counts_after = _get_neighbor_route_counts(duthost, bgp_neighbor_ips)
    for neighbor, counts in neighbor_counts_after.items():
        logger.info(
            "  Neighbor %s: all=%d valid=%d stale=%d",
            neighbor, counts['all'], counts['valid'], counts['stale'])

    # Step 8: Verify ASIC_DB route count restored (FIB programmed)
    # Compare ASIC_DB before vs after. If some routes were unprogrammed before
    # the restart (pre-existing condition), warn but don't fail on that delta.
    if asic_db_before > 0:
        def _asic_db_routes_restored():
            count = _get_asic_db_route_count(duthost)
            return count is not None and count >= asic_db_before

        pytest_assert(
            wait_until(120, 10, 0, _asic_db_routes_restored),
            "ASIC_DB route count did not recover to pre-restart level (%d). "
            "Routes may not have been programmed into FIB." % asic_db_before
        )
        asic_db_after = _get_asic_db_route_count(duthost)
        logger.info("ASIC_DB routes: before=%d after=%d", asic_db_before, asic_db_after)

        # Check for pre-existing unprogrammed routes (BGP received but not in ASIC_DB)
        bgp_vs_asic_gap_before = routes_before - asic_db_before
        bgp_vs_asic_gap_after = routes_after - (asic_db_after or 0)
        if bgp_vs_asic_gap_before > 0:
            logger.warning(
                "Pre-existing gap: %d BGP routes not programmed in ASIC_DB before restart "
                "(this is a pre-existing condition, not caused by GR)",
                bgp_vs_asic_gap_before)
        if bgp_vs_asic_gap_after > bgp_vs_asic_gap_before:
            # New routes appeared in BGP but not ASIC_DB after GR — this is a real problem
            new_gap = bgp_vs_asic_gap_after - bgp_vs_asic_gap_before
            pytest.fail(
                "After GR, %d new BGP routes are not programmed in ASIC_DB "
                "(gap before: %d, gap after: %d). "
                "suppress-fib-pending may not be working correctly."
                % (new_gap, bgp_vs_asic_gap_before, bgp_vs_asic_gap_after))
    else:
        logger.warning("Skipping ASIC_DB comparison: could not get baseline count")

    logger.info("BGP GR with suppress-fib-pending completed successfully. "
                "All routes restored and programmed in FIB.")


def test_bgp_gr_suppress_fib_neighbor_restart(duthosts, rand_one_dut_hostname, nbrhosts,
                                              setup_bgp_graceful_restart, enable_suppress_fib,
                                              tbinfo):
    """
    Test that DUT correctly handles neighbor GR when suppress-fib-pending is enabled.

    When a neighbor restarts with GR, the DUT (as GR helper) should:
    1. Keep stale routes during the neighbor restart
    2. After neighbor recovers, clear stale routes
    3. suppress-fib-pending should not interfere with GR helper mode

    This is complementary to test_bgp_gr_helper_routes_preserved but with
    suppress-fib-pending enabled.
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors_config = config_facts.get('BGP_NEIGHBOR', {})

    # Find a neighbor to restart
    test_neighbor_name = None
    test_bgp_neighbor_ips = []
    for bgp_ip, bgp_details in bgp_neighbors_config.items():
        name = bgp_details.get('name', '')
        if name in nbrhosts:
            if test_neighbor_name is None:
                test_neighbor_name = name
            if bgp_details.get('name') == test_neighbor_name:
                test_bgp_neighbor_ips.append(bgp_ip)

    if not test_neighbor_name or not test_bgp_neighbor_ips:
        pytest.skip("No suitable neighbor found for GR test")

    nbrhost = nbrhosts[test_neighbor_name]['host']
    logger.info(
        "Selected neighbor %s (IPs: %s) for GR test with suppress-fib-pending",
        test_neighbor_name, test_bgp_neighbor_ips)

    # Verify suppress-fib-pending is enabled
    result = duthost.shell('show suppress-fib-pending')
    pytest_assert('Enabled' in result['stdout'], "suppress-fib-pending is not enabled")

    # Get GR timer for appropriate wait timeouts
    gr_timer = _get_gr_restart_timer(duthost, test_bgp_neighbor_ips)
    gr_wait_timeout = gr_timer + 60

    # Verify BGP sessions are established
    pytest_assert(
        wait_until(120, 10, 0, duthost.check_bgp_session_state, test_bgp_neighbor_ips),
        "BGP sessions to %s not established before test" % test_neighbor_name
    )

    # Get routes from this neighbor before GR, counted per-namespace.
    # Each (namespace, neighbor) pair is tracked independently to avoid
    # undercounting on multi-ASIC systems with overlapping prefixes.
    routes_before = _get_neighbor_routes_per_namespace(duthost, test_bgp_neighbor_ips)
    total_before = _count_total_routes(routes_before)

    # Capture ASIC_DB baseline
    asic_db_before = _get_asic_db_route_count(duthost)
    logger.info("Neighbor %s has %d routes before GR (ASIC_DB: %s)",
                test_neighbor_name, total_before, asic_db_before)
    pytest_assert(total_before > 0, "No routes from neighbor %s" % test_neighbor_name)

    try:
        # Kill BGP on neighbor to trigger GR
        logger.info("Killing BGP on neighbor %s to trigger GR", test_neighbor_name)
        nbrhost.kill_bgpd()

        # Wait for DUT to detect neighbor restart
        logger.info("Waiting for DUT to detect neighbor %s restart...", test_neighbor_name)
        pytest_assert(
            wait_until(60, 5, 5, lambda: not duthost.check_bgp_session_state(test_bgp_neighbor_ips)),
            "BGP sessions to %s did not go down after killing BGP" % test_neighbor_name
        )
        logger.info("Neighbor BGP sessions detected as down - GR in progress")

        # Verify routes are preserved during GR (stale or still present)
        counts_during_gr = _get_neighbor_route_counts(duthost, test_bgp_neighbor_ips)
        for neighbor_ip, counts in counts_during_gr.items():
            logger.info(
                "During GR - Neighbor %s: all=%d stale=%d",
                neighbor_ip, counts['all'], counts['stale'])
            # Routes should still exist (stale or otherwise) during GR window
            pytest_assert(
                counts['all'] > 0,
                "Routes from neighbor %s disappeared during GR with suppress-fib-pending" % neighbor_ip
            )

    except Exception:
        nbrhost.start_bgpd()
        raise

    # Restart BGP on neighbor
    logger.info("Restarting BGP on neighbor %s", test_neighbor_name)
    nbrhost.start_bgpd()

    # Wait for BGP sessions to re-establish using negotiated GR timer
    logger.info("Waiting for BGP sessions to re-establish (timeout: %ds)...", gr_wait_timeout)
    pytest_assert(
        wait_until(gr_wait_timeout, 10, 0, duthost.check_bgp_session_state, test_bgp_neighbor_ips),
        "BGP sessions to %s did not re-establish after GR (GR timer: %ds)" % (test_neighbor_name, gr_timer)
    )
    logger.info("BGP sessions re-established after neighbor GR")

    # Verify no stale routes remain
    pytest_assert(
        wait_until(120, 10, 0, _check_no_stale_routes, duthost, test_bgp_neighbor_ips),
        "Stale routes remain after neighbor GR with suppress-fib-pending enabled"
    )

    # Verify route count restored (100%, no tolerance) with wait for convergence
    def _routes_restored():
        routes_after = _get_neighbor_routes_per_namespace(duthost, test_bgp_neighbor_ips)
        return _count_total_routes(routes_after) >= total_before

    pytest_assert(
        wait_until(120, 10, 0, _routes_restored),
        "Routes not fully restored after neighbor GR with suppress-fib-pending "
        "(expected >= %d)" % total_before
    )

    # Final snapshot for logging
    routes_after = _get_neighbor_routes_per_namespace(duthost, test_bgp_neighbor_ips)
    total_after = _count_total_routes(routes_after)
    logger.info("After GR: %d routes (before: %d)", total_after, total_before)

    # Verify ASIC_DB route count (FIB programming)
    if asic_db_before is not None and asic_db_before > 0:
        def _asic_db_restored():
            count = _get_asic_db_route_count(duthost)
            return count is not None and count >= asic_db_before

        pytest_assert(
            wait_until(120, 10, 0, _asic_db_restored),
            "ASIC_DB route count did not recover after neighbor GR "
            "(before: %d)" % asic_db_before
        )
        asic_db_after = _get_asic_db_route_count(duthost)
        logger.info("ASIC_DB routes: before=%d after=%d", asic_db_before, asic_db_after)

        # Warn on pre-existing gap, fail on new gap
        gap_before = total_before - asic_db_before if total_before > asic_db_before else 0
        gap_after = total_after - (asic_db_after or 0) if total_after > (asic_db_after or 0) else 0
        if gap_before > 0:
            logger.warning(
                "Pre-existing gap: %d routes not in ASIC_DB before GR (not caused by GR)",
                gap_before)
        if gap_after > gap_before:
            pytest.fail(
                "After GR, %d new routes not programmed in ASIC_DB "
                "(gap before: %d, gap after: %d)"
                % (gap_after - gap_before, gap_before, gap_after))

    logger.info("Neighbor GR with suppress-fib-pending completed successfully")
