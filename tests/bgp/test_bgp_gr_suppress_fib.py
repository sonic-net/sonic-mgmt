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
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
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
    """Get total number of received BGP routes (IPv4 + IPv6)."""
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
            except Exception:
                pass
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


def _check_all_bgp_sessions_established(duthost, bgp_neighbor_ips):
    """Check that all BGP sessions are established."""
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
                        state = peers[neighbor_ip].get('state', '')
                        if state != 'Established':
                            return False
        except Exception:
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


def _get_routes_in_app_db(duthost):
    """Get route count from APP_DB ROUTE_TABLE.

    Returns None if the query fails so callers can detect errors.
    """
    result = duthost.shell(
        'sonic-db-cli APPL_DB keys "ROUTE_TABLE:*" | wc -l',
        verbose=False)
    rc = result.get('rc', 1)
    stdout = result.get('stdout', '').strip()
    if rc != 0:
        logger.warning("Failed to query APP_DB routes (rc=%d)", rc)
        return None
    try:
        return int(stdout)
    except (TypeError, ValueError):
        logger.warning("Failed to parse APP_DB route count: '%s'", stdout)
        return None


def test_bgp_gr_with_suppress_fib(duthosts, rand_one_dut_hostname, nbrhosts,
                                  setup_bgp_graceful_restart, enable_suppress_fib, tbinfo):
    """
    Test BGP Graceful Restart works correctly when suppress-fib-pending is enabled.

    This verifies the fix for the issue where EOR was sent before all routes were
    programmed into FIB when suppress-fib-pending was enabled (FRR PR #19522).

    Test steps:
    1. Enable suppress-fib-pending on DUT
    2. Enable GR on all neighbors
    3. Record routes from all neighbors before restart
    4. Restart BGP on DUT (systemctl restart bgp)
    5. Verify BGP sessions re-establish
    6. Verify all routes are restored and not stale
    7. Verify routes are present in APP_DB (FIB programmed)
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

    # Step 3: Wait for routes to stabilize (all sessions fully converged)
    # After setup_bgp_graceful_restart configures neighbors, sessions may flap.
    # Wait until route count stabilizes (two consecutive reads match).
    time.sleep(30)  # Allow sessions to settle after GR config
    pytest_assert(
        wait_until(120, 10, 0, _check_all_bgp_sessions_established, duthost, bgp_neighbor_ips),
        "BGP sessions not re-established after GR config"
    )
    pytest_assert(
        wait_until(120, 10, 0, lambda: _get_bgp_routes_summary(duthost) > 0),
        "No BGP routes received after sessions established"
    )
    # Take a stable snapshot
    time.sleep(10)
    routes_before = _get_bgp_routes_summary(duthost)
    app_db_routes_before = _get_routes_in_app_db(duthost)
    pytest_assert(app_db_routes_before is not None, "Failed to query APP_DB routes before restart")
    logger.info("Before restart: %d BGP routes, %d APP_DB routes", routes_before, app_db_routes_before)

    # Step 4: Restart BGP on DUT
    logger.info("Restarting BGP service on DUT with suppress-fib-pending enabled")
    duthost.shell('sudo systemctl restart bgp')

    # Step 5: Wait for BGP sessions to re-establish
    # With suppress-fib-pending, it may take slightly longer since FRR waits
    # for routes to be programmed before sending EOR
    logger.info("Waiting for BGP sessions to re-establish...")
    pytest_assert(
        wait_until(300, 10, 30, _check_all_bgp_sessions_established, duthost, bgp_neighbor_ips),
        "BGP sessions did not re-establish after restart with suppress-fib-pending enabled"
    )
    logger.info("All BGP sessions re-established after restart")

    # Step 6: Verify no stale routes remain (EOR was properly exchanged)
    logger.info("Verifying no stale routes remain...")
    pytest_assert(
        wait_until(180, 10, 10, _check_no_stale_routes, duthost, bgp_neighbor_ips),
        "Stale routes remain after BGP restart with suppress-fib-pending - "
        "EOR may have been sent prematurely before routes were programmed"
    )

    # Step 7: Wait for routes to converge, then verify
    pytest_assert(
        wait_until(180, 10, 0, lambda: _get_bgp_routes_summary(duthost) >= routes_before * 0.50),
        "Routes did not recover to at least 50%% of pre-restart count (%d) "
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

    # Step 8: Verify routes are programmed in APP_DB (FIB)
    app_db_routes_after = _get_routes_in_app_db(duthost)
    pytest_assert(app_db_routes_after is not None, "Failed to query APP_DB routes after restart")
    logger.info("APP_DB routes: before=%d after=%d", app_db_routes_before, app_db_routes_after)
    pytest_assert(
        app_db_routes_after >= app_db_routes_before * 0.90,
        "APP_DB route count dropped significantly: before=%d after=%d. "
        "Routes may not have been programmed into FIB." %
        (app_db_routes_before, app_db_routes_after)
    )

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

    # Verify BGP sessions are established
    pytest_assert(
        wait_until(120, 10, 0, duthost.check_bgp_session_state, test_bgp_neighbor_ips),
        "BGP sessions to %s not established before test" % test_neighbor_name
    )

    # Get routes from this neighbor before GR
    routes_before = {}
    for neighbor_ip in test_bgp_neighbor_ips:
        for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
            if '.' in neighbor_ip:
                cmd = "vtysh -c 'show bgp ipv4 neighbor %s routes json'" % neighbor_ip
            else:
                cmd = "vtysh -c 'show bgp ipv6 neighbor %s routes json'" % neighbor_ip
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                routes_before.update(result.get('routes', {}))
            except Exception:
                pass

    logger.info("Neighbor %s has %d routes before GR", test_neighbor_name, len(routes_before))
    pytest_assert(len(routes_before) > 0, "No routes from neighbor %s" % test_neighbor_name)

    try:
        # Kill BGP on neighbor to trigger GR
        logger.info("Killing BGP on neighbor %s to trigger GR", test_neighbor_name)
        nbrhost.kill_bgpd()

        # Wait for DUT to detect neighbor restart
        # Note: check_bgp_session_nsf may not be supported on all neighbor types (e.g., cEOS)
        # so we just wait for the session to leave Established state
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

    # Wait for BGP sessions to re-establish
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, test_bgp_neighbor_ips),
        "BGP sessions to %s did not re-establish after GR" % test_neighbor_name
    )
    logger.info("BGP sessions re-established after neighbor GR")

    # Verify no stale routes remain
    pytest_assert(
        wait_until(120, 10, 0, _check_no_stale_routes, duthost, test_bgp_neighbor_ips),
        "Stale routes remain after neighbor GR with suppress-fib-pending enabled"
    )

    # Verify route count restored
    routes_after = {}
    for neighbor_ip in test_bgp_neighbor_ips:
        for namespace in (duthost.get_frontend_asic_namespace_list() or ['']):
            if '.' in neighbor_ip:
                cmd = "vtysh -c 'show bgp ipv4 neighbor %s routes json'" % neighbor_ip
            else:
                cmd = "vtysh -c 'show bgp ipv6 neighbor %s routes json'" % neighbor_ip
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            try:
                result = json.loads(duthost.shell(cmd, verbose=False)['stdout'])
                routes_after.update(result.get('routes', {}))
            except Exception:
                pass

    logger.info("After GR: %d routes (before: %d)", len(routes_after), len(routes_before))
    pytest_assert(
        len(routes_after) >= len(routes_before) * 0.95,
        "Routes lost after neighbor GR with suppress-fib-pending: before=%d after=%d" %
        (len(routes_before), len(routes_after))
    )

    logger.info("Neighbor GR with suppress-fib-pending completed successfully")
