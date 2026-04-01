"""
Tests for BGP aggregate-address config persistence and recovery (Test Group 5).

Validates that aggregate address configuration survives disruptions:
  TC 5.1: BGP container restart
  TC 5.2: Config reload
  TC 5.3: Config save and cold reboot
  TC 5.4: BGP container restart with BBR-required inactive aggregate
  TC 5.5: Warm reboot

Aligned with:
  https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md

Verification approach:
  Pre-disruption: verify CONFIG_DB only (GCU write is synchronous).
  Post-disruption: full CONFIG_DB + STATE_DB + FRR running-config check
  (the disruption restarts bgpcfgd, which populates STATE_DB and FRR).
"""

import logging

import pytest

from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from bgp_aggregate_helpers import (
    AggregateCfg,
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    dump_db,
    gcu_add_aggregate,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
    verify_bgp_aggregate_consistence,
    verify_bgp_aggregate_cleanup,
)

from test_bgp_aggregate_address import (
    AGGR_V4,
    AGGR_V6,
)

from tests.common.config_reload import config_reload
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_virtual_platform
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
    pytest.mark.disable_loganalyzer,
]

# ---- Constants ----
BGP_SESSION_WAIT_TIMEOUT = 300
BGP_SESSION_POLL_INTERVAL = 10


# ---- Module-scoped setup/teardown ----
@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    """Checkpoint before tests, rollback + re-save config after.

    TC5.2/TC5.3/TC5.5 run 'config save -y' before a disruption.  If the test
    fails after save but before per-test cleanup, the aggregate persists in the
    on-disk config_db.json.  Re-saving after rollback ensures the saved config
    matches the rolled-back (clean) state.
    """
    create_checkpoint(duthost)

    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
        duthost.shell("sudo config save -y")
    finally:
        delete_checkpoint(duthost)


# ---- Fixtures ----
@pytest.fixture(scope="module")
def bgp_neighbors(duthosts, rand_one_dut_hostname):
    """Return list of BGP neighbor IPs for session-state polling after disruptions."""
    duthost = duthosts[rand_one_dut_hostname]
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    return list(config_facts.get("BGP_NEIGHBOR", {}).keys())


# ---- Helpers ----
def wait_for_bgp_sessions(duthost, bgp_neighbors):
    """Block until all BGP sessions reach Established state."""
    pytest_assert(
        wait_until(BGP_SESSION_WAIT_TIMEOUT, BGP_SESSION_POLL_INTERVAL, 0,
                   duthost.check_bgp_session_state, bgp_neighbors),
        "Not all BGP sessions re-established within timeout"
    )


def verify_config_db_aggregate(duthost, cfg):
    """Lightweight pre-disruption check: only verify CONFIG_DB has the aggregate.

    GCU writes CONFIG_DB synchronously, so this always succeeds immediately.
    STATE_DB and FRR depend on bgpcfgd which may be stale after a previous
    test session's rollback; those are verified post-disruption instead.
    """
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in config_db, f"Aggregate row {cfg.prefix} not found in CONFIG_DB")
    pytest_assert(
        config_db[cfg.prefix].get("bbr-required") == ("true" if cfg.bbr_required else "false"),
        "bbr-required flag mismatch in CONFIG_DB",
    )
    pytest_assert(
        config_db[cfg.prefix].get("summary-only") == ("true" if cfg.summary_only else "false"),
        "summary-only flag mismatch in CONFIG_DB",
    )
    pytest_assert(
        config_db[cfg.prefix].get("as-set") == ("true" if cfg.as_set else "false"),
        "as-set flag mismatch in CONFIG_DB",
    )


def _state_db_has_prefix(duthost, prefix):
    """Return True when bgpcfgd has populated STATE_DB for the given prefix."""
    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    return prefix in state_db


def wait_for_aggregate_state(duthost, prefix, timeout=60):
    """Poll until bgpcfgd populates STATE_DB for the aggregate prefix.

    GCU writes CONFIG_DB synchronously, but bgpcfgd processes the change
    and writes STATE_DB asynchronously. This helper bridges the race after
    a disruption that restarts bgpcfgd.
    """
    pytest_assert(
        wait_until(timeout, 5, 0, _state_db_has_prefix, duthost, prefix),
        f"STATE_DB entry for {prefix} not populated within {timeout}s"
    )


# ===========================================================================
# Test Case 5.1 — BGP container restart
# ===========================================================================
def test_aggregate_persists_bgp_container_restart(
    duthosts, rand_one_dut_hostname, bgp_neighbors
):
    """
    TC 5.1: Aggregate address config survives BGP container restart.

    Steps:
      1. Add aggregate via GCU, verify CONFIG_DB.
      2. Restart BGP container.
      3. Wait for BGP sessions to re-establish.
      4. Verify full consistency (CONFIG_DB + STATE_DB + FRR).
    """
    duthost = duthosts[rand_one_dut_hostname]
    bbr_enabled = is_bbr_enabled(duthost)
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)

    try:
        gcu_add_aggregate(duthost, cfg)
        verify_config_db_aggregate(duthost, cfg)

        duthost.shell("sudo systemctl restart bgp")
        wait_for_bgp_sessions(duthost, bgp_neighbors)

        wait_for_aggregate_state(duthost, cfg.prefix)
        verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)
    finally:
        try:
            gcu_remove_aggregate(duthost, cfg.prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s, will be recovered by rollback", cfg.prefix)
        verify_bgp_aggregate_cleanup(duthost, cfg.prefix)


# ===========================================================================
# Test Case 5.2 — Config reload
# ===========================================================================
def test_aggregate_persists_config_reload(
    duthosts, rand_one_dut_hostname, bgp_neighbors
):
    """
    TC 5.2: Aggregate address config survives config reload.

    Steps:
      1. Add aggregate with summary-only=true via GCU, verify CONFIG_DB.
      2. Save config and execute config reload.
      3. Wait for BGP sessions.
      4. Verify full consistency after reload.
    """
    duthost = duthosts[rand_one_dut_hostname]
    bbr_enabled = is_bbr_enabled(duthost)
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=True, as_set=False)

    try:
        gcu_add_aggregate(duthost, cfg)
        verify_config_db_aggregate(duthost, cfg)

        duthost.shell("sudo config save -y")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        wait_for_bgp_sessions(duthost, bgp_neighbors)

        wait_for_aggregate_state(duthost, cfg.prefix)
        verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)
    finally:
        try:
            gcu_remove_aggregate(duthost, cfg.prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s, will be recovered by rollback", cfg.prefix)
        verify_bgp_aggregate_cleanup(duthost, cfg.prefix)


# ===========================================================================
# Test Case 5.3 — Config save and cold reboot
# ===========================================================================
def test_aggregate_persists_config_save_and_reboot(
    duthosts, rand_one_dut_hostname, localhost, bgp_neighbors
):
    """
    TC 5.3: Aggregate address config survives config save followed by cold reboot.

    Steps:
      1. Add IPv6 aggregate via GCU, verify CONFIG_DB.
      2. Save config and cold reboot.
      3. Wait for BGP sessions.
      4. Verify full consistency after reboot.
    """
    duthost = duthosts[rand_one_dut_hostname]
    bbr_enabled = is_bbr_enabled(duthost)
    cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=False, summary_only=False, as_set=False)

    try:
        gcu_add_aggregate(duthost, cfg)
        verify_config_db_aggregate(duthost, cfg)

        duthost.shell("sudo config save -y")
        reboot(duthost, localhost, reboot_type="cold", safe_reboot=True,
               check_intf_up_ports=True, wait_for_bgp=True)
        wait_for_bgp_sessions(duthost, bgp_neighbors)

        wait_for_aggregate_state(duthost, cfg.prefix)
        verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)
    finally:
        try:
            gcu_remove_aggregate(duthost, cfg.prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s, will be recovered by rollback", cfg.prefix)
        verify_bgp_aggregate_cleanup(duthost, cfg.prefix)


# ===========================================================================
# Test Case 5.4 — BGP container restart with BBR-required inactive aggregate
# ===========================================================================
def test_aggregate_bbr_required_inactive_persists_bgp_restart(
    duthosts, rand_one_dut_hostname, bgp_neighbors
):
    """
    TC 5.4: BBR-required aggregate stays inactive after BGP restart when BBR
    is disabled, then activates once BBR is enabled.

    Steps:
      1. Disable BBR.
      2. Add BBR-required aggregate, verify CONFIG_DB.
      3. Restart BGP container — verify still inactive.
      4. Enable BBR — verify aggregate now active.
    """
    duthost = duthosts[rand_one_dut_hostname]
    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip("BGP BBR is not supported")

    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=True, summary_only=False, as_set=False)

    try:
        # Ensure BBR is disabled
        if bbr_default_state == "enabled":
            config_bbr_by_gcu(duthost, "disabled")

        gcu_add_aggregate(duthost, cfg)
        verify_config_db_aggregate(duthost, cfg)

        duthost.shell("sudo systemctl restart bgp")
        wait_for_bgp_sessions(duthost, bgp_neighbors)

        wait_for_aggregate_state(duthost, cfg.prefix)
        verify_bgp_aggregate_consistence(duthost, False, cfg)

        # Enable BBR — aggregate should become active
        config_bbr_by_gcu(duthost, "enabled")
        verify_bgp_aggregate_consistence(duthost, True, cfg)
    finally:
        try:
            gcu_remove_aggregate(duthost, cfg.prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s, will be recovered by rollback", cfg.prefix)
        verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
        # Restore BBR to original state
        try:
            config_bbr_by_gcu(duthost, bbr_default_state)
        except Exception:
            logger.warning("Cleanup: failed to restore BBR state to %s", bbr_default_state)


# ===========================================================================
# Test Case 5.5 — Warm reboot
# ===========================================================================
def test_aggregate_persists_warm_reboot(
    duthosts, rand_one_dut_hostname, localhost, bgp_neighbors
):
    """
    TC 5.5: Aggregate address config survives warm reboot.

    Steps:
      1. Add aggregate via GCU, save config, verify CONFIG_DB.
      2. Warm reboot.
      3. Wait for BGP sessions.
      4. Verify full consistency after warm reboot.
    """
    duthost = duthosts[rand_one_dut_hostname]
    bbr_enabled = is_bbr_enabled(duthost)
    cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)

    # On KVM/VS the warm-reboot script's 1 s docker-exec health check is too
    # tight, causing fpmsyncd/orchagent crashes.  Apply the same timeout bump
    # that AdvancedReboot uses (tests/common/fixtures/advanced_reboot.py).
    if is_virtual_platform(duthost):
        warmboot_script = duthost.shell("which warm-reboot")["stdout"].strip()
        cmd_format = "sed -i 's/{}/{}/' {}"
        original_line = 'timeout 1s docker exec $container echo "success"'
        replaced_line = 'timeout 5s docker exec $container echo "success"'
        duthost.shell(cmd_format.format(original_line, replaced_line, warmboot_script))

    try:
        gcu_add_aggregate(duthost, cfg)
        duthost.shell("sudo config save -y")
        verify_config_db_aggregate(duthost, cfg)

        reboot(duthost, localhost, reboot_type="warm", safe_reboot=True,
               check_intf_up_ports=True, wait_for_bgp=True,
               wait_warmboot_finalizer=True)
        wait_for_bgp_sessions(duthost, bgp_neighbors)

        wait_for_aggregate_state(duthost, cfg.prefix)
        verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)
    finally:
        try:
            gcu_remove_aggregate(duthost, cfg.prefix)
        except Exception:
            logger.warning("Cleanup: failed to remove aggregate %s, will be recovered by rollback", cfg.prefix)
        verify_bgp_aggregate_cleanup(duthost, cfg.prefix)
