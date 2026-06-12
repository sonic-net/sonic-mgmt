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
import re
import time

import pytest

from bgp_aggregate_helpers import (
    BGP_AGGREGATE_ADDRESS,
    PLACEHOLDER_PREFIX,
    AggregateCfg,
    dump_db,
    gcu_add_aggregate,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
    verify_bgp_aggregate_consistence,
    verify_bgp_aggregate_cleanup,
)

from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from tests.common.config_reload import config_reload
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_virtual_platform
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
]

# ---- Constants ----
AGGR_V4 = "172.16.51.0/24"
AGGR_V6 = "2000:172:16:50::/64"
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


@pytest.fixture(autouse=True)
def ignore_disruption_loganalyzer_noise(duthost, loganalyzer):
    """Ignore transient ERR logs caused by reload/reboot disruptions.

    - iptables TACACS noise: every reload/iptables-change moment briefly
      breaks DUT->TACACS reachability; the existing common-ignore rule for
      `nss_tacplus: failed to connect TACACS+ server` has an unescaped '+'
      and does not actually match, so we add a properly-escaped pair here.
      The sibling `tac_connect_single: ... Network is unreachable` line has
      no common-ignore at all, add it too.
    """
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".* ERR iptables: nss_tacplus: failed to connect TACACS\+ server .*",
            r".* ERR iptables: tac_connect_single: connection to .* failed: "
            r"Network is unreachable.*",
            r".* ERR iptables: tac_author_read: reply timeout after \d+ secs.*",
        ])
    yield


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
# Cold reboot truncates /var/log/syslog so the LogAnalyzer start marker is
# lost; disable LogAnalyzer for this test (matches the pattern used by other
# reboot-based tests in the repo).
@pytest.mark.disable_loganalyzer
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
# Warm reboot rotates/truncates /var/log/syslog so the LogAnalyzer start
# marker is lost; disable LogAnalyzer for this test (matches the pattern
# used by other reboot-based tests in the repo).
@pytest.mark.disable_loganalyzer
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


# ===========================================================================
# Test Cases 5.6 / 5.7 — bgpcfgd startup race on prefix-list aggregates
# ===========================================================================
#
# When a BGP_AGGREGATE_ADDRESS row carries the optional
# `aggregate-address-prefix-list` and `contributing-address-prefix-list`
# fields, bgpcfgd packs `router bgp ... / aggregate-address` (bgpd-routed)
# together with `ip prefix-list ... permit ...` (mgmtd-routed) into ONE
# `vtysh -f` invocation. On container restart, bgpcfgd may push that batch
# while mgmtd is still replaying frr.conf and holds the CONFIG datastore
# lock — the bgpd lines succeed (overall rc=0), but the mgmtd prefix-list
# lines are silently rejected. bgpcfgd does not inspect per-line stderr,
# stamps STATE_DB=active, and the divergence is invisible to
# CONFIG_DB / STATE_DB / `show running-config` checks.
#
# The only reliable oracle is comparing `aggregate-address` lines in
# running-config against the actual content of `show ip prefix-list <NAME>`.
#
# m1's frr.conf replay is small, so a single aggregate per restart is
# ~0% hit. We use a combined A+C strategy to force reproduction on idle m1:
#
#   (A) Scale population & rounds: NUM_RACE_AGGREGATES * RACE_RESTART_ROUNDS
#       = 200 * 8 = 1600 oracle samples per run (~7 min runtime).
#       On bjw3-can-7050c-7 (m1-128, 7050CX3-32C) observed per-trial hit-rate
#       is ~0.02-0.04%, giving ~30-50% cumulative detection probability per
#       single pytest invocation. Run multiple times in CI for >90% cumulative.
#
#   (C) Add NUM_FILLER_AGGREGATES filler rows that reference a SEPARATE
#       prefix-list (STRESS_ROUTES_V4). They are NOT checked by the oracle;
#       their only purpose is to bloat frr.conf so mgmtd's startup datastore
#       replay takes seconds instead of microseconds. This widens the lock
#       window during which AggregateAddressMgr's vtysh -f batches arrive,
#       which is exactly the race condition we want to hit.
NUM_RACE_AGGREGATES = 200
RACE_RESTART_ROUNDS = 8
NUM_FILLER_AGGREGATES = 200
RACE_AGG_PREFIX_LIST = "AGGREGATE_ROUTES_V4"
RACE_AGG_CONTRIB_PREFIX_LIST = "AGGREGATE_CONTRIBUTING_ROUTES_V4"
FILLER_AGG_PREFIX_LIST = "STRESS_ROUTES_V4"
FILLER_AGG_CONTRIB_PREFIX_LIST = "STRESS_CONTRIBUTING_ROUTES_V4"
RACE_POST_RESTART_CONVERGE_TIMEOUT = 300
RACE_INITIAL_PROGRAM_TIMEOUT = 180


def _race_prefixes(n=NUM_RACE_AGGREGATES):
    """Generate N distinct /16 prefixes for the race test (oracle-checked)."""
    # 10.0.0.0/16 .. 10.{N-1}.0.0/16
    return [f"10.{i}.0.0/16" for i in range(n)]


def _filler_prefixes(n=NUM_FILLER_AGGREGATES):
    """Generate N distinct /16 prefixes for filler stress (NOT oracle-checked).

    Uses 11.x.0.0/16 to stay clear of any 10.x test traffic and of the race
    prefix range. These rows exist only to inflate frr.conf so mgmtd's
    startup replay holds the CONFIG datastore lock longer, widening the
    AggregateAddressMgr race window.
    """
    return [f"11.{i}.0.0/16" for i in range(n)]


def _add_aggregate_with_pl(duthost, prefix, pl_name, contrib_pl_name):
    """HSET a BGP_AGGREGATE_ADDRESS row with both prefix-list fields populated.

    This is what makes bgpcfgd emit a mixed bgpd + mgmtd cmd_list — the
    necessary precondition (R1+R2) for the race.
    """
    duthost.shell(
        f"sonic-db-cli CONFIG_DB HSET 'BGP_AGGREGATE_ADDRESS|{prefix}' "
        f"bbr-required false summary-only false as-set false "
        f"aggregate-address-prefix-list {pl_name} "
        f"contributing-address-prefix-list {contrib_pl_name}"
    )


def _add_race_aggregate(duthost, prefix):
    _add_aggregate_with_pl(
        duthost, prefix, RACE_AGG_PREFIX_LIST, RACE_AGG_CONTRIB_PREFIX_LIST
    )


def _add_filler_aggregate(duthost, prefix):
    _add_aggregate_with_pl(
        duthost, prefix, FILLER_AGG_PREFIX_LIST, FILLER_AGG_CONTRIB_PREFIX_LIST
    )


def _del_race_aggregate(duthost, prefix):
    duthost.shell(
        f"sonic-db-cli CONFIG_DB DEL 'BGP_AGGREGATE_ADDRESS|{prefix}'",
        module_ignore_errors=True,
    )


def _aggregates_in_running_config(duthost):
    """Set of prefixes that appear as `aggregate-address <prefix>` in FRR."""
    out = duthost.shell(
        "sudo vtysh -c 'show running-config'", module_ignore_errors=True
    )["stdout"]
    return set(re.findall(r"^\s+aggregate-address\s+(\S+)", out, re.MULTILINE))


def _aggregates_in_prefix_list(duthost, pl_name):
    """Set of prefixes that appear as `permit <prefix>` in the given prefix-list.

    Strips any le/ge suffix and collapses ZEBRA + BGP views to a unique set.
    """
    out = duthost.shell(
        f"vtysh -c 'show ip prefix-list {pl_name}'", module_ignore_errors=True
    )["stdout"]
    return set(re.findall(r"permit\s+(\d+\.\d+\.\d+\.\d+/\d+)", out))


def _race_diff(duthost, expected_prefixes):
    """Return (missing_from_pl, missing_from_rc) restricted to the race set."""
    expected = set(expected_prefixes)
    rc = _aggregates_in_running_config(duthost) & expected
    pl = _aggregates_in_prefix_list(duthost, RACE_AGG_PREFIX_LIST) & expected
    return sorted(rc - pl), sorted(expected - rc)


def _wait_race_initial_program(duthost, expected_prefixes, filler_prefixes=()):
    """Wait until bgpcfgd has programmed all aggregates into FRR + prefix-list.

    Checks both the race set (in RACE_AGG_PREFIX_LIST) and the filler set
    (in FILLER_AGG_PREFIX_LIST) so we don't restart bgp until the entire
    400-row baseline is in place.
    """
    race_expected = set(expected_prefixes)
    filler_expected = set(filler_prefixes)
    all_expected = race_expected | filler_expected

    def _ready():
        rc = _aggregates_in_running_config(duthost)
        if not (rc >= all_expected):
            return False
        if not (_aggregates_in_prefix_list(duthost, RACE_AGG_PREFIX_LIST) >= race_expected):
            return False
        if filler_expected and not (
            _aggregates_in_prefix_list(duthost, FILLER_AGG_PREFIX_LIST) >= filler_expected
        ):
            return False
        return True

    pytest_assert(
        wait_until(RACE_INITIAL_PROGRAM_TIMEOUT, 5, 0, _ready),
        "Initial programming of race + filler aggregates did not converge "
        "(prefix-list or running-config missing entries before restart)",
    )


def _run_race_test(duthost, bgp_neighbors, trigger_fn, trigger_label):
    """Shared body for TC 5.6 / 5.7. trigger_fn(duthost) performs the disruption."""
    prefixes = _race_prefixes()
    fillers = _filler_prefixes()
    all_aggregates = set(prefixes) | set(fillers)
    try:
        logger.info(
            "Pre-installing %d race + %d filler aggregates (oracle checks race only)",
            len(prefixes), len(fillers),
        )
        for p in prefixes:
            _add_race_aggregate(duthost, p)
        for p in fillers:
            _add_filler_aggregate(duthost, p)
        _wait_race_initial_program(duthost, prefixes, fillers)

        for rnd in range(1, RACE_RESTART_ROUNDS + 1):
            logger.info(
                "[%s] race-detect round %d/%d (race=%d, filler=%d)",
                trigger_label, rnd, RACE_RESTART_ROUNDS, len(prefixes), len(fillers),
            )
            trigger_fn(duthost)
            wait_for_bgp_sessions(duthost, bgp_neighbors)

            # Wait for bgpcfgd to drain ALL aggregates (race + filler) back
            # into running-config. Checking too early races bgpcfgd's own
            # batch drain and produces transient missing_from_pl results
            # that have nothing to do with the bgpcfgd startup race we are
            # hunting.
            def _rc_has_all():
                return _aggregates_in_running_config(duthost) >= all_aggregates

            pytest_assert(
                wait_until(RACE_POST_RESTART_CONVERGE_TIMEOUT, 5, 0, _rc_has_all),
                f"[{trigger_label} round {rnd}] bgpcfgd did not finish pushing "
                f"all {len(all_aggregates)} aggregates back into running-config within "
                f"{RACE_POST_RESTART_CONVERGE_TIMEOUT}s after restart.",
            )
            # Settle: let any in-flight mgmtd prefix-list commits land before
            # sampling the oracle. The race bug leaves PERMANENT divergence;
            # this sleep only filters transient inflight states.
            time.sleep(5)

            missing_from_pl, missing_from_rc = _race_diff(duthost, prefixes)
            pytest_assert(
                not missing_from_pl,
                f"[{trigger_label} round {rnd}] bgpcfgd startup race triggered: "
                f"{len(missing_from_pl)}/{len(prefixes)} aggregate(s) present as "
                f"`aggregate-address` in running-config but MISSING from prefix-list "
                f"{RACE_AGG_PREFIX_LIST}: {missing_from_pl}. "
                f"See doc/bgpcfgd-aggregate-prefix-list-race-bug.md."
            )
            if missing_from_rc:
                logger.warning(
                    "[%s round %d] %d aggregate(s) missing from running-config too: %s",
                    trigger_label, rnd, len(missing_from_rc), missing_from_rc,
                )
    finally:
        for p in prefixes:
            _del_race_aggregate(duthost, p)
        for p in fillers:
            _del_race_aggregate(duthost, p)


# ===========================================================================
# Test Case 5.6 — prefix-list aggregates survive BGP container restart
# ===========================================================================
def test_aggregate_prefix_list_survives_bgp_restart_race(
    duthosts, rand_one_dut_hostname, bgp_neighbors,
):
    """
    TC 5.6: After `systemctl restart bgp`, every aggregate-address still
    advertised by FRR MUST also have its `ip prefix-list` entry programmed
    in mgmtd. Catches the bgpcfgd startup race where mixed bgpd+mgmtd
    `vtysh -f` batches partially fail while mgmtd is still locking the
    CONFIG datastore during frr.conf replay.

    Scale: 50 aggregates x 3 restart rounds (~95% cumulative detection on
    idle m1 given observed ~2% per-aggregate-per-restart hit rate).
    """
    duthost = duthosts[rand_one_dut_hostname]

    def _restart_bgp(dh):
        dh.shell("sudo systemctl reset-failed bgp.service", module_ignore_errors=True)
        dh.shell("sudo systemctl restart bgp")

    _run_race_test(duthost, bgp_neighbors, _restart_bgp, "systemctl restart bgp")


# ===========================================================================
# Test Case 5.7 — prefix-list aggregates survive `config reload`
# ===========================================================================
def test_aggregate_prefix_list_survives_config_reload_race(
    duthosts, rand_one_dut_hostname, bgp_neighbors,
):
    """
    TC 5.7: Same invariant as TC 5.6 but triggered by `sudo config reload -y -f`.
    Per bug doc tier12 evidence, config reload internally stops sonic.target,
    which restarts the bgp container through the same supervisor lifecycle —
    confirming the race lives in the bgp container's startup pipeline, not in
    the choice of restart command.
    """
    duthost = duthosts[rand_one_dut_hostname]

    def _config_reload(dh):
        config_reload(dh, safe_reload=True, check_intf_up_ports=True)

    _run_race_test(duthost, bgp_neighbors, _config_reload, "config reload -y -f")
