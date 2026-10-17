"""Monitor Link Group HLD coverage tests.

Each test covers one numbered scenario from the HLD:

    test_scenario_01_create_with_monitored_up
    test_scenario_04_create_with_monitored_down
    test_scenario_06_runtime_monitored_go_down
    test_scenario_07_monitored_recovers
    test_scenario_08_admin_down_managed_overrides_group
    test_scenario_14_three_groups_share_monitored
    test_scenario_15_three_groups_share_managed
"""

import time

import pytest

import monitor_link_helpers as mlg_helpers
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer,
]


def _require_intfs(mlg, count, label):
    pytest_require(
        len(mlg.pool.available()) >= count,
        "need {} usable interfaces ({})".format(count, label),
    )


def _require_portchannels(mlg, count):
    pytest_require(
        len(mlg.pool.available_portchannels()) >= count,
        "need {} usable PortChannel(s)".format(count),
    )


def test_scenario_01_create_with_monitored_up(duthosts, rand_one_dut_hostname, mlg):
    """HLD #1: Create group with all monitored up -> group UP, managed allow_up."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1),
    })

    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})
    mlg_helpers.assert_oper_states(duthost, {managed[0]: "up"})


def test_scenario_04_create_with_monitored_down(duthosts, rand_one_dut_hostname, mlg):
    """HLD #4: Create group with all monitored down -> group DOWN, managed force_down."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg_helpers.assert_oper_states(duthost, {u: "down" for u in monitored})

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1),
    })

    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})
    mlg_helpers.assert_oper_states(duthost, {managed[0]: "down"})


def test_scenario_06_runtime_monitored_go_down(duthosts, rand_one_dut_hostname, mlg):
    """HLD #6: Group UP transitions to DOWN when all monitored drop."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    for u in monitored:
        mlg.shutdown(u)

    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})
    mlg_helpers.assert_oper_states(duthost, {managed[0]: "down"})


def test_scenario_07_monitored_recovers(duthosts, rand_one_dut_hostname, mlg):
    """HLD #7: After monitored drop, recovering one monitored-link (min_monitored_links=1) brings group UP."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    for u in monitored:
        mlg.shutdown(u)
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})

    mlg.no_shutdown(monitored[0])

    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})
    mlg_helpers.assert_oper_states(duthost, {managed[0]: "up"})


def test_scenario_08_admin_down_managed_overrides_group(duthosts, rand_one_dut_hostname, mlg):
    """HLD #8: Admin-down managed-link stays oper-down regardless of group transitions."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)
    managed_link = managed[0]

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_oper_states(duthost, {managed_link: "up"})

    mlg.shutdown(managed_link)
    mlg_helpers.wait_oper(duthost, managed_link, "down")

    for u in monitored:
        mlg.shutdown(u)
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.wait_oper(duthost, managed_link, "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {managed_link: "allow_up"})
    # Downlink itself remains admin-down -> still oper-down.
    mlg_helpers.wait_oper(duthost, managed_link, "down")


def test_scenario_14_three_groups_share_monitored(duthosts, rand_one_dut_hostname, mlg):
    """HLD #14: Three groups sharing monitored transition together."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 5, "2 shared monitored + 3 managed")
    shared_monitored = mlg.allocate(2)
    dls = [mlg.allocate(1)[0] for _ in range(3)]

    mlg.apply({
        "g1": mlg_helpers.make_group(shared_monitored, [dls[0]], min_monitored_links=1),
        "g2": mlg_helpers.make_group(shared_monitored, [dls[1]], min_monitored_links=1),
        "g3": mlg_helpers.make_group(shared_monitored, [dls[2]], min_monitored_links=1),
    })
    for name in ("g1", "g2", "g3"):
        mlg_helpers.wait_group_state(duthost, name, "up")
    mlg_helpers.assert_member_states(duthost, {d: "allow_up" for d in dls})

    for u in shared_monitored:
        mlg.shutdown(u)

    for name in ("g1", "g2", "g3"):
        mlg_helpers.wait_group_state(duthost, name, "down")
    mlg_helpers.assert_member_states(duthost, {d: "force_down" for d in dls})
    mlg_helpers.assert_oper_states(duthost, {d: "down" for d in dls})

    mlg.no_shutdown(shared_monitored[0])

    for name in ("g1", "g2", "g3"):
        mlg_helpers.wait_group_state(duthost, name, "up")
    mlg_helpers.assert_member_states(duthost, {d: "allow_up" for d in dls})
    mlg_helpers.assert_oper_states(duthost, {d: "up" for d in dls})


def test_scenario_15_three_groups_share_managed(duthosts, rand_one_dut_hostname, mlg):
    """HLD #15: Three groups sharing managed; managed UP only when ALL groups UP."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 8, "3x2 monitored + 2 shared managed")
    uls = [mlg.allocate(2) for _ in range(3)]
    shared_managed = mlg.allocate(2)

    mlg.apply({
        "g1": mlg_helpers.make_group(uls[0], shared_managed, min_monitored_links=1),
        "g2": mlg_helpers.make_group(uls[1], shared_managed, min_monitored_links=1),
        "g3": mlg_helpers.make_group(uls[2], shared_managed, min_monitored_links=1),
    })
    for name in ("g1", "g2", "g3"):
        mlg_helpers.wait_group_state(duthost, name, "up")
    mlg_helpers.assert_member_states(
        duthost, {d: "allow_up" for d in shared_managed}
    )
    mlg_helpers.assert_oper_states(duthost, {d: "up" for d in shared_managed})

    for u in uls[0]:
        mlg.shutdown(u)
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.wait_group_state(duthost, "g2", "up")
    mlg_helpers.wait_group_state(duthost, "g3", "up")

    # All shared managed held force_down because g1 is DOWN.
    mlg_helpers.assert_member_states(
        duthost, {d: "force_down" for d in shared_managed}
    )
    mlg_helpers.assert_oper_states(duthost, {d: "down" for d in shared_managed})

    mlg.no_shutdown(uls[0][0])
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg_helpers.assert_member_states(
        duthost, {d: "allow_up" for d in shared_managed}
    )
    mlg_helpers.assert_oper_states(duthost, {d: "up" for d in shared_managed})


# =============================================================================
# Corner-case tests (beyond the numbered HLD scenarios)
# =============================================================================


def test_corner_chained_groups_cross_role(duthosts, rand_one_dut_hostname, mlg):
    """Interface X serves as monitored-link in groupA and managed-link in groupB.

    When groupB's monitored-link Y drops:
      - groupB goes DOWN, X is force_down, X's oper goes down
      - groupA sees its only monitored-link (X) drop, goes DOWN, D_A is force_down
    Bringing Y back up reverses the cascade.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 3, "cross-role chain")
    intfs = mlg.allocate(3)
    chained, b_monitored, a_managed = intfs[0], intfs[1], intfs[2]

    mlg.apply({
        "groupA": mlg_helpers.make_group([chained], [a_managed], min_monitored_links=1),
        "groupB": mlg_helpers.make_group([b_monitored], [chained], min_monitored_links=1),
    })

    mlg_helpers.wait_group_state(duthost, "groupA", "up")
    mlg_helpers.wait_group_state(duthost, "groupB", "up")
    mlg_helpers.assert_member_states(duthost, {
        chained: "allow_up",
        a_managed: "allow_up",
    })

    mlg.shutdown(b_monitored)

    mlg_helpers.wait_group_state(duthost, "groupB", "down")
    mlg_helpers.wait_member_state(duthost, chained, "force_down")
    mlg_helpers.wait_oper(duthost, chained, "down")
    mlg_helpers.wait_group_state(duthost, "groupA", "down")
    mlg_helpers.wait_member_state(duthost, a_managed, "force_down")
    mlg_helpers.wait_oper(duthost, a_managed, "down")

    mlg.no_shutdown(b_monitored)

    mlg_helpers.wait_group_state(duthost, "groupB", "up")
    mlg_helpers.wait_member_state(duthost, chained, "allow_up")
    mlg_helpers.wait_oper(duthost, chained, "up")
    mlg_helpers.wait_group_state(duthost, "groupA", "up")
    mlg_helpers.wait_member_state(duthost, a_managed, "allow_up")
    mlg_helpers.wait_oper(duthost, a_managed, "up")


def test_corner_link_up_delay_pending_then_up(duthosts, rand_one_dut_hostname, mlg):
    """Group with link-up-delay=5 enters PENDING when monitored recover, then UP."""
    duthost = duthosts[rand_one_dut_hostname]
    delay = 5
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)
    # Downlinks stay force_down while PENDING.
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})

    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=delay + 5)
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_corner_link_up_delay_flap_resets_pending(duthosts, rand_one_dut_hostname, mlg):
    """Dropping an monitored-link during PENDING cancels the timer; recovery starts fresh."""
    duthost = duthosts[rand_one_dut_hostname]
    delay = 6
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)

    # Mid-pending flap should cancel the timer and drop the group back to DOWN.
    mlg.shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    # Recovery should start a fresh PENDING cycle (not jump straight to UP
    # using residual time from the original timer).
    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=delay + 5)


def test_corner_link_up_delay_zero_while_pending(duthosts, rand_one_dut_hostname, mlg):
    """Changing link-up-delay to 0 while group is PENDING brings it UP immediately."""
    duthost = duthosts[rand_one_dut_hostname]
    delay = 15
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=0),
    })

    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=5)
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_corner_min_monitored_exceeds_available_stays_down(duthosts, rand_one_dut_hostname, mlg):
    """min-monitored > configured monitored-link count: group stays DOWN at all times."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=5),
    })

    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})
    mlg_helpers.wait_oper(duthost, managed[0], "down")


def test_corner_min_monitored_threshold_above_one(duthosts, rand_one_dut_hostname, mlg):
    """min-monitored=2 with 3 monitored: group tracks the boundary."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 4, "3 monitored + 1 managed-link")
    monitored = mlg.allocate(3)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=2),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    # Drop one monitored-link: 2/3 still meets the threshold.
    mlg.shutdown(monitored[0])
    mlg_helpers.wait_oper(duthost, monitored[0], "down")
    # Give the manager a moment to (not) react; state should remain up.
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=5)

    # Drop second monitored-link: now 1/3, below threshold -> DOWN.
    mlg.shutdown(monitored[1])
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})

    # Recover one monitored-link: back to 2/3 -> UP.
    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_corner_config_rollback(duthosts, rand_one_dut_hostname, mlg):
    """Apply config A, switch to B (different monitored + description), then restore A.

    Verifies that re-applying a previous config rolls the runtime state back.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 5, "2 monitored A + 2 monitored B + 1 managed-link")
    monitored_a = mlg.allocate(2)
    monitored_b = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored_a, managed,
                                     min_monitored_links=1, description="config-A"),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.wait_group_field(duthost, "g1", "description", "config-A")
    state_a = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(
        set(state_a.get("monitored-links", "").split(",")) == set(monitored_a),
        "config-A monitored mismatch: {}".format(state_a),
    )

    # Apply config B: different monitored, different description.
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored_b, managed,
                                     min_monitored_links=1, description="config-B"),
    })
    mlg_helpers.wait_group_field(duthost, "g1", "description", "config-B")
    state_b = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(
        set(state_b.get("monitored-links", "").split(",")) == set(monitored_b),
        "config-B monitored mismatch: {}".format(state_b),
    )
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    # Roll back to config A.
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored_a, managed,
                                     min_monitored_links=1, description="config-A"),
    })
    mlg_helpers.wait_group_field(duthost, "g1", "description", "config-A")
    state_rb = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(
        set(state_rb.get("monitored-links", "").split(",")) == set(monitored_a),
        "rolled-back monitored mismatch: {}".format(state_rb),
    )
    mlg_helpers.wait_group_state(duthost, "g1", "up")


# =============================================================================
# Group A: runtime config-change paths
# =============================================================================


def test_runtime_add_monitored_keeps_group_up(duthosts, rand_one_dut_hostname, mlg):
    """Re-apply config with an extra monitored-link; group stays UP."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 3, "2 monitored + 1 managed-link")
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group([monitored[0]], managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    state = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(
        set(state.get("monitored-links", "").split(",")) == set(monitored),
        "monitored mismatch after re-apply: {}".format(state),
    )


def test_runtime_remove_only_monitored_drops_group(duthosts, rand_one_dut_hostname, mlg):
    """Re-apply with the only remaining monitored-link removed (post drop), group goes DOWN."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    # Shrink monitored-link list to a single port and shut it; group must go DOWN.
    mlg.apply({"g1": mlg_helpers.make_group([monitored[0]], managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg.shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})


def test_runtime_add_managed_to_down_group_force_down(duthosts, rand_one_dut_hostname, mlg):
    """Adding a managed-link to an already-DOWN group puts the new managed-link in force_down immediately."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 4, "2 monitored + 2 managed")
    monitored = mlg.allocate(2)
    managed = mlg.allocate(2)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({"g1": mlg_helpers.make_group(monitored, [managed[0]], min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.wait_member_state(duthost, managed[0], "force_down")

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_member_state(duthost, managed[1], "force_down")
    mlg_helpers.wait_oper(duthost, managed[1], "down")


def test_runtime_min_monitored_increase_drops_group(duthosts, rand_one_dut_hostname, mlg):
    """Raising min-monitored above the current up-count drops the group without any link flap."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=3)})
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})


def test_description_only_update_no_state_flap(duthosts, rand_one_dut_hostname, mlg):
    """Description-only update propagates to STATE_DB; no spurious DOWN transition."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, description="initial"),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.wait_group_field(duthost, "g1", "description", "initial")

    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, description="updated"),
    })
    mlg_helpers.wait_group_field(duthost, "g1", "description", "updated")

    # Sample state for ~3s; should remain UP the entire window.
    def _stays_up():
        return mlg_helpers.get_group_state(duthost, "g1").get("state") != "up"

    # wait_until returns True only if _stays_up returned True at least once,
    # i.e. the state left "up". A False return means it stayed UP for the
    # full window, which is what we want.
    pytest_assert(
        not wait_until(3, 0.5, 0, _stays_up),
        "group flapped from up during description-only update",
    )


# =============================================================================
# Group B: delay edge cases
# =============================================================================


def test_delay_reduced_past_elapsed_brings_up_immediately(duthosts, rand_one_dut_hostname, mlg):
    """Reducing link-up-delay below elapsed PENDING time brings the group UP immediately."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=20),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=10)

    # Spend ~5s in the original 20s pending window before shrinking the delay.
    time.sleep(5)

    # Reduce to 3s -- elapsed (5) >= new_delay (3) -> immediate UP per handleGroupDelayChange.
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=3),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=5)


def test_delay_increase_while_pending_extends_timer(duthosts, rand_one_dut_hostname, mlg):
    """Raising link-up-delay while pending keeps the group in PENDING past the original delay.

    Use generous absolute delays so the apply path latency (no_shutdown +
    state-polling cadence + config load) does not race the original timer.
    """
    duthost = duthosts[rand_one_dut_hostname]
    initial_delay = 10
    new_delay = 40

    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=initial_delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=initial_delay)
    pending_seen = time.time()

    # Bump delay while still PENDING (well before initial_delay elapses).
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=new_delay),
    })

    # Wait until ~5s past the original deadline measured from pending_seen.
    # new_delay (40s) > initial_delay+5 (15s), so the group must still be PENDING here.
    deadline_check = pending_seen + initial_delay + 5
    time.sleep(max(0, deadline_check - time.time()))
    state = mlg_helpers.get_group_state(duthost, "g1").get("state")
    pytest_assert(
        state == "pending",
        "expected still pending {}s past original {}s deadline, got {}".format(
            5, initial_delay, state),
    )

    # Eventually go UP under the extended timer.
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=new_delay + 10)


def test_delete_group_during_pending_releases_managed(duthosts, rand_one_dut_hostname, mlg):
    """Deleting a group while in PENDING releases its managed back to oper-up."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    for u in monitored:
        mlg.shutdown(u)
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=30),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=10)
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})

    mlg.delete_group("g1")

    # State entry should be gone, managed-link released to oper-up.
    pytest_assert(
        not mlg_helpers.group_state_exists(duthost, "g1"),
        "MONITOR_LINK_GROUP_STATE|g1 should be removed",
    )
    mlg_helpers.wait_oper(duthost, managed[0], "up")


# =============================================================================
# Group C: group lifecycle
# =============================================================================


def test_delete_up_group_releases_managed(duthosts, rand_one_dut_hostname, mlg):
    """Deleting a healthy UP group leaves its managed oper-up (HLD: revert to admin state)."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.wait_oper(duthost, managed[0], "up")

    mlg.delete_group("g1")

    pytest_assert(
        not mlg_helpers.group_state_exists(duthost, "g1"),
        "MONITOR_LINK_GROUP_STATE|g1 should be removed",
    )
    # MONITOR_LINK_GROUP_MEMBER entry should be removed; managed-link remains oper-up.
    mlg_helpers.wait_oper(duthost, managed[0], "up")
    member = mlg_helpers.get_member_state(duthost, managed[0])
    pytest_assert(
        member == {},
        "expected empty member state after group delete, got {}".format(member),
    )


def test_delete_and_recreate_same_name(duthosts, rand_one_dut_hostname, mlg):
    """Re-create a group with the same name after deletion (timer executor reuse path)."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored_a = mlg.allocate(2)
    monitored_b = mlg.allocate(2) if len(mlg.pool.available()) >= 2 else monitored_a
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored_a, managed,
                                            min_monitored_links=1, link_up_delay=2)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg.delete_group("g1")
    pytest_assert(
        not mlg_helpers.group_state_exists(duthost, "g1"),
        "MONITOR_LINK_GROUP_STATE|g1 should be removed",
    )

    # Recreate with a different monitored-link list and a delay (executor previously created
    # for this name should be reused per startLinkupDelayTimer).
    mlg.apply({"g1": mlg_helpers.make_group(monitored_b, managed,
                                            min_monitored_links=1, link_up_delay=2)})
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=10)


# =============================================================================
# Group D: boundary configs
# =============================================================================


def test_min_monitored_zero_always_up(duthosts, rand_one_dut_hostname, mlg):
    """min-monitored=0: threshold is met with 0 monitored, group stays UP even with all monitored down."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=0)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    for u in monitored:
        mlg.shutdown(u)
    # Group should remain UP because count(0) >= threshold(0).
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=10)
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_group_with_no_managed_tracks_state_only(duthosts, rand_one_dut_hostname, mlg):
    """Group with monitored but no managed: STATE_DB group entry is maintained; no member entries created."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, [], min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    state = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(
        state.get("managed-links", "") == "",
        "expected empty managed, got {}".format(state),
    )

    for u in monitored:
        mlg.shutdown(u)
    mlg_helpers.wait_group_state(duthost, "g1", "down")


# =============================================================================
# Group E: PortChannel coverage
# =============================================================================


def test_portchannel_monitored(duthosts, rand_one_dut_hostname, mlg):
    """Use a PortChannel as the monitored-link; toggling its admin state drives group state."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_portchannels(mlg, 1)
    pc = mlg.allocate_portchannels(1)[0]
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group([pc], managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    mlg.shutdown(pc)
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "force_down"})

    mlg.no_shutdown(pc)
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_portchannel_managed(duthosts, rand_one_dut_hostname, mlg):
    """Use a PortChannel as the managed-link; force_down must drive the PortChannel down."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_portchannels(mlg, 1)
    monitored = mlg.allocate(2)
    pc = mlg.allocate_portchannels(1)[0]

    mlg.apply({"g1": mlg_helpers.make_group(monitored, [pc], min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")
    mlg_helpers.assert_member_states(duthost, {pc: "allow_up"})

    for u in monitored:
        mlg.shutdown(u)
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.wait_member_state(duthost, pc, "force_down")
    mlg_helpers.wait_oper(duthost, pc, "down")


# =============================================================================
# Group F: multi-group / multi-role fan-out
# =============================================================================


def test_interface_in_three_roles_multi_fanout(duthosts, rand_one_dut_hostname, mlg):
    """X is monitored-link in A, managed-link in B, managed-link in C.

    X is allow_up iff BOTH B and C are UP. When either B or C is DOWN, X is force_down.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 5, "X + 2 monitored + 1 managed-link + 1 spare")
    intfs = mlg.allocate(5)
    x, b_up, c_up, dl_a, _spare = intfs

    mlg.apply({
        "A": mlg_helpers.make_group([x], [dl_a], min_monitored_links=1),
        "B": mlg_helpers.make_group([b_up], [x], min_monitored_links=1),
        "C": mlg_helpers.make_group([c_up], [x], min_monitored_links=1),
    })
    for g in ("A", "B", "C"):
        mlg_helpers.wait_group_state(duthost, g, "up")
    mlg_helpers.assert_member_states(duthost, {x: "allow_up"})

    # Drop only B's monitored-link -> X force_down (held by B). A drops because its monitored-link X is now down.
    mlg.shutdown(b_up)
    mlg_helpers.wait_group_state(duthost, "B", "down")
    mlg_helpers.wait_member_state(duthost, x, "force_down")
    mlg_helpers.wait_group_state(duthost, "A", "down")

    # Recover B; X should now be allow_up only if C is also UP (it is).
    mlg.no_shutdown(b_up)
    mlg_helpers.wait_group_state(duthost, "B", "up")
    mlg_helpers.wait_member_state(duthost, x, "allow_up")
    mlg_helpers.wait_group_state(duthost, "A", "up")

    # Now drop C; same X held by C.
    mlg.shutdown(c_up)
    mlg_helpers.wait_group_state(duthost, "C", "down")
    mlg_helpers.wait_member_state(duthost, x, "force_down")
    mlg_helpers.wait_group_state(duthost, "A", "down")

    mlg.no_shutdown(c_up)
    mlg_helpers.wait_group_state(duthost, "C", "up")
    mlg_helpers.wait_member_state(duthost, x, "allow_up")
    mlg_helpers.wait_group_state(duthost, "A", "up")


def test_many_groups_apply_simultaneously(duthosts, rand_one_dut_hostname, mlg):
    """Apply 8 groups in one config load; verify all reach UP."""
    duthost = duthosts[rand_one_dut_hostname]
    n = 8
    needed = 2 * n  # 1 monitored-link + 1 managed-link per group
    _require_intfs(mlg, needed, "{} groups".format(n))
    intfs = mlg.allocate(needed)
    groups = {}
    for i in range(n):
        u = intfs[2 * i]
        d = intfs[2 * i + 1]
        groups["mg{}".format(i)] = mlg_helpers.make_group([u], [d], min_monitored_links=1)

    mlg.apply(groups)
    for name in groups:
        mlg_helpers.wait_group_state(duthost, name, "up")


# =============================================================================
# Group G: YANG validation (negative)
# =============================================================================


def test_yang_rejects_same_intf_as_monitored_and_managed(duthosts, rand_one_dut_hostname, mlg, loganalyzer):
    """Same interface in both monitored and managed of one group -> apply-patch fails."""
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        # config load is expected to raise YANG validation errors; suppress them.
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([
            r".*ERR.*MONITOR_LINK_GROUP.*",
            r".*ERR.*config_load.*",
            r".*ERR.*sonic_yang.*",
        ])

    monitored = mlg.allocate(1)
    intf = monitored[0]

    bad = {"g_invalid": mlg_helpers.make_group([intf], [intf], min_monitored_links=1)}
    try:
        result = mlg_helpers.apply_config_raw(duthost, bad)
        pytest_assert(
            result["rc"] != 0,
            "expected YANG validation failure when intf is both monitored-link and managed-link: {}".format(result),
        )
        pytest_assert(
            not mlg_helpers.group_state_exists(duthost, "g_invalid"),
            "invalid group should not have been written to STATE_DB",
        )
    finally:
        # Always remove g_invalid -- if apply-patch silently accepted the bad
        # config, it would otherwise be left in CONFIG_DB and trip the
        # framework's post-test YANG validation.
        mlg_helpers.delete_group(duthost, "g_invalid")


def test_yang_rejects_non_ethernet_member(duthosts, rand_one_dut_hostname, mlg, loganalyzer):
    """Non-Ethernet/PortChannel interface as monitored-link -> apply-patch fails."""
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([
            r".*ERR.*MONITOR_LINK_GROUP.*",
            r".*ERR.*config_load.*",
            r".*ERR.*sonic_yang.*",
        ])

    managed = mlg.allocate(1)

    bad = {"g_invalid": mlg_helpers.make_group(["Loopback0"], managed, min_monitored_links=1)}
    try:
        result = mlg_helpers.apply_config_raw(duthost, bad)
        pytest_assert(
            result["rc"] != 0,
            "expected YANG validation failure for Loopback0 as monitored-link: {}".format(result),
        )
        pytest_assert(
            not mlg_helpers.group_state_exists(duthost, "g_invalid"),
            "invalid group should not have been written to STATE_DB",
        )
    finally:
        mlg_helpers.delete_group(duthost, "g_invalid")


# =============================================================================
# Group H: resilience
# =============================================================================


@pytest.mark.skip(
    reason="Disruptive: swss restart drops BGP sessions; post-test env check "
           "fails until BGP fully reconverges. Remove this skip to run manually."
)
def test_swss_restart_recovers_state(duthosts, rand_one_dut_hostname, mlg, loganalyzer):
    """After swss restart, group state is reconstructed from CONFIG_DB."""
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        # swss restart legitimately produces warning/error log lines.
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([
            r".*ERR swss.*",
            r".*ERR syncd.*",
            r".*ERR orchagent.*",
            r".*WARN.*systemd.*swss.*",
        ])

    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    duthost.shell("sudo systemctl restart swss")
    pytest_assert(
        wait_until(180, 5, 0, duthost.critical_services_fully_started),
        "critical services did not come up after swss restart",
    )

    # State should be re-derived from CONFIG_DB and current STATE_DB port states.
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=60)
    mlg_helpers.wait_oper(duthost, managed[0], "up", timeout=60)


@pytest.mark.skip(
    reason="Disruptive: full config reload drops BGP sessions and takes minutes to "
           "reconverge; post-test env check fails. Remove this skip to run manually."
)
def test_config_save_then_reload_persists(duthosts, rand_one_dut_hostname, mlg, loganalyzer):
    """config save + config reload preserves the group definition and state."""
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([
            r".*ERR swss.*",
            r".*ERR syncd.*",
            r".*ERR orchagent.*",
        ])

    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g_persist": mlg_helpers.make_group(monitored, managed,
                                            min_monitored_links=1, description="persist-me"),
    })
    mlg_helpers.wait_group_state(duthost, "g_persist", "up")

    duthost.shell("sudo config save -y")
    config_reload(duthost, safe_reload=True, wait=180)

    # Wait for the monitored to come back oper-up post-reload before asserting
    # group state; otherwise the group is legitimately DOWN until interfaces
    # finish initializing.
    for u in monitored:
        mlg_helpers.wait_oper(duthost, u, "up", timeout=180)

    mlg_helpers.wait_group_state(duthost, "g_persist", "up", timeout=120)
    mlg_helpers.wait_group_field(duthost, "g_persist", "description", "persist-me")


# =============================================================================
# Group H: daemon-level validation (cycle detection, R-6)
# =============================================================================


def test_cycle_rejection(duthosts, rand_one_dut_hostname, mlg):
    """R-6: daemon must reject a SET that forms a dependency cycle between groups.

    Cycle: groupA.monitored=X, groupA.managed=Y;
           groupB.monitored=Y, groupB.managed=X.
    Edge A->B: X is monitored in A, X is managed in B (A's recovery waits on B).
    Edge B->A: Y is monitored in B, Y is managed in A (B's recovery waits on A).
    """
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 2, "2 ports for cycle test")
    intfs = mlg.allocate(2)
    x, y = intfs[0], intfs[1]

    # First group lands cleanly.
    mlg.apply({"groupA": mlg_helpers.make_group([x], [y], min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "groupA", "up")

    # The cyclic second group: CONFIG_DB write succeeds (config load -y is permissive),
    # but the daemon must reject the SET. STATE_DB stays empty for groupB.
    mlg.apply({"groupB": mlg_helpers.make_group([y], [x], min_monitored_links=1)})
    time.sleep(3)
    pytest_assert(
        not mlg_helpers.group_state_exists(duthost, "groupB"),
        "groupB should have been rejected; STATE_DB entry must not appear (actual: {})".format(
            mlg_helpers.get_group_state(duthost, "groupB"),
        ),
    )

    # groupA is unaffected.
    state_a = mlg_helpers.get_group_state(duthost, "groupA")
    pytest_assert(
        state_a.get("state") == "up",
        "groupA should still be up after rejected groupB SET, got {}".format(state_a),
    )


def test_cycle_resolved_by_deletion(duthosts, rand_one_dut_hostname, mlg):
    """R-6: once one of the would-be-cycle participants is deleted, the same SET
    that previously formed a cycle must succeed.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 3, "3 ports for cycle-resolved test")
    intfs = mlg.allocate(3)
    a, b, c = intfs[0], intfs[1], intfs[2]

    # A: monitored=a, managed=b; B: monitored=b, managed=c. No cycle (A -> B only).
    mlg.apply({
        "groupA": mlg_helpers.make_group([a], [b], min_monitored_links=1),
        "groupB": mlg_helpers.make_group([b], [c], min_monitored_links=1),
    })
    mlg_helpers.wait_group_state(duthost, "groupA", "up")
    mlg_helpers.wait_group_state(duthost, "groupB", "up")

    # Update A to monitor c (managed in B) while keeping b managed.
    # Now A -> B (via b) -> A (via c) is a cycle. Daemon must reject:
    # STATE_DB for groupA should still reflect the old monitored-links list.
    mlg.apply({"groupA": mlg_helpers.make_group([c], [b], min_monitored_links=1)})
    time.sleep(3)
    state_a = mlg_helpers.get_group_state(duthost, "groupA")
    pytest_assert(
        set(state_a.get("monitored-links", "").split(",")) == {a},
        "groupA monitored-links should stay as old set ({{a}}) after rejection; got {}".format(state_a),
    )

    # Delete B; cycle is gone.
    mlg.delete_group("groupB")
    # B's state entry should disappear; once it does, the same A update no longer cycles.
    pytest_assert(
        wait_until(30, 1, 0, lambda: not mlg_helpers.group_state_exists(duthost, "groupB")),
        "groupB state entry did not clear after delete",
    )

    # Retry the A update; with B gone there's no edge out of A that returns to A.
    mlg.apply({"groupA": mlg_helpers.make_group([c], [b], min_monitored_links=1)})
    mlg_helpers.wait_group_field(duthost, "groupA", "monitored-links", c)


# =============================================================================
# Group H2: transition tracking (PR-A) -- last_state_change_*, pending_start_time, counters
# =============================================================================


def _to_int(s, default=0):
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def test_pra_first_transition_records_last_state_change(duthosts, rand_one_dut_hostname, mlg):
    """PR-A: after a runtime transition, STATE_DB carries last_state_change_{from,to,time}."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    # Drive a deliberate UP -> DOWN transition.
    mlg.shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    state = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(state.get("last_state_change_from") == "up",
                  "last_state_change_from should be 'up', got {}".format(state))
    pytest_assert(state.get("last_state_change_to") == "down",
                  "last_state_change_to should be 'down', got {}".format(state))
    pytest_assert(_to_int(state.get("last_state_change_time")) > 0,
                  "last_state_change_time should be a non-zero epoch, got {}".format(state))


def test_pra_pending_start_time_set_on_pending_and_cleared_on_up(duthosts, rand_one_dut_hostname, mlg):
    """PR-A: pending_start_time is written while group is PENDING and removed once UP."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)
    delay = 4

    mlg.shutdown(monitored[0])
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    mlg.no_shutdown(monitored[0])
    # Should land in PENDING; pending_start_time must be populated.
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)
    state_pending = mlg_helpers.get_group_state(duthost, "g1")
    pstart = _to_int(state_pending.get("pending_start_time"))
    pytest_assert(pstart > 0,
                  "pending_start_time should be set in PENDING, got {}".format(state_pending))

    # After delay expires, the daemon must remove pending_start_time so external
    # consumers don't see a stale value.
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=delay + 5)
    state_up = mlg_helpers.get_group_state(duthost, "g1")
    pytest_assert(state_up.get("pending_start_time") in (None, ""),
                  "pending_start_time should be cleared once UP, got {}".format(state_up))


def test_pra_total_transitions_bumps_on_direct_down(duthosts, rand_one_dut_hostname, mlg):
    """PR-A: a direct UP -> DOWN transition bumps total_transitions by exactly 1."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    before = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))

    mlg.shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    after = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))
    pytest_assert(after == before + 1,
                  "total_transitions should advance by 1 on UP->DOWN (before={}, after={})".format(
                      before, after))


def test_pra_total_transitions_bumps_on_recovery(duthosts, rand_one_dut_hostname, mlg):
    """PR-A: any path landing in UP (DOWN -> UP or PENDING -> UP) bumps total_transitions."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    # Start DOWN so the first UP transition is a counter event.
    mlg.shutdown(monitored[0])
    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    before = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))

    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    after = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))
    pytest_assert(after == before + 1,
                  "total_transitions should advance by 1 on DOWN->UP (before={}, after={})".format(
                      before, after))

    # Force another transition via PENDING -> UP and confirm it also bumps the counter
    # (i.e. the bump is path-agnostic, not specific to DOWN->UP).
    mlg.delete_group("g1")
    pytest_assert(
        wait_until(30, 1, 0, lambda: not mlg_helpers.group_state_exists(duthost, "g1")),
        "g1 should be deleted",
    )

    delay = 3
    mlg.shutdown(monitored[0])
    mlg.apply({
        "g1": mlg_helpers.make_group(monitored, managed,
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")

    before2 = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))

    mlg.no_shutdown(monitored[0])
    # Pending entry is also a recorded transition; UP via timer expiry is another.
    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=delay + 5)

    after2 = _to_int(mlg_helpers.get_group_state(duthost, "g1").get("total_transitions"))
    # DOWN->PENDING + PENDING->UP both count.
    pytest_assert(after2 == before2 + 2,
                  "total_transitions should advance by 2 across DOWN->PENDING->UP "
                  "(before={}, after={})".format(before2, after2))


# =============================================================================
# Group I: stress / timing
# =============================================================================


def test_rapid_monitored_flap_converges(duthosts, rand_one_dut_hostname, mlg):
    """Toggling an monitored-link rapidly; final state must reflect the final admin state."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({"g1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g1", "up")

    for _ in range(10):
        mlg.shutdown(monitored[0])
        time.sleep(0.2)
        mlg.no_shutdown(monitored[0])
        time.sleep(0.2)

    # Final admin state of monitored[0] is UP, monitored[1] is UP -> group must converge to UP.
    mlg_helpers.wait_oper(duthost, monitored[0], "up", timeout=30)
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=30)
    mlg_helpers.assert_member_states(duthost, {managed[0]: "allow_up"})


def test_concurrent_groups_share_pending(duthosts, rand_one_dut_hostname, mlg):
    """Two groups share an monitored-link with the same delay; both PENDING then both UP."""
    duthost = duthosts[rand_one_dut_hostname]
    _require_intfs(mlg, 3, "1 shared monitored-link + 2 managed")
    shared_monitored_link = mlg.allocate(1)
    managed = mlg.allocate(2)
    delay = 5

    mlg.shutdown(shared_monitored_link[0])
    mlg.apply({
        "g1": mlg_helpers.make_group(shared_monitored_link, [managed[0]],
                                     min_monitored_links=1, link_up_delay=delay),
        "g2": mlg_helpers.make_group(shared_monitored_link, [managed[1]],
                                     min_monitored_links=1, link_up_delay=delay),
    })
    mlg_helpers.wait_group_state(duthost, "g1", "down")
    mlg_helpers.wait_group_state(duthost, "g2", "down")

    mlg.no_shutdown(shared_monitored_link[0])

    mlg_helpers.wait_group_state(duthost, "g1", "pending", timeout=delay)
    mlg_helpers.wait_group_state(duthost, "g2", "pending", timeout=delay)
    mlg_helpers.wait_group_state(duthost, "g1", "up", timeout=delay + 5)
    mlg_helpers.wait_group_state(duthost, "g2", "up", timeout=delay + 5)


# =============================================================================
# Group J: CLI / observability
# =============================================================================


def test_show_monitor_link_group_matches_state_db(duthosts, rand_one_dut_hostname, mlg):
    """show monitor-link-group output mentions the group, its state, and member counts."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(2)
    managed = mlg.allocate(1)

    mlg.apply({
        "g_show": mlg_helpers.make_group(monitored, managed,
                                         min_monitored_links=1, link_up_delay=2,
                                         description="cli-test"),
    })
    mlg_helpers.wait_group_state(duthost, "g_show", "up")

    out = mlg_helpers.show_monitor_link_group(duthost, "g_show")
    pytest_assert("g_show" in out, "group name missing from CLI output:\n{}".format(out))
    pytest_assert("up" in out.lower(), "expected 'up' in CLI output:\n{}".format(out))
    for u in monitored:
        pytest_assert(u in out, "monitored-link {} missing from CLI output:\n{}".format(u, out))
    for d in managed:
        pytest_assert(d in out, "managed-link {} missing from CLI output:\n{}".format(d, out))


# --- PR-B: show monitor-link transition-tracking lines ---


def test_prb_show_renders_last_change_after_transition(duthosts, rand_one_dut_hostname, mlg):
    """PR-B: after a runtime transition, `show monitor-link-group` renders 'Last change:'."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    mlg.apply({"g_b1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g_b1", "up")

    # Drive UP -> DOWN so a transition record exists.
    mlg.shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g_b1", "down")

    out = mlg_helpers.show_monitor_link_group(duthost, "g_b1")
    pytest_assert("Last change:" in out,
                  "'Last change:' line missing from CLI:\n{}".format(out))
    pytest_assert("UP -> DOWN" in out,
                  "'UP -> DOWN' direction missing from Last change line:\n{}".format(out))


def test_prb_show_renders_transitions_counter_line(duthosts, rand_one_dut_hostname, mlg):
    """PR-B: 'Transitions:' counter line is always rendered with a numeric total."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    mlg.apply({"g_b2": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g_b2", "up")

    out = mlg_helpers.show_monitor_link_group(duthost, "g_b2")
    pytest_assert("Transitions:" in out,
                  "'Transitions:' counter line missing:\n{}".format(out))
    # Group came up on creation -> total_transitions should be at least 1.
    import re
    match = re.search(r"Transitions:\s+(\d+)", out)
    pytest_assert(match is not None,
                  "Transitions line should carry a numeric total:\n{}".format(out))
    pytest_assert(int(match.group(1)) >= 1,
                  "expected at least one recorded transition, got {}:\n{}".format(
                      match.group(1), out))


def test_prb_show_renders_pending_elapsed_remaining(duthosts, rand_one_dut_hostname, mlg):
    """PR-B: while state is PENDING, Link-up-delay line shows (elapsed: Xs, remaining: Ys)."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)
    # Use a generous delay so we have a reliable window to query the CLI in
    # PENDING before the timer fires.
    delay = 15

    mlg.shutdown(monitored[0])
    mlg.apply({"g_b3": mlg_helpers.make_group(monitored, managed,
                                              min_monitored_links=1, link_up_delay=delay)})
    mlg_helpers.wait_group_state(duthost, "g_b3", "down")

    # Bring monitored back; group enters PENDING.
    mlg.no_shutdown(monitored[0])
    mlg_helpers.wait_group_state(duthost, "g_b3", "pending", timeout=delay)

    out = mlg_helpers.show_monitor_link_group(duthost, "g_b3")
    pytest_assert("elapsed:" in out,
                  "'elapsed:' missing from Link-up-delay during PENDING:\n{}".format(out))
    pytest_assert("remaining:" in out,
                  "'remaining:' missing from Link-up-delay during PENDING:\n{}".format(out))


# --- PR-C: error-down (mlg) rendering in show interface status / description ---


def _admin_column_for(out, intf):
    """Return the line from `show interface status` that begins with intf, or None.
    The caller pulls the Admin column out of the line via substring match."""
    for line in out.splitlines():
        if line.strip().startswith(intf):
            return line
    return None


def test_prc_show_interface_status_renders_error_down_for_mlg_held(duthosts, rand_one_dut_hostname, mlg):
    """PR-C: a managed-link held DOWN by MLG renders 'error-down (mlg)' in Admin column."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    # Drive group DOWN so MLG forces the managed-link.
    mlg.shutdown(monitored[0])
    mlg.apply({"g_c1": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g_c1", "down")
    mlg_helpers.wait_member_state(duthost, managed[0], "force_down")

    out = duthost.shell("show interface status")["stdout"]
    line = _admin_column_for(out, managed[0])
    pytest_assert(line is not None,
                  "managed-link {} not found in show interface status:\n{}".format(managed[0], out))
    pytest_assert("error-down (mlg)" in line,
                  "expected 'error-down (mlg)' for {}, got line:\n{}\nfull:\n{}".format(
                      managed[0], line, out))


def test_prc_show_interface_status_user_shutdown_is_plain_down(duthosts, rand_one_dut_hostname, mlg):
    """PR-C: a user-shut port not in any MLG renders plain 'down', not 'error-down'."""
    duthost = duthosts[rand_one_dut_hostname]
    intf = mlg.allocate(1)[0]

    mlg.shutdown(intf)
    mlg_helpers.wait_oper(duthost, intf, "down")

    out = duthost.shell("show interface status")["stdout"]
    line = _admin_column_for(out, intf)
    pytest_assert(line is not None,
                  "intf {} not found in show interface status:\n{}".format(intf, out))
    pytest_assert("error-down" not in line,
                  "user shutdown must not render error-down for {}:\n{}".format(intf, line))


def test_prc_show_interface_description_inherits_error_down(duthosts, rand_one_dut_hostname, mlg):
    """PR-C: same getter feeds `show interface description`; it also renders 'error-down (mlg)'."""
    duthost = duthosts[rand_one_dut_hostname]
    monitored = mlg.allocate(1)
    managed = mlg.allocate(1)

    mlg.shutdown(monitored[0])
    mlg.apply({"g_c3": mlg_helpers.make_group(monitored, managed, min_monitored_links=1)})
    mlg_helpers.wait_group_state(duthost, "g_c3", "down")
    mlg_helpers.wait_member_state(duthost, managed[0], "force_down")

    out = duthost.shell("show interface description")["stdout"]
    line = _admin_column_for(out, managed[0])
    pytest_assert(line is not None,
                  "managed-link {} not found in show interface description:\n{}".format(managed[0], out))
    pytest_assert("error-down (mlg)" in line,
                  "expected 'error-down (mlg)' in description output for {}:\n{}".format(managed[0], line))
