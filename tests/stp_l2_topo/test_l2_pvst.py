# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
PVST on the three-bridge l2-topo.

The cases that injection on a single switch cannot reach: agreement between
independent bridges, a leg that blocks because another bridge won the election,
and failover onto a path a neighbour chose.

"""
import logging
import time

import pytest

from .l2topo import BLOCKING, FORWARDING, PVST, capture_end, wait_for_value, wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

MODE = PVST


def _forwarding(node, vlan, port):
    return node.port_state(MODE, vlan, port) == FORWARDING


def _blocking(node, vlan, port):
    return node.port_state(MODE, vlan, port) in (BLOCKING, "DISCARDING")


# The virtual switch forwards a PVST BPDU (dst 01:00:0C:CC:CC:CD) through its data
# plane as well as punting it, so a bridge two hops from the root also hears the
# root directly and can block its real uplink instead of the t0 to t0 leg.
# MSTP BPDUs (01:80:C2:00:00:00) are forwarded too once a port has a PVID, which
# untagged members do; the legs here are tagged, so the MSTP cases are unaffected.
# An image that drops both addresses in ebtables on vs makes these cases pass
# (sonic-net/sonic-buildimage#30503).
VIRTUAL_PVST_LEAK = ("the virtual switch forwards PVST BPDUs in its data plane, so "
                     "the tree it builds is not the one the triangle defines; see "
                     "the vs BPDU ebtables drop in sonic-net/sonic-buildimage#30503")


def _expect_virtual_pvst_leak(request, topo):
    if not topo.has_hardware:
        request.node.add_marker(pytest.mark.xfail(reason=VIRTUAL_PVST_LEAK, strict=False))


@pytest.mark.usefixtures("pvst")
class TestPvstL2Topo(object):

    def test_the_t1_is_root_for_every_vlan_on_every_bridge(self, topo):
        """Three independent elections have to reach the same answer. The t1 is
                given the best bridge priority at bring-up, so the other two bridges
                agree on it as root without being told.
        """
        t1_mac = topo.t1.bridge_mac()
        for vlan in topo.vlans:
            assert topo.converge(MODE, vlan), \
                "VLAN {} never settled: {}".format(vlan, topo.port_states(MODE, vlan))
            assert topo.t1.is_self_root(MODE, vlan), \
                "the t1 is not root for VLAN {}: {}".format(vlan, topo.t1.bridge_data(MODE, vlan))
            for node in (topo.t0_1, topo.t0_2):
                ok, seen = wait_for_value(60, 2, lambda n=node, v=vlan: (
                    n.root_is(MODE, v, t1_mac), n.root_bridge_id(MODE, v)))
                assert ok, (
                    "{} elected root bridge id {!r} for VLAN {}, expected one ending "
                    "in the t1's MAC {}".format(node.name, seen, vlan, t1_mac))

    def test_exactly_one_of_the_parallel_pair_forwards(self, topo):
        """Two equal cost ports towards the same neighbour, one has to lose. With a
                single uplink the choice would not be observable.
        """
        if not topo.has_parallel_pair:
            pytest.skip("this topology has no equal cost pair: the switch under "
                        "test has one port to each neighbour, so there is no "
                        "choice between two identical paths to observe")
        pair = topo.parallel_legs
        for vlan in topo.vlans:
            topo.converge(MODE, vlan)
            states = [topo.t0_1.port_state(MODE, vlan, leg.b_port) for leg in pair]
            forwarding = [s for s in states if s == FORWARDING]
            assert len(forwarding) == 1, (
                "VLAN {}: expected exactly one of the parallel pair {} forwarding on {}, "
                "states were {}".format(vlan, [leg.b_port for leg in pair], topo.t0_1.name, states))

    def test_the_t0_to_t0_leg_blocks(self, topo, request):
        """The redundant leg is the one the triangle has to give up. Both t0 bridges
                reach the root in one hop, so the higher bridge ID gives up its end.
        """
        if topo.has_hardware:
            pytest.skip("assumes the all-virtual MAC layout where the two t0 "
                        "bridges block the leg between them; a hardware bridge "
                        "has a vendor MAC worse than any assigned one and blocks an "
                        "uplink instead. The shape invariant (exactly one leg blocks) is "
                        "covered topology-agnostically in test_l2_only.py")
        _expect_virtual_pvst_leak(request, topo)
        cross = topo.cross_leg
        for vlan in topo.vlans:
            topo.converge(MODE, vlan)
            a_state = cross.a.port_state(MODE, vlan, cross.a_port)
            b_state = cross.b.port_state(MODE, vlan, cross.b_port)
            assert BLOCKING in (a_state, b_state) or "DISCARDING" in (a_state, b_state), (
                "VLAN {}: neither end of the t0 to t0 leg is blocking "
                "({}:{} is {}, {}:{} is {}). The triangle has no blocked leg, "
                "which is a loop.".format(vlan, cross.a.name, cross.a_port, a_state,
                                          cross.b.name, cross.b_port, b_state))

    @pytest.mark.usefixtures("restore_legs")
    def test_the_cross_leg_unblocks_when_a_t0_uplink_fails(self, topo, request):
        """Failover onto a path the neighbour chose, not one we configured."""
        if topo.has_hardware:
            pytest.skip("assumes the cross leg is the blocked one; with a "
                        "hardware bridge an uplink blocks instead")
        _expect_virtual_pvst_leak(request, topo)
        cross = topo.cross_leg
        uplink_b = topo.leg("uplink-b")
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)

        blocked_end = cross.b if _blocking(cross.b, vlan, cross.b_port) else cross.a
        blocked_port = cross.b_port if blocked_end is cross.b else cross.a_port
        assert _blocking(blocked_end, vlan, blocked_port), \
            "no blocked end to unblock on VLAN {}".format(vlan)

        uplink_b.set_up(False)
        try:
            ok = wait_until(120, 2, lambda: _forwarding(blocked_end, vlan, blocked_port),
                            "cross leg unblocks")
            assert ok, (
                "{}:{} stayed {} after the t0 uplink failed. With its uplink gone the "
                "only path to the root is across the t0 to t0 leg, so that leg has to "
                "come up.".format(blocked_end.name, blocked_port,
                                  blocked_end.port_state(MODE, vlan, blocked_port)))
        finally:
            uplink_b.set_up(True)

    @pytest.mark.usefixtures("restore_legs")
    def test_the_original_tree_returns_when_the_link_returns(self, topo):
        """Restoring the uplink has to put the tree back, not leave a second one."""
        uplink_b = topo.leg("uplink-b")
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        before = topo.port_states(MODE, vlan)

        uplink_b.set_up(False)
        wait_until(120, 2, lambda: topo.port_states(MODE, vlan) != before, "tree moves")
        uplink_b.set_up(True)

        ok, seen = wait_for_value(180, 3, lambda: (
            topo.port_states(MODE, vlan) == before, topo.port_states(MODE, vlan)))
        assert ok, (
            "the tree did not return to its original shape on VLAN {}.\n"
            "before: {}\nafter:  {}".format(vlan, before, seen))

    def test_per_vlan_priority_elects_a_different_root(self, topo):
        """The per VLAN property PVST exists for: one VLAN's tree moves alone."""
        if len(topo.vlans) < 2:
            pytest.skip("needs at least two VLANs; this topology has one")
        moved, control = topo.vlans[0], topo.vlans[1]
        topo.converge(MODE, moved)
        topo.t0_2.set_bridge_priority(MODE, moved, 4096)
        try:
            ok = wait_until(120, 3, lambda: topo.t0_2.is_self_root(MODE, moved),
                            "t0-2 becomes root for VLAN {}".format(moved))
            assert ok, (
                "VLAN {} did not move its root to {} after its priority was lowered "
                "to 4096: {}".format(moved, topo.t0_2.name, topo.t0_2.bridge_data(MODE, moved)))
            assert topo.t1.is_self_root(MODE, control), (
                "VLAN {} lost its root when only VLAN {} was reconfigured. Per VLAN "
                "priority has to be per VLAN.".format(control, moved))
        finally:
            topo.t0_2.set_bridge_priority(MODE, moved, 32768)
            topo.converge(MODE, moved)

    def test_per_vlan_port_cost_steers_vlans_onto_different_uplinks(self, topo):
        """Path diversity: two VLANs take different members of the parallel pair."""
        if not topo.has_parallel_pair:
            pytest.skip("this topology has no equal cost pair: the switch under "
                        "test has one port to each neighbour, so there is no "
                        "choice between two identical paths to observe")
        if len(topo.vlans) < 2:
            pytest.skip("needs at least two VLANs; this topology has one")
        leg_a, leg_b = topo.parallel_legs
        v1, v2 = topo.vlans[0], topo.vlans[1]
        sut = topo.t0_1

        sut.set_port_cost(MODE, v2, leg_a.b_port, 20000)
        try:
            for vlan in (v1, v2):
                topo.converge(MODE, vlan)
            v1_root = sut.root_port(MODE, v1)
            v2_root = sut.root_port(MODE, v2)
            assert v1_root != v2_root, (
                "VLAN {} and VLAN {} both use {} as their root port on {}. Raising the "
                "cost of {} for VLAN {} alone should have steered it onto {}.".format(
                    v1, v2, v1_root, sut.name, leg_a.b_port, v2, leg_b.b_port))
            assert v2_root == leg_b.b_port, (
                "VLAN {} should have moved onto the cheaper uplink {}, it is on {}".format(
                    v2, leg_b.b_port, v2_root))
        finally:
            sut.set_port_cost(MODE, v2, leg_a.b_port, 200)
            topo.converge(MODE, v2)

    @pytest.mark.usefixtures("restore_legs")
    def test_a_topology_change_in_one_vlan_leaves_the_others_untouched(self, topo):
        """PVST's isolation property, checked across real peers rather than one box."""
        if len(topo.vlans) < 2:
            pytest.skip("needs at least two VLANs; this topology has one")
        disturbed, control = topo.vlans[0], topo.vlans[1]
        for vlan in topo.vlans:
            topo.converge(MODE, vlan)
        control_before = {n.name: n.root_bridge_id(MODE, control)
                          for n in topo.all_nodes()}

        # Move only the disturbed VLAN's tree, by making the second t0 its root.
        topo.t0_2.set_bridge_priority(MODE, disturbed, 4096)
        try:
            wait_until(120, 3, lambda: topo.t0_2.is_self_root(MODE, disturbed))
            control_after = {n.name: n.root_bridge_id(MODE, control)
                             for n in topo.all_nodes()}
            assert control_after == control_before, (
                "VLAN {}'s tree changed while only VLAN {} was reconfigured.\n"
                "before: {}\nafter:  {}".format(control, disturbed,
                                                control_before, control_after))
        finally:
            topo.t0_2.set_bridge_priority(MODE, disturbed, 32768)
            topo.converge(MODE, disturbed)

    @pytest.mark.usefixtures("restore_legs")
    def test_a_topology_change_propagates_and_flushes_the_fdb(self, topo):
        """A real peer raises the change. A learned entry has to be flushed on a
                bridge that saw only the notification, not the link event.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)

        # Learn something on the far side of the triangle from where we break it.
        witness = topo.t0_1
        before = witness.fdb_entries(vlan)
        if not before:
            pytest.skip("no FDB entries learned on {} for VLAN {}; the topology "
                        "carries BPDUs but no data plane traffic to learn from"
                        .format(witness.name, vlan))

        topo.leg("uplink-b").set_up(False)
        try:
            ok = wait_until(90, 2, lambda: witness.fdb_entries(vlan) != before,
                            "FDB flushed on {}".format(witness.name))
            assert ok, (
                "{} did not flush its VLAN {} FDB after a topology change raised "
                "elsewhere in the triangle. Entries were {}".format(
                    witness.name, vlan, before))
        finally:
            topo.leg("uplink-b").set_up(True)

    def test_peers_send_pvst_bpdus_on_every_leg(self, topo):
        """Interoperability, stated as a property of the wire. The switch under test
                cannot tell whether its neighbours run the same implementation, so this
                is asserted on the wire.
        """
        for leg in topo.legs:
            node, eth = capture_end(leg)
            assert node is not None, "leg {} has no capturable end".format(leg.role)
            cap = node.capture_bpdus(eth, seconds=10)
            assert cap["ieee"] or cap["pvst"], (
                "leg {} carried no BPDU in 10s, watched at {}".format(leg.role, node.name))
            logger.info("leg %-10s ieee=%d pvst=%d", leg.role, cap["ieee"], cap["pvst"])

    @pytest.mark.usefixtures("restore_legs")
    def test_convergence_time_is_measured(self, topo, convergence_log):
        """Recorded, not asserted against a threshold.

        Convergence is measured here rather than assumed. There is
        no number to hold a virtual topology to, so this records one and fails
        only if the tree never reconverges at all.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        before = topo.port_states(MODE, vlan)

        topo.leg("uplink-b").set_up(False)
        start = time.time()
        moved = wait_until(180, 1, lambda: topo.port_states(MODE, vlan) != before, "tree moves")
        settled = topo.converge(MODE, vlan, timeout=180)
        elapsed = time.time() - start
        topo.leg("uplink-b").set_up(True)

        assert moved and settled, (
            "VLAN {} never reconverged after an uplink failure in 180s: {}".format(
                vlan, topo.port_states(MODE, vlan)))
        convergence_log.append({"mode": MODE, "scope": vlan, "event": "uplink-b down",
                                "seconds": round(elapsed, 2)})
        logger.info("PVST VLAN %s reconverged in %.2fs", vlan, elapsed)
