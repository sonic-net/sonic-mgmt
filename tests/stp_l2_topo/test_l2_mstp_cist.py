# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP coverage that needs only the CIST.

Two things cannot be exercised on this build: an MST instance beyond the CIST,
because no command creates one, and configuration surviving a daemon restart,
because nothing is replayed. The suites needing them stand down, which leaves
MSTP half checked. Every case here is reachable with the CIST alone.

"""
import logging
import threading
import time

import pytest

from .l2topo import (FORWARDING, MST, all_endpoints, assert_boundary_legs, blocked_end, capture_end, capture_many,
                     entry_point, forwarding_legs, is_blocked, leg_states, tagged_broadcast,
                     wait_for_value, wait_until)

from .conftest import MST_REGION, MST_REVISION

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

MODE = MST
CIST = 0
PROBE_SRC = "02:00:00:c1:57:01"


def _inject_while_capturing(endpoints, bpf, seconds, sender, eth, frame, times=3):
    """Capture across the topology while a frame is put into it."""
    out = {}

    def run():
        out["counts"] = capture_many(endpoints, bpf, seconds)

    t = threading.Thread(target=run)
    t.start()
    time.sleep(2.5)                     # capture_many attaches for 2s
    eths = eth if isinstance(eth, (list, tuple)) else [eth]
    for _ in range(times):
        for e in eths:
            sender.inject(e, frame)
        time.sleep(0.4)
    t.join()
    return out["counts"]


@pytest.mark.usefixtures("mstp")
class TestCistOnly(object):

    # ---------------------------------------------------------- the shape
    def test_the_cist_forwards_on_exactly_two_legs(self, topo):
        """A tree over three bridges has two edges, on the CIST as on any tree."""
        assert topo.converge(MODE, CIST), \
            "the CIST never settled: {}".format(topo.port_states(MODE, CIST))
        edges = [leg.role for leg in forwarding_legs(topo, MODE, CIST)]
        assert len(edges) == 2, (
            "{} of 3 legs forward at both ends on the CIST ({}). Fewer than two "
            "partitions the topology, more than two is a loop. Full state: {}"
            .format(len(edges), edges, topo.port_states(MODE, CIST)))

    def test_no_cist_leg_is_blocked_at_both_ends(self, topo):
        """One end of every leg has to be designated, or the leg is dead."""
        topo.converge(MODE, CIST)
        for leg in topo.legs:
            a_state, b_state = leg_states(leg, MODE, CIST)
            assert not (is_blocked(a_state) and is_blocked(b_state)), (
                "leg {} is blocked at both ends on the CIST ({}:{} is {}, "
                "{}:{} is {})".format(leg.role, leg.a.name, leg.a_port, a_state,
                                      leg.b.name, leg.b_port, b_state))

    def test_exactly_one_bridge_is_the_cist_root(self, topo):
        """Two bridges each believing they are root means the region is split."""
        topo.converge(MODE, CIST)
        roots = [n.name for n in topo.all_nodes() if n.is_self_root(MODE, CIST)]
        assert roots == [topo.t1.name], (
            "bridges claiming the CIST root are {}, expected only the t1 ({})"
            .format(roots, topo.t1.name))

    # ------------------------------------------------------- the loop test
    def test_a_broadcast_does_not_circulate_under_mstp(self, topo):
        """The loop has to be prevented under MSTP too. The two modes block by
                different machinery, so proving it once does not prove it twice.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, CIST)
        leg, sender, eth = entry_point(topo, MODE, CIST)
        assert sender is not None, \
            "no forwarding entry point: {}".format(topo.port_states(MODE, CIST))

        frame = tagged_broadcast(vlan, PROBE_SRC)
        bpf = "ether src {}".format(PROBE_SRC)
        endpoints = all_endpoints(topo)

        # The injecting end sees the injection itself and does not count.
        watched = [ep for ep in endpoints if not (ep[1] is sender and ep[2] == eth)]
        flood = _inject_while_capturing(watched, bpf, 5, sender, eth, frame, times=1)
        later = capture_many(endpoints, bpf, 8)

        logger.info("flood window %s", flood)
        logger.info("later window %s", later)
        assert sum(flood.values()) > 0, (
            "the broadcast was never seen on any leg, so it did not enter the "
            "topology and nothing about looping was tested. Entry was {}:{} on "
            "leg {}.".format(sender.name, eth, leg.role))
        assert sum(later.values()) == 0, (
            "the broadcast was still crossing legs 8s after it was sent: {}. Under "
            "MSTP as under PVST, a frame that outlives its flooding is going round "
            "the triangle.".format({k: v for k, v in later.items() if v}))

    def test_the_blocked_cist_port_transmits_no_data(self, topo):
        """Blocking discards data and keeps BPDUs, checked by direction. Inbound is
                the control: a frame that never arrived proves nothing.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, CIST)
        found = blocked_end(topo, MODE, CIST)
        assert found, "no blocked CIST port: {}".format(topo.port_states(MODE, CIST))
        leg, blocker, block_eth, block_port = found
        if not blocker.can_capture:
            pytest.skip("the blocked port is on a hardware switch, where a raw "
                        "capture on the port is not a view of the wire")

        # An injected frame leaves the sender's port without crossing its own
        # bridge, so send from the third bridge out both of its legs: one copy
        # reaches the blocked port through its peer, the other reaches the
        # blocker's forwarding port and is what the blocked port must not send.
        peer = leg.a if blocker is leg.b else leg.b
        sender = next(n for n in topo.all_nodes() if n not in (blocker, peer))
        send_eth = [e for lg in topo.legs for (nd, e, p) in lg.ends()
                    if nd is sender and nd.port_state(MODE, CIST, p) == FORWARDING]

        src = "02:00:00:c1:57:02"
        frame = tagged_broadcast(vlan, src, tag=0xC157)
        counts = _inject_while_capturing(
            [("inbound", blocker, block_eth, "in"),
             ("outbound", blocker, block_eth, "out")],
            "ether src {}".format(src), 8, sender, send_eth, frame)

        logger.info("blocked %s:%s in=%d out=%d",
                    blocker.name, block_port, counts["inbound"], counts["outbound"])
        assert counts["inbound"] > 0, (
            "the frame never reached {}:{} on leg {}, so the blocked port was "
            "never given anything to drop".format(blocker.name, block_port, leg.role))
        assert counts["outbound"] == 0, (
            "{}:{} is blocking on the CIST but transmitted {} data frame(s) onto "
            "leg {}".format(blocker.name, block_port, counts["outbound"], leg.role))

    def test_the_blocked_cist_port_still_receives_bpdus(self, topo):
        """A blocked port keeps listening, or it could never unblock."""
        topo.converge(MODE, CIST)
        found = blocked_end(topo, MODE, CIST)
        assert found, "no blocked CIST port"
        leg, node, eth, port = found
        if not node.can_capture:
            pytest.skip("the blocked port is on a hardware switch, where a raw "
                        "capture on the port is not a view of the wire")
        cap = node.capture_bpdus(eth, seconds=10)
        assert cap["ieee"], (
            "{}:{} is blocking on leg {} and heard no IEEE BPDU in 10s, so it "
            "cannot learn that the topology changed".format(node.name, port, leg.role))
        logger.info("blocked %s:%s still hears ieee=%d", node.name, port, cap["ieee"])

    # ------------------------------------------------- what is on the wire
    def test_the_bpdus_on_the_wire_are_mstp(self, topo):
        """Speaking MSTP, not something that merely carries the same address. A
                bridge that fell back to classic STP would use the same address and
                still build a tree, so the version is what distinguishes them.
        """
        topo.converge(MODE, CIST)
        for leg in topo.legs:
            a, a_eth = capture_end(leg)
            assert a is not None, "leg {} has no capturable end".format(leg.role)
            cap = a.capture_bpdus(a_eth, seconds=10)
            assert cap["ieee"], "leg {} carried no IEEE BPDU".format(leg.role)
            mstp = [ln for ln in cap["lines"] if "802.1s" in ln]
            assert mstp, (
                "leg {} carries BPDUs but none decode as 802.1s. A sample was: {}"
                .format(leg.role, cap["lines"][0] if cap["lines"] else "(none)"))
            logger.info("leg %-10s %d of %d BPDUs are 802.1s",
                        leg.role, len(mstp), len(cap["lines"]))

    # ------------------------------------------------- moving the CIST tree
    def test_cist_bridge_priority_moves_the_root(self, topo):
        """The root is a decision, not a property of the wiring."""
        topo.converge(MODE, CIST)
        assert topo.t1.is_self_root(MODE, CIST), "the t1 was not root to begin with"
        topo.t0_2.set_bridge_priority(MODE, CIST, 4096)
        try:
            ok = wait_until(150, 3, lambda: topo.t0_2.is_self_root(MODE, CIST),
                            "{} becomes the CIST root".format(topo.t0_2.name))
            assert ok, (
                "{} did not become the CIST root after its priority was lowered to "
                "4096: {}".format(topo.t0_2.name, topo.t0_2.bridge_data(MODE, CIST)))
            new_root = topo.t0_2.bridge_mac()
            ok, seen = wait_for_value(90, 3, lambda: (
                all(n.root_is(MODE, CIST, new_root) for n in topo.all_nodes()),
                {n.name: n.root_bridge_id(MODE, CIST) for n in topo.all_nodes()}))
            assert ok, "the other bridges did not follow the new root: {}".format(seen)
        finally:
            topo.t0_2.set_bridge_priority(MODE, CIST, 32768)
            topo.converge(MODE, CIST, timeout=180)

    def test_cist_port_cost_moves_the_root_port(self, topo):
        """Cost on the parallel pair decides which equal cost port wins."""
        if not topo.has_parallel_pair:
            pytest.skip("this topology has no equal cost pair: the switch under "
                        "test has one port to each neighbour, so there is no "
                        "choice between two identical paths to observe")
        leg_a, leg_b = topo.parallel_legs
        sut = topo.t0_1
        topo.converge(MODE, CIST)
        before = sut.root_port(MODE, CIST)
        assert before in (leg_a.b_port, leg_b.b_port), (
            "the switch under test's CIST root port is {}, expected one of the "
            "parallel pair {}".format(before, [leg_a.b_port, leg_b.b_port]))

        sut.set_port_cost(MODE, CIST, before, 20000)
        try:
            ok, seen = wait_for_value(150, 3, lambda: (
                sut.root_port(MODE, CIST) not in ("", before),
                sut.root_port(MODE, CIST)))
            assert ok, (
                "the CIST root port stayed on {} after that port was costed up to "
                "20000; the other member of the pair should have won".format(before))
            logger.info("CIST root port moved %s -> %s", before, seen)
        finally:
            sut.set_port_cost(MODE, CIST, before, 200)
            topo.converge(MODE, CIST, timeout=180)

    # ---------------------------------------------------- region boundaries
    def test_a_revision_mismatch_alone_creates_a_boundary(self, topo):
        """Both fields define a region, so both have to split one. A revision that
                differs while the name matches is the case where two bridges look like
                they agree and do not.
        """
        odd = topo.t0_2
        topo.converge(MODE, CIST)
        odd.set_region(MST_REGION, MST_REVISION + 5)
        try:
            ok = wait_until(90, 3, lambda: odd.region_config().get("revision") ==
                            str(MST_REVISION + 5), "revision change applied")
            assert ok, "{} did not take the new revision: {}".format(
                odd.name, odd.region_config())
            assert odd.region_config().get("name") == MST_REGION, \
                "the region name changed as well, which is not the case under test"

            assert topo.converge(MODE, CIST, timeout=180), (
                "the CIST did not settle after the revision split: {}".format(
                    topo.port_states(MODE, CIST)))
            assert_boundary_legs(topo, odd)
            states = [odd.port_state(MODE, CIST, p) for p in odd.ports.values()]
            assert FORWARDING in states, (
                "{} has no forwarding CIST port after a revision only mismatch. The "
                "CIST spans regions, so a boundary must not cut the bridge off. "
                "States: {}".format(odd.name, dict(zip(odd.ports.values(), states))))
        finally:
            odd.set_region(MST_REGION, MST_REVISION)
            topo.converge(MODE, CIST, timeout=180)

    def test_max_hops_is_the_budget_the_cist_starts_from(self, topo):
        """Hop count is MSTP's loop bound inside a region and is configurable. The
                default is 20, and changing it has to change what the root starts from.
        """
        topo.converge(MODE, CIST)
        field = "remaining_hops"
        start = topo.t1.bridge_data(MODE, CIST).get(field)
        if start is None:
            pytest.skip("this build publishes no {} field: bridge row is {}".format(
                field, topo.t1.bridge_data(MODE, CIST)))
        assert int(start) == 20, \
            "the root starts from {} hops, expected the documented default 20".format(start)

        for node in topo.all_nodes():
            node.config("config spanning-tree max_hops 12")
        try:
            ok, seen = wait_for_value(120, 3, lambda: (
                topo.t1.bridge_data(MODE, CIST).get(field) == "12",
                topo.t1.bridge_data(MODE, CIST).get(field)))
            assert ok, (
                "the root still starts from {} hops after max_hops was set to 12, "
                "so the configured budget is not reaching the tree".format(seen))
        finally:
            for node in topo.all_nodes():
                node.exec("config spanning-tree max_hops 20")
            topo.converge(MODE, CIST, timeout=180)
