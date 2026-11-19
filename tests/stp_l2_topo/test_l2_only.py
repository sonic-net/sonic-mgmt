# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
The cases that only a real topology can reach.

A PTF test injects frames and watches one switch react. It cannot run a
spanning tree of its own, so anything depending on two independent bridges
agreeing, on a loop physically existing, or on traffic following the elected
tree belongs here. Everything else belongs in the PTF suite.

"""
import logging

import pytest

from .l2topo import (FORWARDING, PVST, all_endpoints, capture_many, entry_point, is_blocked,
                     leg_states, tagged_broadcast, wait_for_value, wait_until)

from .conftest import make_t1_root


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

MODE = PVST
PROBE_SRC = "02:00:00:de:ad:01"


@pytest.mark.usefixtures("pvst")
class TestTopologyOnly(object):

    def test_the_tree_forwards_on_exactly_two_legs(self, topo):
        """A spanning tree over three bridges has two edges. The triangle offers three
                legs, so one has to be given up. Checkable only with every bridge's view
                in hand at once.
        """
        for vlan in topo.vlans:
            assert topo.converge(MODE, vlan), \
                "VLAN {} never settled: {}".format(vlan, topo.port_states(MODE, vlan))
            forwarding = [leg.role for leg in topo.legs
                          if all(s == FORWARDING for s in leg_states(leg, MODE, vlan))]
            assert len(forwarding) == 2, (
                "VLAN {}: {} of 3 legs forward at both ends ({}). Three bridges "
                "need exactly two edges: fewer than two partitions the topology, "
                "more than two is a loop. Full state: {}".format(
                    vlan, len(forwarding), forwarding, topo.port_states(MODE, vlan)))

    def test_no_leg_is_blocked_at_both_ends(self, topo):
        """One end of every leg has to be designated. A leg blocked at both ends is a
                segment nothing can cross, which a single switch cannot detect about
                itself.
        """
        for vlan in topo.vlans:
            topo.converge(MODE, vlan)
            for leg in topo.legs:
                a_state, b_state = leg_states(leg, MODE, vlan)
                assert not (is_blocked(a_state) and is_blocked(b_state)), (
                    "VLAN {}: leg {} is blocked at both ends ({}:{} is {}, "
                    "{}:{} is {})".format(vlan, leg.role, leg.a.name, leg.a_port,
                                          a_state, leg.b.name, leg.b_port, b_state))

    def test_exactly_one_bridge_is_root_per_vlan(self, topo):
        """Two bridges each believing they are root means the topology is split."""
        for vlan in topo.vlans:
            topo.converge(MODE, vlan)
            roots = [n.name for n in topo.all_nodes() if n.is_self_root(MODE, vlan)]
            assert roots == [topo.t1.name], (
                "VLAN {}: bridges claiming root are {}, expected only the t1 ({}). "
                "More than one means they are not hearing each other.".format(
                    vlan, roots, topo.t1.name))

    def test_a_broadcast_does_not_circulate(self, topo):
        """What spanning tree is for, and the one case a loop is required to prove.

                A broadcast is injected and every leg watched. It has to be seen while
                flooding, which shows it entered the topology, and gone afterwards,
                which shows the triangle is not carrying it round.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        leg, sender, eth = entry_point(topo, MODE, vlan)
        assert sender is not None, \
            "no forwarding entry point for VLAN {}: {}".format(vlan, topo.port_states(MODE, vlan))

        frame = tagged_broadcast(vlan, PROBE_SRC)
        bpf = "ether src {}".format(PROBE_SRC)
        endpoints = all_endpoints(topo)

        logger.info("injecting one broadcast on %s:%s (leg %s)", sender.name, eth, leg.role)
        import threading
        result = {}

        # The port the frame is injected on sees the injection itself, so it
        # cannot show the frame entered the topology; a sighting has to come
        # from another leg end.
        watched = [ep for ep in endpoints if not (ep[1] is sender and ep[2] == eth)]

        def _phase(name, seconds, inject):
            def run():
                result[name] = capture_many(watched if inject else endpoints, bpf, seconds)
            t = threading.Thread(target=run)
            t.start()
            if inject:
                import time as _t
                _t.sleep(2.5)          # capture_many attaches for 2s
                sender.inject(eth, frame)
            t.join()

        _phase("flood", 5, True)
        flooded = sum(result["flood"].values())
        _phase("after", 8, False)
        lingering = sum(result["after"].values())

        logger.info("flood window %s", result["flood"])
        logger.info("later window %s", result["after"])
        assert flooded > 0, (
            "the injected broadcast was never seen on any leg, so it did not enter "
            "the topology and nothing about looping was tested. Entry was {}:{} on "
            "leg {}.".format(sender.name, eth, leg.role))
        assert lingering == 0, (
            "the broadcast was still crossing legs {} seconds after it was sent: {}. "
            "A frame that outlives its flooding is going round the triangle, so a "
            "leg that should be blocked is forwarding.".format(
                8, {k: v for k, v in result["after"].items() if v}))

    def test_the_blocked_port_still_receives_bpdus(self, topo):
        """A blocked port keeps processing BPDUs, or the tree can never recover. The
                distinction only exists with a real neighbour still sending on the leg
                that was given up.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        blocked = None
        for leg in topo.legs:
            a_state, b_state = leg_states(leg, MODE, vlan)
            if is_blocked(a_state):
                blocked = (leg, leg.a, leg.a_eth, leg.a_port)
            elif is_blocked(b_state):
                blocked = (leg, leg.b, leg.b_eth, leg.b_port)
            if blocked:
                break
        assert blocked, "no blocked port on VLAN {}: {}".format(
            vlan, topo.port_states(MODE, vlan))

        leg, node, eth, port = blocked
        if not node.can_capture:
            pytest.skip("the blocked port is on a hardware switch, where a raw "
                        "capture on the port is not a view of the wire")
        cap = node.capture_bpdus(eth, seconds=10)
        assert cap["ieee"] or cap["pvst"], (
            "{}:{} is blocking on leg {} and heard no BPDU in 10s. A blocked port "
            "that stops hearing its neighbour cannot learn that the topology "
            "changed, so it would never unblock.".format(node.name, port, leg.role))
        logger.info("blocked %s:%s still hears ieee=%d pvst=%d",
                    node.name, port, cap["ieee"], cap["pvst"])

    def test_the_blocked_port_transmits_no_data(self, topo):
        """The other half of blocking, and the one that prevents the loop.

                Direction is the whole question. A blocked leg still carries the frame
                towards the blocked port, so what has to be true is that the blocking
                bridge never puts a data frame onto that leg itself. Inbound is the
                control: silence in both directions proves nothing.
        """
        if topo.has_hardware:
            pytest.skip("needs the switch under test to flood a probe two hops to "
                        "a blocked virtual port, a data-plane path a hardware bridge "
                        "does not guarantee. The loop-freedom invariant this protects "
                        "is covered by test_a_broadcast_does_not_circulate")
        vlan = topo.vlans[0]
        assert topo.converge(MODE, vlan, timeout=240), "the tree never settled"

        blocked = None
        for leg in topo.legs:
            a_state, b_state = leg_states(leg, MODE, vlan)
            if is_blocked(b_state):
                blocked = (leg, leg.b, leg.b_eth, leg.b_port)
            elif is_blocked(a_state):
                blocked = (leg, leg.a, leg.a_eth, leg.a_port)
            if blocked:
                break
        assert blocked, "no blocked port on VLAN {}: {}".format(
            vlan, topo.port_states(MODE, vlan))
        leg, blocker, block_eth, block_port = blocked
        if not blocker.can_capture:
            pytest.skip("the blocked port is on a hardware switch, where a raw "
                        "capture on the port is not a view of the wire")

        # Two injections, both from the far side. From the other end of the
        # blocked leg the frame lands on the blocked port: that is the inbound
        # control. From the far end of one of the blocker's forwarding legs it
        # enters the blocker the legitimate way, which is what would make a
        # broken blocker flood it back out onto the blocked leg.
        def far_end(lg, node):
            (a, a_eth, _), (b, b_eth, _) = lg.ends()
            return (b, b_eth) if a is node else (a, a_eth)

        sends = [far_end(leg, blocker)]
        for lg in topo.legs:
            ends = lg.ends()
            mine = [p for (nd, e, p) in ends if nd is blocker]
            if lg is not leg and mine and blocker.port_state(MODE, vlan, mine[0]) == FORWARDING:
                sends.append(far_end(lg, blocker))
                break
        sends = [(n, e) for (n, e) in sends if n.can_capture]
        if not sends:
            pytest.skip("no virtual bridge available to inject from")

        src = "02:00:00:de:ad:02"
        frame = tagged_broadcast(vlan, src, tag=0xBEEF)
        bpf = "ether src {}".format(src)
        endpoints = [("inbound", blocker, block_eth, "in"),
                     ("outbound", blocker, block_eth, "out")]

        import threading
        import time as _t
        out = {}

        def run():
            out["counts"] = capture_many(endpoints, bpf, 8)
        t = threading.Thread(target=run)
        t.start()
        _t.sleep(2.5)
        for _ in range(3):
            for sender, send_eth in sends:
                sender.inject(send_eth, frame)
            _t.sleep(0.4)
        t.join()

        counts = out["counts"]
        logger.info("blocked %s:%s in=%d out=%d",
                    blocker.name, block_port, counts["inbound"], counts["outbound"])
        assert counts["inbound"] > 0, (
            "the frame never reached {}:{} on leg {}, so the blocked port was never "
            "given anything to drop and nothing was tested. Injected from {}."
            .format(blocker.name, block_port, leg.role,
                    ", ".join("{}:{}".format(n.name, e) for n, e in sends)))
        assert counts["outbound"] == 0, (
            "{}:{} is blocking on leg {} but transmitted {} data frame(s) onto it. "
            "A blocking port carries BPDUs and nothing else, and putting data onto "
            "a leg that the tree gave up is the loop the topology exists to prevent."
            .format(blocker.name, block_port, leg.role, counts["outbound"]))

    @pytest.mark.usefixtures("restore_legs")
    def test_a_new_root_is_elected_when_the_root_leaves(self, topo):
        """Re-election by mutual agreement, with no candidate configured. Taking the
                root out leaves two bridges to agree on a new one and rebuild a tree over
                the leg they had given up.
        """
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        assert topo.t1.is_self_root(MODE, vlan), "the t1 was not root to begin with"

        for leg in topo.legs:
            if topo.t1 in (leg.a, leg.b):
                leg.set_up(False)
        try:
            survivors = [topo.t0_1, topo.t0_2]

            def agreed():
                # Settled means one survivor is root and the other has elected
                # it, not merely that one of them claims root first. A switch
                # whose own port was shut loses the root at once while its
                # neighbour keeps the old root until max age runs out.
                roots = [n for n in survivors if n.is_self_root(MODE, vlan)]
                seen = {n.name: n.root_port(MODE, vlan) for n in survivors}
                if len(roots) != 1:
                    return False, seen
                other = next(n for n in survivors if n is not roots[0])
                return other.root_is(MODE, vlan, roots[0].bridge_mac()), seen

            ok, seen = wait_for_value(180, 3, agreed)
            assert ok, (
                "the two remaining bridges did not agree on one root after the "
                "root left. root_port per bridge: {}".format(seen))

            new_root = next(n for n in survivors if n.is_self_root(MODE, vlan))
            # The survivor with the lowest bridge MAC wins, whichever node that
            # is, so the winner is computed rather than named.
            expected = min(survivors, key=lambda n: n.bridge_mac())
            assert new_root is expected, (
                "{} became root, expected {} which carries the lower bridge "
                "MAC ({} vs {})".format(new_root.name, expected.name,
                                        expected.bridge_mac(), new_root.bridge_mac()))

            # The leg the survivors gave up is the one joining them.
            cross = next(lg for lg in topo.legs
                         if lg.a in survivors and lg.b in survivors)
            ok = wait_until(120, 3,
                            lambda: all(s == FORWARDING for s in leg_states(cross, MODE, vlan)),
                            "cross leg forwards at both ends")
            assert ok, (
                "the t0 to t0 leg did not come up at both ends after the root "
                "left, so the two survivors have no path to each other: {}".format(
                    leg_states(cross, MODE, vlan)))
        finally:
            for leg in topo.legs:
                leg.set_up(True)

        ok = wait_until(180, 3, lambda: topo.t1.is_self_root(MODE, vlan),
                        "the t1 takes the root back")
        assert ok, "the t1 did not become root again after its legs returned"

    def test_a_broadcast_circulates_without_spanning_tree(self, topo, request):
        """The control that shows the loop test can fail. Off by default: without
                spanning tree the triangle is a real loop and this is a broadcast storm
                on purpose. Run it deliberately with --allow-storm.
        """
        if not request.config.getoption("--allow-storm"):
            pytest.skip("needs --allow-storm: this deliberately creates a broadcast "
                        "storm, which is what proves test_a_broadcast_does_not_"
                        "circulate is capable of failing")
        vlan = topo.vlans[0]
        topo.converge(MODE, vlan)
        _leg, sender, eth = entry_point(topo, MODE, vlan)
        assert sender is not None

        src = "02:00:00:de:ad:03"
        frame = tagged_broadcast(vlan, src, tag=0xF00D)
        bpf = "ether src {}".format(src)
        endpoints = all_endpoints(topo)

        for node in topo.all_nodes():
            node.disable_stp()
        try:
            import threading
            import time as _t
            out = {}

            def run():
                out["counts"] = capture_many(endpoints, bpf, 10)
            t = threading.Thread(target=run)
            t.start()
            _t.sleep(2.5)
            sender.inject(eth, frame)
            t.join()
            total = sum(out["counts"].values())
            assert total > 0, (
                "with spanning tree off the triangle is a physical loop, so one "
                "broadcast should still have been circulating after 10s. Seeing "
                "none means the loop test cannot fail and is not proving anything.")
            logger.info("storm control: %d sightings with spanning tree off", total)
        finally:
            # The topology's set_mode, not each node's: it also re-enrols the ports.
            assert topo.set_mode(MODE), "no tree after turning spanning tree back on"
            # The disable dropped the per-VLAN rows and the t1's priority with them.
            make_t1_root(topo, MODE, list(topo.vlans))
            assert topo.converge(MODE, vlan, timeout=180), \
                "VLAN {} never settled after the storm test: {}".format(vlan, topo.port_states(MODE, vlan))
