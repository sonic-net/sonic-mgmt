# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
What the switch under test advertises, read off the wire by a real neighbour.

State tables say what a bridge believes; a BPDU says what it tells the next
bridge. Injection cannot make a switch the designated bridge on a real leg and
then read what arrives at the far end. Here the t0_2 neighbour is demoted so
the switch under test wins the leg between them, and its BPDUs are decoded
there.

"""
import logging

import pytest

from .l2topo import FORWARDING, MST, PVST, wait_for_value

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

WORST = 61440
DEFAULT_PRIORITY = 32768
PARKED_COST = 200000   # the observed leg, so it can never win the root port
CIST = 0


def leg_root_port(topo, mode, scope):
    """The switch under test's current root port, or None."""
    rp = topo.t0_1.root_port(mode, scope)
    return None if rp in ("", "Root") else rp


def _scope(topo, mode):
    return CIST if mode == MST else topo.vlans[0]


def _capture_from_sut(topo, leg, mode, scope, seconds=10):
    """BPDUs the switch under test sends down `leg`, decoded at the far end."""
    far = leg.a if leg.b is topo.t0_1 else leg.b
    far_eth = leg.a_eth if far is leg.a else leg.b_eth
    seen = far.capture_bpdu_details(far_eth, seconds=seconds, direction="in")
    sut_mac = topo.t0_1.bridge_mac().lower()
    mine = [b for b in seen if b.get("bridge_mac") == sut_mac]
    if not mine:
        raise AssertionError(
            "{} saw no BPDU from {} ({}) on {} in {}s; it saw {} BPDUs from {}".format(
                far.name, topo.t0_1.name, sut_mac, far_eth, seconds, len(seen),
                sorted({b.get("bridge_mac", "?") for b in seen})))
    return mine


class _Advertised(object):
    """Shared body for both modes: demote t0_2, make the switch under test the
        designated bridge on the leg between them, and read its BPDUs there.
    """

    MODE = None

    @pytest.fixture(autouse=True)
    def sut_designated(self, topo):
        mode = self.MODE
        scope = _scope(topo, mode)
        leg = topo.cross_leg
        sut, neighbour = topo.t0_1, topo.t0_2
        sut_port = leg.b_port if leg.b is sut else leg.a_port
        neighbour.set_bridge_priority(mode, scope, WORST)
        # Price the observed leg out of the running. Raising the root port's
        # cost is how this test moves the advertised value; without this the
        # switch re-elects onto the leg being watched and stops being the
        # designated bridge there. Record the real costs first, so teardown
        # restores a configured value rather than an invented default.
        self.original = {p: sut.port_path_cost(mode, scope, p)
                         for p in (sut_port, leg_root_port(topo, mode, scope))
                         if p}
        sut.set_port_cost(mode, scope, sut_port, PARKED_COST)
        try:
            assert topo.converge(mode, scope), "tree did not settle after demoting {}".format(
                neighbour.name)
            state = sut.port_state(mode, scope, sut_port)
            assert state == FORWARDING, (
                "{}:{} is {} after {} was demoted to priority {}; the switch under test "
                "has to be the designated bridge on this leg for its BPDUs to be "
                "observable".format(sut.name, sut_port, state, neighbour.name, WORST))
            # Verify the parking took. If it did not, the switch can re-elect
            # onto this leg and the advertisement would be about another path.
            parked = sut.port_path_cost(mode, scope, sut_port)
            assert parked == PARKED_COST, (
                "{}:{} still reads path cost {!r} after being set to {}; without "
                "that the switch can re-elect onto this leg mid-test and the "
                "number read off the wire is about another path".format(
                    sut.name, sut_port, parked, PARKED_COST))
            self.leg, self.scope = leg, scope
            self.root_port = sut.root_port(mode, scope)
            assert self.root_port not in ("", "Root"), (
                "{} has no root port ({!r}) in {}; it needs one for a root path cost to "
                "be advertised".format(sut.name, self.root_port, mode))
            yield
        finally:
            neighbour.set_bridge_priority(mode, scope, DEFAULT_PRIORITY)
            for port, cost in getattr(self, "original", {}).items():
                if cost is not None:
                    sut.set_port_cost(mode, scope, port, cost)
            topo.converge(mode, scope)

    def _cost_test(self, topo):
        mode, scope, leg = self.MODE, self.scope, self.leg
        sut = topo.t0_1
        before = _capture_from_sut(topo, leg, mode, scope)
        baseline = before[-1].get("root_path_cost")
        assert baseline is not None, "no root path cost decoded: {}".format(before[-1]["raw"])
        logger.info("%s advertises root path cost %s before the change (root port %s)",
                    sut.name, baseline, self.root_port)
        assert baseline != 0, (
            "{} advertises root path cost 0 while {} is its root port. A non root bridge "
            "one hop from the root advertises at least that port's cost".format(
                sut.name, self.root_port))

        # Lower the root port's cost rather than raise it. Root path cost is
        # compared before bridge id, so a higher cost can hand the watched leg
        # to the neighbour and the switch stops sending BPDUs there.
        port_cost = self.original.get(self.root_port) or sut.port_path_cost(
            mode, scope, self.root_port)
        assert port_cost and port_cost > 1, (
            "{}:{} has no usable path cost to lower ({!r})".format(
                sut.name, self.root_port, port_cost))
        test_cost = port_cost // 2
        expected = baseline - (port_cost - test_cost)
        sut.set_port_cost(mode, scope, self.root_port, test_cost)
        try:
            def advertised():
                # A capture can come back empty while the tree reacts to the
                # change; keep polling rather than ending the measurement.
                try:
                    cost = _capture_from_sut(topo, leg, mode, scope, seconds=6)[-1].get(
                        "root_path_cost")
                except AssertionError:
                    return False, None
                return cost == expected, cost
            ok, seen = wait_for_value(120, 4, advertised)
            assert sut.root_port(mode, scope) == self.root_port, (
                "the root port moved from {} to {} when its cost was lowered, so the "
                "switch is no longer the designated bridge on the leg being "
                "watched; the test cannot read its advertisement".format(
                    self.root_port, sut.root_port(mode, scope)))
            assert ok, (
                "after config spanning-tree {} interface cost {} {} {}, {} advertises "
                "root path cost {} to {}, expected {} (was {} before the change)".format(
                    "mst instance" if mode == MST else "vlan", scope, self.root_port,
                    test_cost, sut.name, seen, topo.t0_2.name, expected, baseline))
        finally:
            # `baseline` is an advertised root path cost, not this port's cost,
            # so it is not a value to restore here.
            original = self.original.get(self.root_port)
            if original is not None:
                sut.set_port_cost(mode, scope, self.root_port, original)
            topo.converge(mode, scope)


@pytest.mark.usefixtures("pvst")
class TestPvstAdvertisedCost(_Advertised):
    MODE = PVST

    def test_the_advertised_root_path_cost_follows_the_configured_port_cost(self, topo):
        """A bridge one hop below the root must advertise at least its root port's
                cost, and a changed port cost must show on the wire.
        """
        self._cost_test(topo)


@pytest.mark.usefixtures("mstp")
class TestMstpAdvertisedCost(_Advertised):
    MODE = MST

    def test_the_advertised_cist_root_path_cost_follows_the_configured_port_cost(self, topo):
        """Deliberately unmarked. An xfail(strict) here reported the marker's reason
                instead of the assertion when the precondition failed, so a correct
                re-election read as a daemon that ignored a cost.
        """
        self._cost_test(topo)

    def test_the_advertised_port_id_follows_the_configured_port_priority(self, topo):
        """The port priority written by `config spanning-tree mst instance interface
                priority` has to reach the daemon and move the advertised port id.
        """
        mode, scope, leg = self.MODE, self.scope, self.leg
        sut = topo.t0_1
        sut_port = leg.b_port if leg.b is sut else leg.a_port
        before = _capture_from_sut(topo, leg, mode, scope)[-1]
        assert "port_id" in before, "no port id decoded: {}".format(before["raw"])
        default_nibble = before["port_id"] >> 12
        new_priority = 64 if default_nibble != 4 else 32
        sut.set_port_priority(mode, scope, sut_port, new_priority)
        try:
            def advertised():
                try:
                    port_id = _capture_from_sut(topo, leg, mode, scope, seconds=6)[-1].get("port_id")
                except AssertionError:
                    return False, None
                return port_id is not None and (port_id >> 12) == new_priority // 16, port_id
            ok, seen = wait_for_value(90, 4, advertised)
            assert ok, (
                "after config spanning-tree mst instance interface priority {} {} {}, {} "
                "still advertises port id {:#06x} on {} (priority nibble {}, expected {})".format(
                    scope, sut_port, new_priority, sut.name, seen or 0, sut_port,
                    (seen or 0) >> 12, new_priority // 16))
        finally:
            sut.set_port_priority(mode, scope, sut_port, default_nibble * 16)
            topo.converge(mode, scope)
