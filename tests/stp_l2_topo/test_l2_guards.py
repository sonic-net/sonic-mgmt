# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Root guard across real bridges: whether a guarded port returns to service once
the superior bridge withdraws its claim.

Injection can show a switch a superior BPDU, but not the withdrawal and
recovery that follow. MSTP root guard is 802.1Q restrictedRole, so the port
should recover when the superior information ages out. PVST has
root_guard_timeout for the same purpose and is the control here.

"""
import logging
import time

import pytest

from .l2topo import FORWARDING, MST, PVST, is_blocked, wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0-l2tri'),
    # The suite deliberately blocks ports and drops legs, which the image logs
    # at error level.
    pytest.mark.disable_loganalyzer,
]

SUPERIOR = 0
WORST = 61440
DEFAULT_PRIORITY = 32768
CIST = 0
RECOVERY_WINDOW = 240


class _RootGuardRecovers(object):
    MODE = None

    def _run(self, topo):
        mode = self.MODE
        scope = CIST if mode == MST else topo.vlans[0]
        leg = topo.cross_leg
        sut, neighbour = topo.t0_1, topo.t0_2
        sut_port = leg.b_port if leg.b is sut else leg.a_port
        # Root guard only means anything on a designated forwarding port, so
        # demote the neighbour first. An alternate port is already discarding
        # before the guard is armed and would measure nothing.
        neighbour.set_bridge_priority(mode, scope, WORST)
        assert topo.converge(mode, scope), "tree did not settle before the test"
        assert sut.root_port(mode, scope) != sut_port, (
            "{}:{} is the root port; the guard has to go on a port that is not "
            "already the way to the root".format(sut.name, sut_port))
        before = sut.port_state(mode, scope, sut_port)
        assert before == FORWARDING, (
            "{}:{} is {} before the guard is armed, even with {} demoted to {}. "
            "A guard test needs a forwarding designated port; a port that is "
            "already blocked cannot be observed being blocked.".format(
                sut.name, sut_port, before, neighbour.name, WORST))

        sut.set_root_guard(sut_port, True)
        neighbour.set_bridge_priority(mode, scope, SUPERIOR)
        try:
            tripped = wait_until(60, 2, lambda: is_blocked(sut.port_state(mode, scope, sut_port)),
                                 "root guard trips")
            state = sut.port_state(mode, scope, sut_port)
            assert tripped, (
                "{}:{} is {} after {} became the superior bridge (priority {}); root "
                "guard did not refuse it".format(sut.name, sut_port, state,
                                                 neighbour.name, SUPERIOR))
            logger.info("%s:%s tripped to %s (was %s)", sut.name, sut_port, state, before)

            # Withdraw the claim: back to the priority the port was forwarding
            # under, so recovery is all that is measured.
            neighbour.set_bridge_priority(mode, scope, WORST)
            withdrawn = time.time()
            recovered, seen = False, state
            while time.time() - withdrawn < RECOVERY_WINDOW:
                seen = sut.port_state(mode, scope, sut_port)
                if seen == FORWARDING:
                    recovered = True
                    break
                time.sleep(5)
            logger.info("%s:%s is %s %.0fs after the claim was withdrawn",
                        sut.name, sut_port, seen, time.time() - withdrawn)
            assert recovered, (
                "{}:{} is still {} {}s after {} stopped claiming the root, so {} "
                "root guard has no working recovery path. PVST recovers on "
                "root_guard_timeout.".format(
                    sut.name, sut_port, seen, RECOVERY_WINDOW, neighbour.name,
                    mode.upper()))
        finally:
            neighbour.set_bridge_priority(mode, scope, DEFAULT_PRIORITY)
            sut.set_root_guard(sut_port, False)
            topo.converge(mode, scope)


@pytest.mark.usefixtures("mstp")
class TestMstpRootGuard(_RootGuardRecovers):
    MODE = MST

    def test_a_guarded_port_recovers_when_the_claim_is_withdrawn(self, topo):
        """Unmarked on purpose, so whatever this reports is a measurement of root
                guard.
        """
        self._run(topo)


@pytest.mark.usefixtures("pvst")
class TestPvstRootGuard(_RootGuardRecovers):
    MODE = PVST

    def test_a_guarded_port_recovers_when_the_claim_is_withdrawn(self, topo):
        """PVST has root_guard_timeout (default 30s) for exactly this, so it is the
                control: the same sequence in the mode that is meant to recover.
        """
        self._run(topo)
