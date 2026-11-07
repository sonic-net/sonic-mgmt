"""
PVST (Per-VLAN Spanning Tree) sonic-mgmt tests.

`TestPvst` subclasses `StpTestBase` (STP_MODE="pvst"), reusing the shared,
mode-parameterized config/verify/PTF helpers. This is the PVST sibling of
`test_mstp.py`, ported from the standalone `tests/pvst/test_pvst.py` suite into
the shared framework:

  * scope is the VLAN id (MST uses CIST instance 0);
  * the "not forwarding" state is BLOCKING (MST reports DISCARDING);
  * the PTF is driven with `pvst_bpdu_test.PvstBpduTest`, selected by mode in
    `run_bpdu`. A PVST "config" BPDU is superior by default (the PTF advertises a
    better bridge id), so `_superior_params` only needs the VLAN + send ports.

Every assertion here is validated only on a testbed run (no scapy/PTF locally).
"""
import logging
import time

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.stp import stp_utils
from tests.stp.stp_base import StpTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs'),
    # STP exercises deliberately produce error-level syslogs (bpdu-guard
    # err-disable, superior-BPDU processing); LogAnalyzer's end-marker read is
    # also unreliable on this image. Disabled for the module (see test_mstp.py).
    pytest.mark.disable_loganalyzer,
]

# A locally-injected dummy source MAC used to check FDB learning per port.
DUMMY_MAC_PREFIX = "00:11:22:33:55"

# A port takes two forward delays (15 s each by default) to reach FORWARDING.
# Portfast cuts each to 2 s and uplink fast to 1 s, so anything under this
# bound is the fast path and anything that is still not forwarding at this
# point took the slow one.
FAST_TRANSITION_LIMIT = 10
SLOW_TRANSITION_LIMIT = 60


def _config_port_field(duthost, port, field):
    return duthost.shell("redis-cli -n 4 hget 'STP_PORT|{}' {}".format(port, field),
                         module_ignore_errors=True).get("stdout", "").strip()


def _port_fast_flag(duthost, port):
    """The daemon's operational portfast flag for `port`. The table
    materialises under its bare name once orchagent consumes it, and only
    under the producer's underscored name before that."""
    for key in ("STP_PORT_TABLE:{}".format(port), "_STP_PORT_TABLE:{}".format(port)):
        flag = stp_utils._hgetall(duthost, key).get("port_fast")
        if flag:
            return flag
    return ""


def _port_stats(duthost, vlan_id, port):
    row = stp_utils.get_port_data(duthost, stp_utils.PVST, vlan_id, port)
    return {f: int(row.get(f, "0") or "0")
            for f in ("bpdu_sent", "bpdu_received", "tc_sent", "tc_received")}


class TestPvst(StpTestBase):

    STP_MODE = "pvst"
    # PVST reports the non-forwarding state as BLOCKING (MST uses DISCARDING).
    BLOCK_STATE = "BLOCKING"

    # ---------------------------------------------------------------- helpers
    def _superior_params(self, data, send_ptf_ports, **overrides):
        """PVST superior-BPDU params: the PVST PTF advertises a better bridge id
        by default, so only the VLAN + send ports are needed."""
        params = {"vlan_id": data["vlan"]["id"], "send_port": list(send_ptf_ports)}
        params.update(overrides)
        return params

    @staticmethod
    def _bridge_cfg(duthost, vlan_id):
        """CONFIG_DB `STP_VLAN|Vlan<vid>` -- the configured priority + timers the
        DUT advertises (PVST folds the VLAN id into the advertised priority)."""
        out = duthost.shell("redis-cli -n 4 HGETALL 'STP_VLAN|Vlan{}'".format(vlan_id),
                            module_ignore_errors=True).get("stdout_lines", [])
        return dict(zip(out[::2], out[1::2]))

    @pytest.fixture(autouse=True)
    def pvst_quiesced(self, duthosts, rand_one_dut_hostname, setup_stp_test_data):
        """Start every test from the same converged baseline: the lone DUT is
        the root of the VLAN under test. A neighbour the previous test injected
        is held for a max age after its last frame, so without this gate the
        next test's precondition reads the leftover and fails."""
        duthost = duthosts[rand_one_dut_hostname]
        vlan_id = setup_stp_test_data["vlan"]["id"]
        if not wait_until(60, 3, 0, lambda: self.is_self_root(duthost, vlan_id)):
            self.bounce_stp(duthost)
            pytest_assert(
                wait_until(60, 3, 0, lambda: self.is_self_root(duthost, vlan_id)),
                "DUT did not return to root of VLAN {} before the test started".format(vlan_id))
        yield

    # ============================== testcases ===============================
    def test_pvst_validate_root_bridge(self, duthosts, rand_one_dut_hostname, ptfhost,
                                       setup_stp_test_data):
        """A lone DUT is the root bridge for the VLAN; its ports transition
        LISTENING -> LEARNING -> FORWARDING; the BPDU it emits carries the DUT
        bridge id/priority/timers; and an L2 frame forwards between its ports."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        self.bounce_stp(duthost)

        pytest_assert(wait_until(60, 2, 0, lambda: self.is_self_root(duthost, vlan_id)),
                      "DUT is not the root bridge for VLAN {}".format(vlan_id))
        for state in ("LISTENING", "LEARNING", "FORWARDING"):
            self.verify_stp_state(duthost, vlan_id, [dut_port_1, dut_port_2], state)

        cfg = self._bridge_cfg(duthost, vlan_id)
        bd = self.get_bridge_data(duthost, vlan_id)
        bridge_priority = int(cfg["priority"]) + vlan_id
        for cap in (ptf_port_1, ptf_port_2):
            self.run_bpdu(
                ptfhost, duthost, "validate_bpdu_packet",
                {"vlan_id": vlan_id,
                 "expected_bridge_mac": d["dut_ports"]["mac"],
                 "expected_bridge_priority": bridge_priority,
                 "expected_hello_time": int(cfg["hello_time"]),
                 "expected_max_age": int(cfg["max_age"]),
                 "expected_forward_delay": int(cfg["forward_delay"]),
                 "expected_root_path_cost": int(bd.get("root_path_cost", "0") or 0),
                 "capture_port": cap, "capture_duration": self.PKT_CAPTURE_DURATION},
                "/tmp/pvst_root_bridge_cap{}.log".format(cap))

        self.run_bpdu(
            ptfhost, duthost, "validate_l2_packet",
            {"send_port": ptf_port_1, "receive_port": ptf_port_2,
             "vlan_id": vlan_id, "verify_packet": True},
            "/tmp/pvst_root_bridge_l2.log")

    def test_pvst_designated_bridge(self, duthosts, rand_one_dut_hostname, ptfhost,
                                    setup_stp_test_data):
        """Under a superior neighbor the DUT roots on port_1 (port_2 blocking); a
        frame from the forwarding port learns its source MAC on that port."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        with self.periodic_superior_sender(
                ptfhost, duthost, self._superior_params(d, [ptf_port_1, ptf_port_2]),
                "/tmp/pvst_designated_periodic.log"):

            pytest_assert(
                wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
                "DUT did not accept the superior neighbor as root")
            pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                          "root port is not {}".format(dut_port_1))
            self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)

            # Frame from the forwarding port -> its source MAC is learned on it.
            self.run_bpdu(
                ptfhost, duthost, "validate_l2_packet",
                {"send_port": ptf_port_1, "receive_port": ptf_port_2,
                 "vlan_id": vlan_id, "verify_packet": False},
                "/tmp/pvst_designated_l2.log")
            pytest_assert(
                wait_until(10, 2, 1, stp_utils.fdb_has_mac_for_interface,
                           duthost, dut_port_1, DUMMY_MAC_PREFIX),
                "source MAC not learned on forwarding port {}".format(dut_port_1))
            # NOTE: the blocking-port "MAC must NOT be learned" check is omitted --
            # the VS platform learns on blocking ports (no blocking-state support),
            # same limitation the reference PVST suite documents.

    def test_pvst_shutdown_root_port(self, duthosts, rand_one_dut_hostname, ptfhost,
                                     setup_stp_test_data):
        """Under a superior neighbor the DUT roots on port_1 (port_2 blocking);
        shutting port_1 moves the root to port_2; startup restores port_1."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost, self._superior_params(d, [ptf_port_1, ptf_port_2]),
                    "/tmp/pvst_shutdown_root_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
                    "DUT did not accept the superior neighbor as root")
                pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                              "root port is not {}".format(dut_port_1))
                self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)

                duthost.shell("config interface shutdown {}".format(dut_port_1))
                self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")
                pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_2),
                              "root port did not move to {}".format(dut_port_2))

                duthost.shell("config interface startup {}".format(dut_port_1))
                self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)
                pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                              "root port did not return to {}".format(dut_port_1))
        finally:
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)

    def test_pvst_bridge_priority_change_in_bpdu(self, duthosts, rand_one_dut_hostname, ptfhost,
                                                 setup_stp_test_data):
        """A superior neighbor is root until the DUT's VLAN priority is lowered
        past it; then the DUT is root, all ports forward, and its emitted BPDU
        carries the new bridge id/priority."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]
        default_priority = int(self._bridge_cfg(duthost, vlan_id).get("priority", "32768"))

        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost, self._superior_params(d, [ptf_port_1, ptf_port_2]),
                    "/tmp/pvst_bridge_priority_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
                    "DUT did not accept the superior neighbor as root")
                self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)

                # Lower the DUT VLAN priority below the neighbor's -> DUT is root.
                self.set_bridge_priority(duthost, vlan_id, self.BRIDGE_PRIORITY)
                pytest_assert(
                    wait_until(60, 2, 0, lambda: self.is_self_root(duthost, vlan_id)),
                    "DUT did not become root after lowering its priority")
                self.verify_stp_state(duthost, vlan_id, [dut_port_1, dut_port_2], "FORWARDING")

            bridge_priority = self.BRIDGE_PRIORITY + vlan_id
            for cap in (ptf_port_1, ptf_port_2):
                self.run_bpdu(
                    ptfhost, duthost, "validate_root_bridge_id",
                    {"vlan_id": vlan_id,
                     "expected_bridge_mac": d["dut_ports"]["mac"],
                     "expected_bridge_priority": bridge_priority,
                     "capture_port": cap, "capture_duration": self.PKT_CAPTURE_DURATION},
                    "/tmp/pvst_bridge_priority_cap{}.log".format(cap))
        finally:
            self.set_bridge_priority(duthost, vlan_id, default_priority)

    def test_pvst_port_priority_change_in_bpdu(self, duthosts, rand_one_dut_hostname, ptfhost,
                                               setup_stp_test_data):
        """With equal path cost the DUT roots on port_1; injecting a better CIST
        port priority on port_2 moves the root port there and blocks port_1."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        # Establish the superior neighbor on both ports; port_1 becomes root port.
        # (Convergence is confirmed by the wait_until below, so no fixed sleep.)
        for _ in range(2):
            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1, ptf_port_2]),
                          "/tmp/pvst_port_priority_setup.log")

        pytest_assert(
            wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
            "DUT did not accept the superior neighbor as root")
        pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                      "root port is not {}".format(dut_port_1))
        self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
        self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)

        # Better (lower) port priority on port_2 -> root port moves to port_2.
        # Both neighbours keep talking at hello cadence while the DUT
        # re-elects, so neither ages out mid-election.
        with self.bpdu_streams(ptfhost, duthost, [
                (self._superior_params(d, [ptf_port_2], port_priority=0x60),
                 "/tmp/pvst_port_priority_p2.log"),
                (self._superior_params(d, [ptf_port_1]),
                 "/tmp/pvst_port_priority_p1.log")]):
            pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_2),
                          "root port did not move to {}".format(dut_port_2))
            self.verify_stp_state(duthost, vlan_id, [dut_port_1], self.BLOCK_STATE)
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

    def test_pvst_path_cost_validation(self, duthosts, rand_one_dut_hostname, ptfhost,
                                       setup_stp_test_data):
        """Under a superior neighbor on port_1, the root path cost the DUT emits on
        its designated port_2 tracks the configured cost of the root port."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        default_port_cost = None
        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost, self._superior_params(d, [ptf_port_1]),
                    "/tmp/pvst_path_cost_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
                    "DUT did not accept the superior neighbor as root")
                pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                              "root port is not {}".format(dut_port_1))

                default_port_cost = self.get_port_cost(duthost, vlan_id, dut_port_1)
                self.run_bpdu(
                    ptfhost, duthost, "validate_path_cost",
                    {"vlan_id": vlan_id, "capture_port": ptf_port_2,
                     "capture_duration": self.PKT_CAPTURE_DURATION,
                     "expected_bridge_mac": d["dut_ports"]["mac"],
                     "expected_root_path_cost": default_port_cost},
                    "/tmp/pvst_path_cost_default.log")

                self.set_port_cost(duthost, vlan_id, dut_port_1, self.PORT_COST)
                pytest_assert(
                    wait_until(30, 2, 0,
                               lambda: self.get_port_cost(duthost, vlan_id, dut_port_1) == self.PORT_COST),
                    "port cost was not updated to {}".format(self.PORT_COST))

                self.run_bpdu(
                    ptfhost, duthost, "validate_path_cost",
                    {"vlan_id": vlan_id, "capture_port": ptf_port_2,
                     "capture_duration": self.PKT_CAPTURE_DURATION,
                     "expected_bridge_mac": d["dut_ports"]["mac"],
                     "expected_root_path_cost": self.PORT_COST},
                    "/tmp/pvst_path_cost_updated.log")
        finally:
            if default_port_cost is not None:
                self.set_port_cost(duthost, vlan_id, dut_port_1, default_port_cost)

    def test_pvst_root_guard_functionality(self, duthosts, rand_one_dut_hostname, ptfhost,
                                           setup_stp_test_data):
        """With root-guard enabled on both ports, a superior BPDU puts the ports
        in the root-inconsistent (ROOT-INC) state rather than yielding root."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]
        guard_ports = [dut_port_1, dut_port_2]

        try:
            for port in guard_ports:
                duthost.shell("config spanning-tree interface root_guard enable {}".format(port),
                              module_ignore_errors=True)

            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1, ptf_port_2]),
                          "/tmp/pvst_root_guard.log")

            for port in guard_ports:
                pytest_assert(
                    wait_until(30, 2, 0,
                               lambda p=port: self.get_port_state(duthost, vlan_id, p) == "ROOT-INC"),
                    "port {} did not enter ROOT-INC under root-guard".format(port))
        finally:
            for port in guard_ports:
                duthost.shell("config spanning-tree interface root_guard disable {}".format(port),
                              module_ignore_errors=True)

    def test_pvst_bpdu_guard_with_shutdown(self, duthosts, rand_one_dut_hostname, ptfhost,
                                           setup_stp_test_data):
        """A received BPDU err-disables a bpdu-guard --shutdown port; after
        disabling the guard and bouncing the port it stays up under more BPDUs."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1 = d["dut_ports"]["ptf_port_1"]

        try:
            duthost.shell("config spanning-tree interface bpdu-guard enable {} --shutdown".format(dut_port_1),
                          module_ignore_errors=True)

            vlan_id = d["vlan"]["id"]
            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/pvst_bpdu_guard_trigger.log")

            # bpdu-guard reacts to a received BPDU by taking the port out of
            # forwarding (BPDU-DIS/BLOCKING/DISCARDING) and/or err-disabling it
            # (oper-down); wait for either signal.
            tripped = wait_until(30, 2, 0, lambda: self.bpdu_guard_tripped(duthost, vlan_id, dut_port_1))
            port = stp_utils.get_port_data(duthost, self.STP_MODE, vlan_id, dut_port_1)
            state = port.get("port_state", "")
            oper = stp_utils.get_port_oper_state(duthost, dut_port_1)
            pytest_assert(
                tripped,
                "port {} should be bpdu-guard-tripped; state={!r}, oper={!r}"
                .format(dut_port_1, state, oper))

            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(dut_port_1),
                          module_ignore_errors=True)
            duthost.shell("config interface shutdown {}".format(dut_port_1), module_ignore_errors=True)
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)
            pytest_assert(
                wait_until(30, 2, 0, lambda: stp_utils.get_port_oper_state(duthost, dut_port_1).lower() == "up"),
                "port {} did not come back up after guard disable + bounce".format(dut_port_1))

            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/pvst_bpdu_guard_disabled.log")
            # With the guard disabled the port must NOT err-disable -- confirm it
            # never goes oper-down across the settle window.
            pytest_assert(
                not wait_until(6, 2, 0,
                               lambda: stp_utils.get_port_oper_state(duthost, dut_port_1).lower() == "down"),
                "port {} should stay up with guard disabled".format(dut_port_1))
        finally:
            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(dut_port_1),
                          module_ignore_errors=True)
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)

    def test_pvst_bpdu_timer_validation(self, duthosts, rand_one_dut_hostname, ptfhost,
                                        setup_stp_test_data):
        """Set custom per-VLAN timers and confirm the DUT's emitted BPDU carries
        them on both ports."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        vlan_id = d["vlan"]["id"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        try:
            self.set_timers(duthost, vlan_id,
                            hello=self.CUSTOM_HELLO_TIME,
                            max_age=self.CUSTOM_MAX_AGE,
                            fwd_delay=self.CUSTOM_FORWARD_DELAY)

            for cap in (ptf_port_1, ptf_port_2):
                self.run_bpdu(
                    ptfhost, duthost, "validate_timers",
                    {"vlan_id": vlan_id, "capture_port": cap,
                     "expected_hello_time": self.CUSTOM_HELLO_TIME,
                     "expected_max_age": self.CUSTOM_MAX_AGE,
                     "expected_forward_delay": self.CUSTOM_FORWARD_DELAY,
                     "capture_duration": self.PKT_CAPTURE_DURATION},
                    "/tmp/pvst_timer_cap{}.log".format(cap))
        finally:
            self.set_timers(duthost, vlan_id, hello=2, max_age=20, fwd_delay=15)

    def test_pvst_backup_port_functionality(self, duthosts, rand_one_dut_hostname, ptfhost,
                                            setup_stp_test_data):
        """The DUT is root; replaying the DUT's own BPDU back on port_2 makes it a
        backup port (BLOCKING); it returns to FORWARDING once the loop stops."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_2 = d["dut_ports"]["dut_port_2"]
        ptf_port_2 = d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]
        default_priority = int(self._bridge_cfg(duthost, vlan_id).get("priority", "32768"))

        try:
            # Reset the STP state machine before the self-loop exercise. The
            # disable tears the tree's rows down, so wait for the port to be
            # enrolled again before reading its state: otherwise the checks
            # below can pass on nothing at all.
            self.bounce_stp(duthost)
            pytest_assert(self.wait_enrolled(duthost, vlan_id, dut_port_2),
                          "precondition: {} did not enrol after the bounce".format(dut_port_2))
            pytest_assert(
                wait_until(60, 2, 0, lambda: self.is_self_root(duthost, vlan_id)),
                "precondition: DUT should be the root bridge")
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

            # capture_port MUST equal replay_port. `supercedes_port_info()`
            # (sonic-stp stp/stp.c) only reaches `self_loop = true` - the sole
            # path to `make_blocking()` - when the received BPDU's port id
            # compares EQUAL_TO the *receiving* port's `designated_port`. A BPDU
            # captured on port_1 and replayed on port_2 carries port_1's id and
            # can never satisfy that.
            self.run_bpdu(
                ptfhost, duthost, "validate_backup_port",
                {"vlan_id": vlan_id, "capture_port": ptf_port_2, "replay_port": ptf_port_2,
                 "capture_duration": self.PKT_CAPTURE_DURATION, "replay_delay": 1,
                 # Replay one captured BPDU 20x at 0.4s - an 8s self-loop, long
                 # enough for the BLOCKING transition to be observed.
                 "replay_count": 20, "replay_interval": 0.4},
                "/tmp/pvst_backup_port.log")

            self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)
            # Once the DUT stops receiving its own BPDU, the port returns to forwarding.
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")
        finally:
            self.set_bridge_priority(duthost, vlan_id, default_priority)

    def test_pvst_mac_flush(self, duthosts, rand_one_dut_hostname, ptfhost,
                            setup_stp_test_data):
        """Learn a MAC via L2 traffic, then a topology-change (TCN) BPDU received
        on the other port flushes it from the DUT's FDB."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        pytest_assert(self.is_self_root(duthost, vlan_id),
                      "precondition: DUT should be the root bridge")
        self.verify_stp_state(duthost, vlan_id, [dut_port_1, dut_port_2], "FORWARDING")

        # Ports reaching FORWARDING during setup are a topology change of the
        # root's own, and that window stays open for max age plus forward
        # delay. The daemon publishes the fast-ageing row once, when the
        # window opens, and orchagent flushes once on it; a MAC learned inside
        # an open window therefore survives a TCN, which only keeps the window
        # open. Start from a closed one.
        def _window_open():
            key = "STP_FASTAGEING_FLUSH_TABLE:Vlan{}".format(vlan_id)
            out = duthost.shell("redis-cli -n 0 exists {0} _{0}".format(key)).get("stdout", "0")
            return out.strip() != "0"

        pytest_assert(wait_until(90, 3, 0, lambda: not _window_open()),
                      "a topology change window was still open on Vlan{} after 90 s".format(vlan_id))

        def _mac_count():
            # Only the probe's own source address: the PTF also learns its
            # management chatter on the port, and that comes back after a
            # flush and would hide it.
            lines = duthost.shell("show mac").get("stdout_lines", [])
            return sum(1 for ln in lines if dut_port_1 in ln and DUMMY_MAC_PREFIX in ln.lower())

        before = _mac_count()
        self.run_bpdu(
            ptfhost, duthost, "validate_l2_packet",
            {"send_port": ptf_port_1, "receive_port": ptf_port_2,
             "vlan_id": vlan_id, "verify_packet": True},
            "/tmp/pvst_mac_flush_l2.log")

        after = _mac_count()
        pytest_assert(after > before,
                      "MACs not learned on {} (before {}, after {})".format(dut_port_1, before, after))

        # The TCN goes in on port_2 and the flush is observed on port_1: the
        # port a topology change arrives on keeps its entries.
        self.run_bpdu(ptfhost, duthost, "tcn",
                      {"vlan_id": vlan_id, "send_port": [ptf_port_2]},
                      "/tmp/pvst_mac_flush_tcn.log")

        # A real flush removes the learned entries; `<=` passes when the flush
        # does nothing. PVST ages the VLAN's entries out over a forward delay
        # rather than dropping them at once, so allow for that.
        pytest_assert(
            wait_until(60, 2, 0, lambda: _mac_count() < after),
            "MACs not flushed on {} (before flush {}, still {})".format(
                dut_port_1, after, _mac_count()))

    # ------------------------------------------------ portfast / uplink fast
    def _bounce_link(self, duthost, vlan_id, port):
        """Shut the port, wait for the daemon to see it down, bring it back and
        return the moment it came back, for timing the transition."""
        duthost.shell("config interface shutdown {}".format(port))
        pytest_assert(
            wait_until(30, 1, 0, lambda: self.get_port_state(duthost, vlan_id, port) == "DISABLED"),
            "{} did not read DISABLED after shutdown".format(port))
        duthost.shell("config interface startup {}".format(port))
        return time.time()

    def _seconds_to_state(self, duthost, vlan_id, port, state, timeout, since):
        """Seconds from `since` until `port` reads `state`, or None."""
        if wait_until(timeout, 1, 0, lambda: self.get_port_state(duthost, vlan_id, port) == state):
            return time.time() - since
        return None

    def _restore_port_flag(self, duthost, port, feature, value):
        duthost.shell("config spanning-tree interface {} {} {}".format(
            feature, "enable" if value == "true" else "disable", port), module_ignore_errors=True)

    def test_pvst_portfast(self, duthosts, rand_one_dut_hostname, ptfhost, setup_stp_test_data):
        """A portfast port skips the two forward delays when its link comes up,
        a BPDU arriving on it turns portfast off, and the same bounce with
        portfast disabled takes the full two forward delays."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_2, ptf_port_2 = d["dut_ports"]["dut_port_2"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]
        before = _config_port_field(duthost, dut_port_2, "portfast")

        pytest_assert(self.is_self_root(duthost, vlan_id), "precondition: DUT should be the root bridge")
        try:
            duthost.shell("config spanning-tree interface portfast enable {}".format(dut_port_2))
            pytest_assert(wait_until(30, 2, 0, lambda: _port_fast_flag(duthost, dut_port_2) == "yes"),
                          "the daemon did not report portfast on {}".format(dut_port_2))

            since = self._bounce_link(duthost, vlan_id, dut_port_2)
            took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                          FAST_TRANSITION_LIMIT, since)
            pytest_assert(took is not None,
                          "portfast port {} was not FORWARDING {} s after link up (state {})".format(
                              dut_port_2, FAST_TRANSITION_LIMIT,
                              self.get_port_state(duthost, vlan_id, dut_port_2)))
            logger.info("portfast: %s reached FORWARDING %.1f s after link up", dut_port_2, took)

            # A BPDU on a portfast port means a bridge is there, so portfast
            # comes off. A TCN leaves the DUT root, so nothing else moves.
            self.run_bpdu(ptfhost, duthost, "tcn", {"vlan_id": vlan_id, "send_port": [ptf_port_2]},
                          "/tmp/pvst_portfast_tcn.log")
            pytest_assert(wait_until(30, 2, 0, lambda: _port_fast_flag(duthost, dut_port_2) == "no"),
                          "portfast stayed on {} after it received a BPDU".format(dut_port_2))

            # Configured portfast is re-armed by a link down.
            duthost.shell("config interface shutdown {}".format(dut_port_2))
            pytest_assert(wait_until(30, 2, 0, lambda: _port_fast_flag(duthost, dut_port_2) == "yes"),
                          "portfast was not re-armed on {} when its link went down".format(dut_port_2))
            duthost.shell("config interface startup {}".format(dut_port_2))
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")

            # Without portfast the same bounce walks LISTENING and LEARNING at
            # the configured forward delay.
            duthost.shell("config spanning-tree interface portfast disable {}".format(dut_port_2))
            pytest_assert(wait_until(30, 2, 0, lambda: _port_fast_flag(duthost, dut_port_2) == "no"),
                          "the daemon still reports portfast on {} after it was disabled".format(dut_port_2))
            since = self._bounce_link(duthost, vlan_id, dut_port_2)
            took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                          FAST_TRANSITION_LIMIT, since)
            pytest_assert(took is None,
                          "{} reached FORWARDING in {} s with portfast disabled; the forward "
                          "delay was not applied".format(dut_port_2, took))
            took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                          SLOW_TRANSITION_LIMIT, since)
            pytest_assert(took is not None,
                          "{} never reached FORWARDING after link up (state {})".format(
                              dut_port_2, self.get_port_state(duthost, vlan_id, dut_port_2)))
            logger.info("no portfast: %s reached FORWARDING %.1f s after link up", dut_port_2, took)
        finally:
            duthost.shell("config interface startup {}".format(dut_port_2), module_ignore_errors=True)
            self._restore_port_flag(duthost, dut_port_2, "portfast", before)
            # Logged, not asserted: a failure here would replace the test's own.
            if not wait_until(120, 5, 0, lambda: self.get_port_state(duthost, vlan_id, dut_port_2) == "FORWARDING"):
                logger.warning("%s did not return to FORWARDING after the portfast test (state %s)",
                               dut_port_2, self.get_port_state(duthost, vlan_id, dut_port_2))

    def test_pvst_uplink_fast(self, duthosts, rand_one_dut_hostname, ptfhost, setup_stp_test_data):
        """With uplink fast on both uplinks, losing the root port moves the
        tree onto the blocked uplink within a second or two instead of two
        forward delays. The same failover without uplink fast takes the slow
        path, so the fast result is the feature and not the daemon's default."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]
        ports = (dut_port_1, dut_port_2)
        before = {p: {f: _config_port_field(duthost, p, f) for f in ("portfast", "uplink_fast")}
                  for p in ports}
        streams = [(self._superior_params(d, [ptf_port_1]), "/tmp/pvst_uplink_fast_p1.log"),
                   (self._superior_params(d, [ptf_port_2]), "/tmp/pvst_uplink_fast_p2.log")]

        def _converge_on_port_1():
            pytest_assert(wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, vlan_id)),
                          "DUT did not accept the superior neighbor as root")
            pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_1),
                          "root port is not {}".format(dut_port_1))
            self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)

        try:
            # Portfast would also shorten the transition, and it is re-armed by
            # a link down, so it is switched off for both uplinks first.
            for p in ports:
                duthost.shell("config spanning-tree interface portfast disable {}".format(p))
                duthost.shell("config spanning-tree interface uplink_fast enable {}".format(p))
            for p in ports:
                pytest_assert(wait_until(30, 2, 0, lambda p=p: _config_port_field(
                    duthost, p, "uplink_fast") == "true"), "uplink_fast did not apply on {}".format(p))

            with self.bpdu_streams(ptfhost, duthost, streams):
                _converge_on_port_1()
                duthost.shell("config interface shutdown {}".format(dut_port_1))
                since = time.time()
                took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                              FAST_TRANSITION_LIMIT, since)
                pytest_assert(took is not None,
                              "uplink fast: {} was not FORWARDING {} s after the root port went "
                              "down (state {})".format(dut_port_2, FAST_TRANSITION_LIMIT,
                                                       self.get_port_state(duthost, vlan_id, dut_port_2)))
                pytest_assert(self.wait_root_port(duthost, vlan_id, dut_port_2),
                              "root port did not move to {}".format(dut_port_2))
                logger.info("uplink fast: %s took over %.1f s after %s went down", dut_port_2, took, dut_port_1)
                duthost.shell("config interface startup {}".format(dut_port_1))

            # Control: the same failover with uplink fast off walks LISTENING
            # and LEARNING at the configured forward delay.
            for p in ports:
                duthost.shell("config spanning-tree interface uplink_fast disable {}".format(p))
            with self.bpdu_streams(ptfhost, duthost, streams):
                _converge_on_port_1()
                duthost.shell("config interface shutdown {}".format(dut_port_1))
                since = time.time()
                took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                              FAST_TRANSITION_LIMIT, since)
                pytest_assert(took is None,
                              "{} reached FORWARDING in {} s with uplink fast disabled; the forward "
                              "delay was not applied".format(dut_port_2, took))
                took = self._seconds_to_state(duthost, vlan_id, dut_port_2, "FORWARDING",
                                              SLOW_TRANSITION_LIMIT, since)
                pytest_assert(took is not None,
                              "{} never took over after {} went down (state {})".format(
                                  dut_port_2, dut_port_1, self.get_port_state(duthost, vlan_id, dut_port_2)))
                logger.info("no uplink fast: %s took over %.1f s after %s went down",
                            dut_port_2, took, dut_port_1)
        finally:
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)
            for p in ports:
                self._restore_port_flag(duthost, p, "uplink_fast", before[p]["uplink_fast"])
                self._restore_port_flag(duthost, p, "portfast", before[p]["portfast"])

    # ------------------------------------------------------------ statistics
    def test_pvst_statistics_and_clear(self, duthosts, rand_one_dut_hostname, ptfhost,
                                       setup_stp_test_data):
        """The per-port counters count the DUT's own BPDUs and the TCNs it
        receives, the show command reports the same numbers, and the clear
        command resets them."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, ptf_port_1 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["ptf_port_1"]
        vlan_id = d["vlan"]["id"]
        tcn_count = 3

        def _cli_stats(port):
            # The image registers the group as spanning-tree only; the
            # documented spanning_tree spelling is not a show command.
            out = duthost.shell("show spanning-tree statistics vlan {}".format(vlan_id),
                                module_ignore_errors=True).get("stdout_lines", [])
            for line in out:
                cols = line.split()
                if cols and cols[0] == port:
                    vals = [0 if c == "-" else int(c) for c in cols[1:5]]
                    return dict(zip(("bpdu_sent", "bpdu_received", "tc_sent", "tc_received"), vals))
            return None

        pytest_assert(self.is_self_root(duthost, vlan_id), "precondition: DUT should be the root bridge")
        self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")

        # The root sends a BPDU every hello on every designated port.
        sent = _port_stats(duthost, vlan_id, dut_port_1)["bpdu_sent"]
        pytest_assert(
            wait_until(15, 1, 0, lambda: _port_stats(duthost, vlan_id, dut_port_1)["bpdu_sent"] >= sent + 2),
            "bpdu_sent on {} did not advance in 15 s (still {})".format(
                dut_port_1, _port_stats(duthost, vlan_id, dut_port_1)["bpdu_sent"]))

        received = _port_stats(duthost, vlan_id, dut_port_1)["tc_received"]
        for _ in range(tcn_count):
            self.run_bpdu(ptfhost, duthost, "tcn", {"vlan_id": vlan_id, "send_port": [ptf_port_1]},
                          "/tmp/pvst_statistics_tcn.log")
        pytest_assert(
            wait_until(15, 1, 0, lambda: _port_stats(
                duthost, vlan_id, dut_port_1)["tc_received"] >= received + tcn_count),
            "tc_received on {} did not count the {} TCNs (was {}, now {})".format(
                dut_port_1, tcn_count, received, _port_stats(duthost, vlan_id, dut_port_1)["tc_received"]))

        shown = _cli_stats(dut_port_1)
        pytest_assert(shown is not None,
                      "show spanning-tree statistics vlan {} has no row for {}".format(vlan_id, dut_port_1))
        # Two reads a moment apart, so the transmit counter may have moved by a hello.
        held = _port_stats(duthost, vlan_id, dut_port_1)
        pytest_assert(abs(shown["bpdu_sent"] - held["bpdu_sent"]) <= 2
                      and all(shown[f] == held[f] for f in ("bpdu_received", "tc_sent", "tc_received")),
                      "show reports {} but APPL_DB holds {}".format(shown, held))

        before_clear = _port_stats(duthost, vlan_id, dut_port_1)
        duthost.shell("sonic-clear spanning-tree statistics")
        pytest_assert(
            wait_until(15, 1, 0, lambda: _port_stats(duthost, vlan_id, dut_port_1)["tc_received"] == 0
                       and _port_stats(duthost, vlan_id, dut_port_1)["bpdu_sent"] < before_clear["bpdu_sent"]),
            "counters on {} were not cleared: {} -> {}".format(
                dut_port_1, before_clear, _port_stats(duthost, vlan_id, dut_port_1)))
        res = duthost.shell("sonic-clear spanning-tree statistics vlan {}".format(vlan_id),
                            module_ignore_errors=True)
        pytest_assert(res.get("rc", 1) == 0,
                      "sonic-clear spanning-tree statistics vlan {} failed: {}".format(
                          vlan_id, (res.get("stderr") or res.get("stdout") or "").strip()))

    # ------------------------------------------------------------- BPDU flood
    FLOOD_COUNT = 3000

    def test_pvst_bpdu_flood_is_survived(self, duthosts, rand_one_dut_hostname, ptfhost,
                                         setup_stp_test_data):
        """A burst of superior BPDUs as fast as the PTF can send them must not
        take the daemon down or leave the tree stuck: stpd keeps its pid, the
        container stays up, every frame that reached the daemon is counted, and
        once the burst stops the DUT is root again within a max age."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, ptf_port_1 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["ptf_port_1"]
        vlan_id = d["vlan"]["id"]

        def _stpd_pid():
            return duthost.shell("docker exec stp pidof stpd", module_ignore_errors=True).get("stdout", "").strip()

        pid_before = _stpd_pid()
        pytest_assert(pid_before, "stpd is not running before the flood")
        received_before = _port_stats(duthost, vlan_id, dut_port_1)["bpdu_received"]

        self.run_bpdu(ptfhost, duthost, "config",
                      self._superior_params(d, [ptf_port_1], send_count=self.FLOOD_COUNT, send_interval=0),
                      "/tmp/pvst_bpdu_flood.log")

        pytest_assert(self.stp_container_up(duthost), "the stp container went down during the flood")
        pytest_assert(_stpd_pid() == pid_before,
                      "stpd restarted during the flood (pid {} -> {})".format(pid_before, _stpd_pid()))
        # The daemon publishes its counters on a timer, so give the count a
        # moment to reach APPL_DB. CoPP rate limits BPDUs to the CPU, so only a
        # fraction of a line-rate burst is expected to arrive.

        def _received():
            return _port_stats(duthost, vlan_id, dut_port_1)["bpdu_received"] - received_before
        wait_until(15, 1, 0, lambda: _received() > 0)
        received = _received()
        logger.info("BPDU flood: %d sent on %s, %d counted by the daemon",
                    self.FLOOD_COUNT, dut_port_1, received)
        pytest_assert(0 < received <= self.FLOOD_COUNT,
                      "the daemon counted {} BPDUs for a burst of {}".format(received, self.FLOOD_COUNT))

        # The burst carried a superior root; once it stops the DUT takes root
        # back within a max age and the daemon still answers.
        pytest_assert(self.wait_self_root(duthost, vlan_id, timeout=60),
                      "DUT did not return to root within 60 s after the flood stopped")
        self.verify_stp_state(duthost, vlan_id, [dut_port_1], "FORWARDING")
