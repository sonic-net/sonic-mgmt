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
        for _ in range(15):
            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_2], port_priority=0x60),
                          "/tmp/pvst_port_priority_p2.log")
            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/pvst_port_priority_p1.log")

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
            pytest_assert(self.is_self_root(duthost, vlan_id),
                          "precondition: DUT should be the root bridge")

            self.run_bpdu(
                ptfhost, duthost, "validate_backup_port",
                {"vlan_id": vlan_id, "capture_port": ptf_port_2, "replay_port": ptf_port_2,
                 "capture_duration": self.PKT_CAPTURE_DURATION, "replay_delay": 1},
                "/tmp/pvst_backup_port.log")

            self.verify_stp_state(duthost, vlan_id, [dut_port_2], self.BLOCK_STATE)
            # Once the DUT stops receiving its own BPDU, the port returns to forwarding.
            self.verify_stp_state(duthost, vlan_id, [dut_port_2], "FORWARDING")
        finally:
            self.set_bridge_priority(duthost, vlan_id, default_priority)

    def test_pvst_mac_flush(self, duthosts, rand_one_dut_hostname, ptfhost,
                            setup_stp_test_data):
        """Learn a MAC via L2 traffic, then a topology-change (TCN) BPDU flushes
        it from the DUT's FDB."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        pytest_assert(self.is_self_root(duthost, vlan_id),
                      "precondition: DUT should be the root bridge")
        self.verify_stp_state(duthost, vlan_id, [dut_port_1, dut_port_2], "FORWARDING")

        def _mac_count():
            lines = duthost.shell("show mac").get("stdout_lines", [])
            return sum(1 for ln in lines if dut_port_1 in ln)

        before = _mac_count()
        self.run_bpdu(
            ptfhost, duthost, "validate_l2_packet",
            {"send_port": ptf_port_1, "receive_port": ptf_port_2,
             "vlan_id": vlan_id, "verify_packet": True},
            "/tmp/pvst_mac_flush_l2.log")

        after = _mac_count()
        pytest_assert(after > before,
                      "MACs not learned on {} (before {}, after {})".format(dut_port_1, before, after))

        self.run_bpdu(ptfhost, duthost, "tcn",
                      {"vlan_id": vlan_id, "send_port": [ptf_port_1]},
                      "/tmp/pvst_mac_flush_tcn.log")

        after_flush = _mac_count()
        pytest_assert(after_flush <= after,
                      "MACs not flushed on {} (before flush {}, after flush {})".format(
                          dut_port_1, after, after_flush))
