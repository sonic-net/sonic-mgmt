# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP (IEEE 802.1s) sonic-mgmt tests.

`TestMstp` subclasses `StpTestBase` (STP_MODE="mst"), reusing the shared,
mode-parameterized config/verify/PTF helpers. The MST region is enabled and the
VLAN-under-test mapped to instance 1 by the autouse `enable_stp_and_verify`
fixture (see conftest.py); the PTF is driven with the *same* region params so its
BPDU config-digest matches the DUT's and it is treated as in-region.

Scope convention (mirrors the DB tables):
  * CIST checks use instance 0 (superior-BPDU-driven port-role tests act on the
    CIST, since we inject a superior CIST BPDU with no MSTI records);
  * the mapped-VLAN instance checks use `setup_stp_test_data["mst"]["instance"]`.

This mirrors the PVST suite (`tests/pvst/test_pvst.py`) for every case the MST
daemon can expose identically. Three PVST cases are intentionally *not* mirrored
because sonic-stp does not surface the equivalent MST state:
  * designated-bridge blocking-MAC learning (VS blocking-state limitation),
  * per-port root-guard ROOT-INC (MST writes root-guard state PVST-only),
  * backup-port (same blocking-state dependency).

Every assertion here is validated only on a testbed run (no scapy/PTF locally).
"""
import json
import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.stp import stp_base
from tests.stp import stp_utils
from tests.stp.stp_base import StpTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs'),
    # LogAnalyzer is disabled on this image: its end marker never lands in
    # /var/log/syslog (imrelp pipeline + config-reload rsyslog restart), so
    # every test ERRORs at teardown. Tracked separately; re-enable with the
    # staged ignore_regex once that infra bug is fixed.
    pytest.mark.disable_loganalyzer,
]

CIST = 0
# This build ignores MST bridge-priority config and advertises a CIST priority
# of 0 (the best possible). Priority 0 can't be beaten on priority, so an
# injected "superior" root must match priority 0 and win on the MAC tiebreak —
# hence a very low MAC. (A normal switch MAC is far above 00:00:00:00:00:01.)
FOREIGN_BRIDGE_MAC = "00:00:00:00:00:01"
SUPERIOR_PRIORITY = 0
# A neighbour the DUT can actually outrank. Bridge IDs compare as priority then
# MAC, and FOREIGN_BRIDGE_MAC is lower than any real system MAC, so a neighbour
# at priority 0 wins even when the DUT is also at 0.
BEATABLE_PRIORITY = 8192
# RSTP/MST flags for an injected designated-forwarding bridge: Proposal (0x02) +
# port-role Designated (0x0C) + Learning (0x10) + Forwarding (0x20) + Agreement
# (0x40). A BPDU with role "Unknown" (flags 0x00) is discarded by the daemon, so
# injected superior BPDUs must carry a valid designated role to be acted on.
CIST_FLAGS_DESIGNATED = 0x7E
# A designated port that is neither learning nor forwarding: what a bridge
# sends while it still loses the election, and nothing a designated port
# disputes.
CIST_FLAGS_QUIET_DESIGNATED = 0x0C
# A neighbour that loses to everything: the worst priority and a high MAC.
INFERIOR_PRIORITY = 0xF000
INFERIOR_BRIDGE_MAC = "02:ff:ff:ff:ff:ff"
# Source prefix of the PTF's L2 probe frames (StpBpduBase.L2_SRC_PREFIX).
PROBE_MAC_PREFIX = "00:11:22:33:55"


class TestMstp(StpTestBase):

    STP_MODE = "mst"

    # MST uses RSTP port states; the "not forwarding" state is DISCARDING
    # (PVST reports this as BLOCKING).
    BLOCK_STATE = "DISCARDING"
    # To win the CIST root back from an injected SUPERIOR_PRIORITY (4096) sender
    # the DUT must advertise a strictly better priority.
    DUT_SUPERIOR_PRIORITY = 0

    # ---------------------------------------------------------------- helpers
    def _region_params(self, data):
        """Region kwargs the PTF needs to be in-region (name/revision/digest)."""
        mst = data["mst"]
        return {
            "region_name": mst["region_name"],
            "revision": mst["revision"],
            "vid_to_mstid": json.dumps(mst["vid_to_mstid"]),
        }

    def _superior_params(self, data, send_ptf_ports, **overrides):
        """In-region superior CIST BPDU params (a foreign bridge that outranks
        the DUT), for the periodic sender / one-shot injects."""
        params = dict(self._region_params(data),
                      send_port=list(send_ptf_ports),
                      cist_flags=CIST_FLAGS_DESIGNATED,
                      cist_root_priority=SUPERIOR_PRIORITY, cist_root_mac=FOREIGN_BRIDGE_MAC,
                      cist_bridge_priority=SUPERIOR_PRIORITY, cist_bridge_mac=FOREIGN_BRIDGE_MAC)
        params.update(overrides)
        return params

    @pytest.fixture(autouse=True)
    def mstp_quiesced(self, duthosts, rand_one_dut_hostname, setup_stp_test_data):
        """Start every test from the same converged baseline: the lone DUT is
        its own CIST root. BPDUs injected by the previous test influence the
        daemon until they age out, so without this gate leftovers leak into the
        next test as order-dependent failures."""
        duthost = duthosts[rand_one_dut_hostname]
        if not wait_until(60, 3, 0, lambda: self.is_self_root(duthost, CIST)):
            self._bounce_and_restore_region(duthost, setup_stp_test_data)
            pytest_assert(
                wait_until(60, 3, 0, lambda: self.is_self_root(duthost, CIST)),
                "DUT did not return to CIST root before the test started")
        yield

    def _bounce_and_restore_region(self, duthost, data):
        """`config spanning-tree disable mst` deletes the STP_MST tables, region
        name and revision included, so a bare bounce silently drops the DUT into
        the MAC-derived default region and every region-dependent test after it
        fails. Any bounce must therefore re-apply the region."""
        self.bounce_stp(duthost)
        mst = data["mst"]
        self.setup_region(duthost, mst["region_name"], mst["revision"],
                          mst["instance_vlan_map"])

    # =========================== MST-specific tests =========================
    def test_mstp_validate_root_bridge(self, duthosts, rand_one_dut_hostname, ptfhost,
                                       setup_stp_test_data):
        """A lone DUT is the CIST regional root; its ports forward; and the BPDU
        it emits carries our region name/revision and the matching digest."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]

        self._bounce_and_restore_region(duthost, d)

        pytest_assert(wait_until(60, 2, 0, lambda: self.is_self_root(duthost, CIST)),
                      "DUT is not the CIST root")
        self.verify_stp_state(duthost, CIST, [dut_port_1, dut_port_2], "FORWARDING")

        # NOTE: this build ignores `config spanning-tree mst region-name`/`revision`
        # (it advertises the default MAC-derived region name), so we don't assert
        # those. We still verify the DUT emits a well-formed CIST BPDU with the
        # empty-region config digest (matching vid_to_mstid={}) and the standard
        # max_age — the parts the daemon does drive.
        self.run_bpdu(
            ptfhost, duthost, "validate_bpdu_packet",
            dict(self._region_params(d),
                 expected_max_age=20,
                 capture_port=d["dut_ports"]["ptf_port_1"],
                 capture_duration=self.PKT_CAPTURE_DURATION),
            "/tmp/mstp_root_bridge.log")

    def test_mstp_region_and_instance(self, duthosts, rand_one_dut_hostname, ptfhost,
                                      setup_stp_test_data):
        """The configured region + instance-1 VLAN mapping is reflected in the
        DUT's operational state and its emitted BPDU."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        inst = d["mst"]["instance"]
        vlan_id = d["vlan"]["id"]

        # An MSTI is created by setting its priority. A build without that CLI
        # refuses with "does not exist", which is the real capability gate.
        create = duthost.shell(
            "config spanning-tree mst instance {} priority 32768".format(inst),
            module_ignore_errors=True)
        if create["rc"] != 0:
            pytest.skip("this build cannot create MST instance {}: {}".format(
                inst, (create.get("stderr") or "").strip().splitlines()[-1]))

        try:
            duthost.shell(
                "config spanning-tree mst instance {} vlan add {}".format(inst, vlan_id))

            pytest_assert(
                wait_until(30, 2, 0,
                           lambda: inst in stp_utils.get_mst_instances(duthost)),
                "MST instance {} not present (have {})".format(
                    inst, stp_utils.get_mst_instances(duthost)))
            vlans = stp_utils.get_instance_vlans(duthost, inst)
            pytest_assert(vlan_id in vlans,
                          "VLAN {} not mapped to instance {} (mapped: {})".format(
                              vlan_id, inst, vlans))

            # BPDU carries the region identity; the digest now reflects the
            # VLAN-to-instance mapping, so the PTF must expect the same map.
            self.run_bpdu(
                ptfhost, duthost, "validate_bpdu_packet",
                dict(self._region_params(d),
                     vid_to_mstid=json.dumps({vlan_id: inst}),
                     expected_region_name=d["mst"]["region_name"],
                     expected_revision=d["mst"]["revision"],
                     capture_port=d["dut_ports"]["ptf_port_1"],
                     capture_duration=self.PKT_CAPTURE_DURATION),
                "/tmp/mstp_region_instance.log")
        finally:
            # Unmap, then delete the instance.
            duthost.shell(
                "config spanning-tree mst instance {} vlan del {}".format(inst, vlan_id),
                module_ignore_errors=True)
            stp_base.delete_mst_instance(duthost, inst)

    def test_mstp_boundary_on_region_mismatch(self, duthosts, rand_one_dut_hostname, ptfhost,
                                              setup_stp_test_data):
        """A BPDU from a *different* region (mismatched digest) makes the DUT mark
        the receiving port an MST region boundary."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        vlan_id = d["vlan"]["id"]

        self.run_bpdu(
            ptfhost, duthost, "send_cist",
            {"send_port": [d["dut_ports"]["ptf_port_1"]],
             "region_name": "other-region", "revision": 99,
             "vid_to_mstid": json.dumps({vlan_id: 5}),   # differs -> different digest
             "cist_flags": CIST_FLAGS_DESIGNATED,
             "cist_root_priority": SUPERIOR_PRIORITY, "cist_root_mac": FOREIGN_BRIDGE_MAC,
             "cist_bridge_priority": SUPERIOR_PRIORITY, "cist_bridge_mac": FOREIGN_BRIDGE_MAC},
            "/tmp/mstp_boundary_send.log")

        pytest_assert(
            wait_until(30, 2, 0, lambda: stp_utils.get_mst_boundary(duthost, dut_port_1) == "yes"),
            "port {} not marked MST boundary after a foreign-region BPDU".format(dut_port_1))

    def test_mstp_superior_root_takes_over(self, duthosts, rand_one_dut_hostname, ptfhost,
                                           setup_stp_test_data):
        """An in-region superior CIST BPDU makes the DUT yield the CIST root."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data

        pytest_assert(self.is_self_root(duthost, CIST), "precondition: DUT should start as CIST root")

        self.run_bpdu(
            ptfhost, duthost, "send_cist",
            self._superior_params(d, [d["dut_ports"]["ptf_port_1"]]),
            "/tmp/mstp_superior_root.log")

        pytest_assert(
            wait_until(15, 2, 0, lambda: not self.is_self_root(duthost, CIST)),
            "DUT did not yield CIST root to a superior in-region BPDU")

    # ===================== PVST-parity tests (CIST scope) ===================
    def test_mstp_shutdown_root_port(self, duthosts, rand_one_dut_hostname, ptfhost,
                                     setup_stp_test_data):
        """Mirror of test_shutdown_root_port_on_sonic_and_verify: under a superior
        CIST neighbor the DUT roots on port_1 (port_2 discarding); shutting port_1
        moves the root to port_2; startup restores port_1."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost,
                    self._superior_params(d, [ptf_port_1, ptf_port_2]),
                    "/tmp/mstp_shutdown_root_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, CIST)),
                    "DUT did not accept the superior CIST neighbor as root")
                pytest_assert(self.wait_root_port(duthost, CIST, dut_port_1),
                              "root port is not {}".format(dut_port_1))
                self.verify_stp_state(duthost, CIST, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, CIST, [dut_port_2], self.BLOCK_STATE)

                duthost.shell("config interface shutdown {}".format(dut_port_1))
                self.verify_stp_state(duthost, CIST, [dut_port_2], "FORWARDING")
                pytest_assert(self.wait_root_port(duthost, CIST, dut_port_2),
                              "root port did not move to {}".format(dut_port_2))

                duthost.shell("config interface startup {}".format(dut_port_1))
                self.verify_stp_state(duthost, CIST, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, CIST, [dut_port_2], self.BLOCK_STATE)
                pytest_assert(self.wait_root_port(duthost, CIST, dut_port_1),
                              "root port did not return to {}".format(dut_port_1))
        finally:
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)

    def test_mstp_bridge_priority_change_in_bpdu(self, duthosts, rand_one_dut_hostname, ptfhost,
                                                 setup_stp_test_data):
        """Mirror of test_bridge_priority_change_in_bpdu: a superior neighbor is
        root until the DUT's CIST priority is lowered past it; then the DUT is
        root, all ports forward, and its emitted BPDU carries the new priority."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost,
                    self._superior_params(d, [ptf_port_1, ptf_port_2],
                                          cist_root_priority=BEATABLE_PRIORITY,
                                          cist_bridge_priority=BEATABLE_PRIORITY),
                    "/tmp/mstp_bridge_priority_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, CIST)),
                    "DUT did not accept the superior CIST neighbor as root")
                self.verify_stp_state(duthost, CIST, [dut_port_1], "FORWARDING")
                self.verify_stp_state(duthost, CIST, [dut_port_2], self.BLOCK_STATE)

                # Lower the DUT CIST priority below the neighbor's -> DUT becomes root.
                self.set_bridge_priority(duthost, CIST, self.DUT_SUPERIOR_PRIORITY)
                pytest_assert(
                    wait_until(60, 2, 0, lambda: self.is_self_root(duthost, CIST)),
                    "DUT did not become CIST root after lowering its priority")

            # FORWARDING is asserted only after the sender stops: while it keeps
            # injecting inferior designated BPDUs with learn/forward set, the
            # dispute mechanism correctly holds the receiving port DISCARDING.
            self.verify_stp_state(duthost, CIST, [dut_port_1, dut_port_2], "FORWARDING")

            # BPDU the DUT now emits carries its (new) CIST bridge priority. Only
            # the priority is checked: the CIST bridge MAC is the DUT *system* MAC,
            # which isn't in setup data.
            self.run_bpdu(
                ptfhost, duthost, "validate_root_bridge_id",
                dict(self._region_params(d),
                     expected_bridge_priority=self.DUT_SUPERIOR_PRIORITY,
                     capture_port=ptf_port_1,
                     capture_duration=self.PKT_CAPTURE_DURATION),
                "/tmp/mstp_bridge_priority_validate.log")
        finally:
            self.set_bridge_priority(duthost, CIST, 32768)

    def test_mstp_port_priority_change_in_bpdu(self, duthosts, rand_one_dut_hostname, ptfhost,
                                               setup_stp_test_data):
        """Mirror of test_port_priority_change_in_bpdu: with equal path cost the
        DUT roots on port_1 (lower neighbor port id); sending a *better* CIST port
        priority on port_2 moves the root port there and blocks port_1."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        # Establish the superior neighbour on both ports; port_1 becomes root
        # port. The neighbour keeps talking while the checks run: the daemon
        # drops a neighbour it has not heard from for three hellos, and because
        # the injected BPDU carries the Agreement flag the alternate port goes
        # straight back to FORWARDING when that happens, with no forward delay.
        # A one-shot send therefore leaves about five seconds to observe port_2
        # DISCARDING, less than the polls before it can take.
        with self.bpdu_streams(ptfhost, duthost, [
                (self._superior_params(d, [ptf_port_1, ptf_port_2]),
                 "/tmp/mstp_port_priority_setup.log")]):
            pytest_assert(
                wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, CIST)),
                "DUT did not accept the superior CIST neighbor as root")
            pytest_assert(self.wait_root_port(duthost, CIST, dut_port_1),
                          "root port is not {}".format(dut_port_1))
            self.verify_stp_state(duthost, CIST, [dut_port_1], "FORWARDING")
            self.verify_stp_state(duthost, CIST, [dut_port_2], self.BLOCK_STATE)

        # Better (lower) CIST port priority on port_2 -> root port moves to
        # port_2. Both neighbours keep talking at hello cadence while the DUT
        # re-elects; the DUT drops a neighbour it has not heard from for three
        # hellos, so the two streams must run at the same time.
        with self.bpdu_streams(ptfhost, duthost, [
                (self._superior_params(d, [ptf_port_2], port_priority=0x60),
                 "/tmp/mstp_port_priority_p2.log"),
                (self._superior_params(d, [ptf_port_1]),
                 "/tmp/mstp_port_priority_p1.log")]):
            pytest_assert(self.wait_root_port(duthost, CIST, dut_port_2),
                          "root port did not move to {}".format(dut_port_2))
            self.verify_stp_state(duthost, CIST, [dut_port_1], self.BLOCK_STATE)
            self.verify_stp_state(duthost, CIST, [dut_port_2], "FORWARDING")

    def test_mstp_path_cost_validation(self, duthosts, rand_one_dut_hostname, ptfhost,
                                       setup_stp_test_data):
        """Mirror of test_pvst_path_cost_validation: raise the CIST cost of the
        root port and verify the CIST internal root path cost the DUT advertises
        on its designated port tracks the change."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        default_port_cost = None
        try:
            with self.periodic_superior_sender(
                    ptfhost, duthost,
                    self._superior_params(d, [ptf_port_1]),
                    "/tmp/mstp_path_cost_periodic.log"):

                pytest_assert(
                    wait_until(60, 2, 0, lambda: not self.is_self_root(duthost, CIST)),
                    "DUT did not accept the superior CIST neighbor as root")
                pytest_assert(self.wait_root_port(duthost, CIST, dut_port_1),
                              "root port is not {}".format(dut_port_1))

                default_port_cost = self.get_port_cost(duthost, CIST, dut_port_1)
                self.run_bpdu(
                    ptfhost, duthost, "validate_path_cost",
                    {"capture_port": ptf_port_2, "capture_duration": self.PKT_CAPTURE_DURATION,
                     "expected_root_path_cost": default_port_cost,
                     "expected_bridge_mac": d["dut_ports"]["mac"]},
                    "/tmp/mstp_path_cost_default.log")

                self.set_port_cost(duthost, CIST, dut_port_1, self.PORT_COST)
                pytest_assert(
                    wait_until(30, 2, 0,
                               lambda: self.get_port_cost(duthost, CIST, dut_port_1) == self.PORT_COST),
                    "CIST port cost was not updated to {}".format(self.PORT_COST))

                self.run_bpdu(
                    ptfhost, duthost, "validate_path_cost",
                    {"capture_port": ptf_port_2, "capture_duration": self.PKT_CAPTURE_DURATION,
                     "expected_root_path_cost": self.PORT_COST,
                     "expected_bridge_mac": d["dut_ports"]["mac"]},
                    "/tmp/mstp_path_cost_updated.log")
        finally:
            if default_port_cost is not None:
                self.set_port_cost(duthost, CIST, dut_port_1, default_port_cost)

    def test_mstp_bpdu_guard_with_shutdown(self, duthosts, rand_one_dut_hostname, ptfhost,
                                           setup_stp_test_data):
        """Mirror of test_pvst_bpdu_guard_with_shutdown (bpdu_guard is a global,
        mode-independent interface setting): a received BPDU err-disables the
        guarded port; after disabling the guard and bouncing the port it stays up
        even when BPDUs keep arriving."""

        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1 = d["dut_ports"]["ptf_port_1"]

        try:
            duthost.shell("config spanning-tree interface bpdu-guard enable {} --shutdown".format(dut_port_1),
                          module_ignore_errors=True)

            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/mstp_bpdu_guard_trigger.log")

            # bpdu-guard reacts to a received BPDU by taking the port out of
            # forwarding (DISCARDING/BPDU-DIS/BLOCKING) and/or err-disabling it
            # (oper-down); wait for either signal.
            tripped = wait_until(30, 2, 0, lambda: self.bpdu_guard_tripped(duthost, CIST, dut_port_1))
            port = stp_utils.get_port_data(duthost, self.STP_MODE, CIST, dut_port_1)
            state = port.get("port_state", "")
            oper = stp_utils.get_port_oper_state(duthost, dut_port_1)
            pytest_assert(
                tripped,
                "port {} should be bpdu-guard-tripped (not forwarding); state={!r}, oper={!r}"
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
                          "/tmp/mstp_bpdu_guard_disabled.log")
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

    def test_mstp_bpdu_guard_without_shutdown(self, duthosts, rand_one_dut_hostname, ptfhost,
                                              setup_stp_test_data):
        """bpdu-guard *without* --shutdown is warn-only: a received BPDU logs a
        syslog warning ("BPDU received on BPDU guard enabled interface") but the
        guarded port is NOT err-disabled (stays oper-up), since
        bpdu_guard_do_disable is not set."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1 = d["dut_ports"]["ptf_port_1"]

        warn_msg = "Warning - BPDU received on BPDU guard enabled interface {}".format(dut_port_1)

        def _warn_count():
            out = duthost.shell("grep -c '{}' /var/log/syslog".format(warn_msg),
                                module_ignore_errors=True).get("stdout", "0").strip()
            return int(out or 0)

        try:
            before = _warn_count()
            # enable bpdu-guard WITHOUT --shutdown (warn-only)
            duthost.shell("config spanning-tree interface bpdu-guard enable {}".format(dut_port_1),
                          module_ignore_errors=True)

            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/mstp_bpdu_guard_noshut.log")

            # A warn-only guard logs the syslog warning on BPDU receipt...
            pytest_assert(
                wait_until(30, 2, 0, lambda: _warn_count() > before),
                "expected a bpdu-guard syslog warning for {} but none appeared".format(dut_port_1))

            # ...and does NOT err-disable the port (err-disable takes the port
            # oper-down; a warn-only guard leaves it up).
            oper = stp_utils.get_port_oper_state(duthost, dut_port_1)
            pytest_assert(oper.lower() == "up",
                          "warn-only bpdu-guard must not err-disable {}; oper={!r}"
                          .format(dut_port_1, oper))
        finally:
            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(dut_port_1),
                          module_ignore_errors=True)

    def test_mstp_bpdu_guard_shutdown_survives_feature_restart(self, duthosts, rand_one_dut_hostname,
                                                               ptfhost, setup_stp_test_data):
        """bpdu-guard --shutdown config persists across an STP feature disable/enable:
        after bouncing `config feature state stp`, the stp docker comes back up and a
        received BPDU still err-disables the guarded port."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1 = d["dut_ports"]["dut_port_1"]
        ptf_port_1 = d["dut_ports"]["ptf_port_1"]

        def _stp_container_up():
            return self.stp_container_up(duthost)

        try:
            duthost.shell("config spanning-tree interface bpdu-guard enable {} --shutdown".format(dut_port_1),
                          module_ignore_errors=True)

            # Bounce the STP feature: the stp docker must go down, then come back up.
            duthost.shell("config feature state stp disabled", module_ignore_errors=True)
            pytest_assert(wait_until(60, 3, 0, lambda: not _stp_container_up()),
                          "stp container did not go down after disabling the feature")
            duthost.shell("config feature state stp enabled", module_ignore_errors=True)
            pytest_assert(wait_until(90, 3, 0, _stp_container_up),
                          "stp container did not come back up after re-enabling the feature")

            # With the MST enrol-on-enable fix, re-enabling the feature re-enrols
            # the VLAN members automatically -- no VLAN-membership bounce needed.
            # (A bounce would also wrongly reset the port's STP_PORT config,
            # clearing bpdu-guard, so it must NOT be used here.)
            pytest_assert(
                wait_until(60, 2, 0,
                           lambda: stp_utils.get_port_data(duthost, self.STP_MODE, CIST, dut_port_1) != {}),
                "port {} did not re-enrol in CIST after the feature restart".format(dut_port_1))

            # A received BPDU must still err-disable the guarded port.
            self.run_bpdu(ptfhost, duthost, "config",
                          self._superior_params(d, [ptf_port_1]),
                          "/tmp/mstp_bpdu_guard_feature_restart.log")
            tripped = wait_until(30, 2, 0, lambda: self.bpdu_guard_tripped(duthost, CIST, dut_port_1))
            port = stp_utils.get_port_data(duthost, self.STP_MODE, CIST, dut_port_1)
            state = port.get("port_state", "")
            oper = stp_utils.get_port_oper_state(duthost, dut_port_1)
            pytest_assert(
                tripped,
                "port {} should be err-disabled by bpdu-guard after the feature restart; "
                "state={!r}, oper={!r}".format(dut_port_1, state, oper))
        finally:
            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(dut_port_1),
                          module_ignore_errors=True)
            duthost.shell("config interface startup {}".format(dut_port_1), module_ignore_errors=True)
            # leave the STP feature enabled + docker up for the rest of the module
            duthost.shell("config feature state stp enabled", module_ignore_errors=True)
            wait_until(90, 3, 0, _stp_container_up)

    def test_mstp_bpdu_timer_validation(self, duthosts, rand_one_dut_hostname, ptfhost,
                                        setup_stp_test_data):
        """Mirror of test_pvst_bpdu_timer_validation: set custom (global) MST
        timers and confirm the DUT's emitted BPDU carries them on both ports."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        vlan_id = d["vlan"]["id"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]

        try:
            self.set_timers(duthost, vlan_id,
                            hello=self.CUSTOM_HELLO_TIME,
                            max_age=self.CUSTOM_MAX_AGE,
                            fwd_delay=self.CUSTOM_FORWARD_DELAY)

            for cap_port, log in ((ptf_port_1, "/tmp/mstp_timer_p1.log"),
                                  (ptf_port_2, "/tmp/mstp_timer_p2.log")):
                self.run_bpdu(
                    ptfhost, duthost, "validate_timers",
                    {"capture_port": cap_port, "capture_duration": self.PKT_CAPTURE_DURATION,
                     "expected_hello_time": self.CUSTOM_HELLO_TIME,
                     "expected_max_age": self.CUSTOM_MAX_AGE,
                     "expected_forward_delay": self.CUSTOM_FORWARD_DELAY},
                    log)
        finally:
            # Restore SONiC defaults (hello 2, max_age 20, forward_delay 15).
            self.set_timers(duthost, vlan_id, hello=2, max_age=20, fwd_delay=15)

    def test_mstp_mac_flush(self, duthosts, rand_one_dut_hostname, ptfhost,
                            setup_stp_test_data):
        """Mirror of test_pvst_mac_flush: learn a MAC via L2 traffic, then a
        topology-change (TC-flagged CIST) BPDU received on the other port
        flushes it."""
        duthost = duthosts[rand_one_dut_hostname]
        d = setup_stp_test_data
        dut_port_1, dut_port_2 = d["dut_ports"]["dut_port_1"], d["dut_ports"]["dut_port_2"]
        ptf_port_1, ptf_port_2 = d["dut_ports"]["ptf_port_1"], d["dut_ports"]["ptf_port_2"]
        vlan_id = d["vlan"]["id"]

        pytest_assert(self.is_self_root(duthost, CIST), "precondition: DUT should be CIST root")
        self.verify_stp_state(duthost, CIST, [dut_port_1, dut_port_2], "FORWARDING")

        # A port that has never received a BPDU is an edge port (auto edge is
        # on by default), and a topology change leaves an edge port's entries
        # alone, because its hosts did not move. The port the MAC is learned
        # on faces the PTF, so give it a bridge to talk to first: one quiet
        # BPDU it outranks, which the daemon remembers for good.
        self.run_bpdu(ptfhost, duthost, "send_cist",
                      self._superior_params(d, [ptf_port_1],
                                            cist_flags=CIST_FLAGS_QUIET_DESIGNATED,
                                            cist_root_priority=INFERIOR_PRIORITY,
                                            cist_root_mac=INFERIOR_BRIDGE_MAC,
                                            cist_bridge_priority=INFERIOR_PRIORITY,
                                            cist_bridge_mac=INFERIOR_BRIDGE_MAC),
                      "/tmp/mstp_mac_flush_neighbour.log")
        pytest_assert(self.is_self_root(duthost, CIST),
                      "the inferior neighbour on {} took the root".format(dut_port_1))

        def _mac_count():
            # Only the probe's own source address, see the PVST twin.
            lines = duthost.shell("show mac").get("stdout_lines", [])
            return sum(1 for ln in lines if dut_port_1 in ln and PROBE_MAC_PREFIX in ln.lower())

        before = _mac_count()
        self.run_bpdu(
            ptfhost, duthost, "validate_l2_packet",
            {"send_port": ptf_port_1, "receive_port": ptf_port_2,
             "vlan_id": vlan_id, "verify_packet": True},
            "/tmp/mstp_mac_flush_l2.log")

        after = _mac_count()
        pytest_assert(after > before,
                      "MACs not learned on {} (before {}, after {})".format(dut_port_1, before, after))

        # A TC is only honoured from a bridge whose information the port
        # accepts, and a designated port disputes an inferior neighbour, so
        # the TC-flagged BPDU comes from a superior root on port_2. A TC
        # flushes every non-edge port except the one it arrived on, which is
        # where the topology just changed and the entries are still valid, so
        # the flush is observed on port_1.
        self.run_bpdu(ptfhost, duthost, "tcn",
                      self._superior_params(d, [ptf_port_2]),
                      "/tmp/mstp_mac_flush_tcn.log")

        # A real flush removes the learned entries; `<=` would pass when the
        # flush does nothing, which is how this assertion stayed green for so
        # long. The flush is asynchronous, so poll for the drop.
        pytest_assert(
            wait_until(30, 2, 0, lambda: _mac_count() < after),
            "MACs not flushed on {} (before flush {}, still {})".format(
                dut_port_1, after, _mac_count()))
