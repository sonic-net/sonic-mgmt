# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
PVST config / port-enrolment behaviour tests.

The PVST counterpart of `test_mstp_config.py`. Both share the container-up guard,
feature enable/disable, per-scope enrolment helpers and the `stp_config_env`
topology fixture (in `StpTestBase` / `conftest.py`); the difference is the scope
and the lifecycle semantics:

  * PVST runs an independent spanning tree per VLAN, so a port's STP state is
    keyed by VLAN (``_STP_VLAN_PORT_TABLE:Vlan<vid>:<port>``). The scope passed
    to the shared helpers is the VLAN id (MST uses CIST instance 0).

  * ``test_pvst_enrol_on_feature_start`` (testlet 1) -- two VLANs and their
    member ports are created *first*; PVST + the STP feature are then enabled.
    Each member must enrol in *its* VLAN's tree. Disabling PVST clears the mode.
  * ``test_pvst_member_lifecycle_per_vlan`` (testlet 2) -- because each VLAN has
    its own tree, a port in two VLANs has *independent* state in each. Removing
    it from one VLAN drops only that VLAN's state; the other VLAN's state stays
    until the port leaves that VLAN too. (This is the PVST analogue of the MST
    single-CIST lifecycle test.)
"""
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.stp.stp_base import StpTestBase

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs'),
    # LogAnalyzer is disabled on this image: its end marker never lands in
    # /var/log/syslog (imrelp pipeline + config-reload rsyslog restart), so
    # every test ERRORs at teardown. Tracked separately; re-enable with the
    # staged ignore_regex once that infra bug is fixed.
    pytest.mark.disable_loganalyzer,
]


class TestPvstConfig(StpTestBase):

    STP_MODE = "pvst"
    BLOCK_STATE = "BLOCKING"

    # =========================================================== testlet 1
    def test_pvst_enrol_on_feature_start(self, duthosts, rand_one_dut_hostname, stp_config_env):
        """PVST + the STP feature are enabled *after* two VLANs and their member
        ports already exist; every member must enrol in its VLAN's spanning tree.
        Disabling PVST then clears the mode."""
        duthost = duthosts[rand_one_dut_hostname]
        env = stp_config_env
        vlan_a, vlan_b = env["vlan_a"], env["vlan_b"]
        p1, p2, p3, p4 = env["ports"]

        try:
            # --- start from STP fully off, so this is a genuine "feature starts
            #     with pre-existing members" test ---
            self.disable_stp(duthost)
            self.disable_feature_and_wait(duthost)

            # --- build topology while STP is down: VLAN A keeps p1..p3, VLAN B
            #     gets p4 (moved out of VLAN A so it is a plain untagged member) ---
            duthost.shell("config vlan member del {} {}".format(vlan_a, p4), module_ignore_errors=True)
            duthost.shell("config vlan add {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_b, p4),
                          module_ignore_errors=True)
            for p in (p1, p2, p3):
                duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p),
                              module_ignore_errors=True)

            # --- enable PVST, then start the STP feature ---
            self.enable_stp(duthost)
            self.enable_feature_and_wait(duthost)
            self.ensure_stp_up(duthost)

            # --- each member enrols in its own VLAN's tree ---
            for p in (p1, p2, p3):
                pytest_assert(self.wait_enrolled(duthost, vlan_a, p),
                              "PVST did not enrol {} in VLAN {} after feature start".format(p, vlan_a))
            pytest_assert(self.wait_enrolled(duthost, vlan_b, p4),
                          "PVST did not enrol {} in VLAN {} after feature start".format(p4, vlan_b))

            # DUT is the root of both per-VLAN trees; oper-up members forward.
            for vid in (vlan_a, vlan_b):
                pytest_assert(self.wait_self_root(duthost, vid),
                              "DUT is not the root for VLAN {} after feature start".format(vid))
            for p in (p1, p2, p3):
                self.assert_forwarding_if_up(duthost, vlan_a, p)
            self.assert_forwarding_if_up(duthost, vlan_b, p4)

            # --- disable PVST: STP|GLOBAL mode is cleared in CONFIG_DB ---
            self.disable_stp(duthost)
            self.assert_mode_cleared(duthost)
        finally:
            # restore baseline: drop VLAN B, hand p4 back to VLAN A
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)
            self.enable_stp(duthost)
            self.enable_feature_and_wait(duthost)

    # =========================================================== testlet 2
    def test_pvst_member_lifecycle_per_vlan(self, duthosts, rand_one_dut_hostname, stp_config_env):
        """PVST keeps *independent* per-VLAN state for a shared port. VLAN A has
        p1..p4; VLAN B also gets p4. p4 has state in both trees. Removing p4 from
        VLAN B drops only its VLAN-B state (VLAN-A state stays); removing p4 from
        VLAN A drops its VLAN-A state too; re-adding p4 re-enrols it in VLAN A."""
        duthost = duthosts[rand_one_dut_hostname]
        env = stp_config_env
        vlan_a, vlan_b = env["vlan_a"], env["vlan_b"]
        p1, p2, p3, p4 = env["ports"]

        try:
            # VLAN A already holds p1..p4 (minigraph baseline). Also put p4 in
            # VLAN B (tagged -- it is untagged in VLAN A).
            duthost.shell("config vlan add {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {}".format(vlan_b, p4), module_ignore_errors=True)

            # p1..p4 run PVST in VLAN A; p4 additionally runs PVST in VLAN B.
            for p in (p1, p2, p3, p4):
                pytest_assert(self.wait_enrolled(duthost, vlan_a, p),
                              "PVST not running on {} in VLAN {}".format(p, vlan_a))
            pytest_assert(self.wait_enrolled(duthost, vlan_b, p4),
                          "PVST not running on {} in VLAN {}".format(p4, vlan_b))

            # remove p4 from VLAN B -> only its VLAN-B state is gone; VLAN-A stays
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            pytest_assert(self.wait_unenrolled(duthost, vlan_b, p4),
                          "PVST state for {} in VLAN {} not removed after leaving it".format(p4, vlan_b))
            for p in (p1, p2, p3, p4):
                pytest_assert(self.is_enrolled(duthost, vlan_a, p),
                              "PVST VLAN-{} state for {} wrongly dropped when only VLAN {} "
                              "membership was removed".format(vlan_a, p, vlan_b))
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)

            # remove p4 from VLAN A -> its VLAN-A state is now gone as well
            duthost.shell("config vlan member del {} {}".format(vlan_a, p4), module_ignore_errors=True)
            pytest_assert(self.wait_unenrolled(duthost, vlan_a, p4),
                          "PVST state for {} in VLAN {} not removed after leaving it".format(p4, vlan_a))
            for p in (p1, p2, p3):
                pytest_assert(self.is_enrolled(duthost, vlan_a, p),
                              "PVST VLAN-{} state for {} wrongly dropped when only {} left".format(
                                  vlan_a, p, p4))

            # re-add p4 to VLAN A -> it re-enrols in VLAN A
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)
            pytest_assert(self.wait_enrolled(duthost, vlan_a, p4),
                          "PVST did not re-enrol {} in VLAN {} after re-adding it".format(p4, vlan_a))
        finally:
            # ensure VLAN B is gone and p4 is back in VLAN A
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)
