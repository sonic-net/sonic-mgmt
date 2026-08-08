# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
MSTP config / port-enrolment behaviour tests.

These verify how MSTP enrols interfaces from VLAN membership, independent of the
BPDU/packet tests in `test_mstp.py`:

  * ``test_mstp_enrol_on_feature_start`` (testlet 1) -- two VLANs and their
    member ports are created *first*; MSTP is then enabled and the STP feature
    started. Every VLAN member must enrol in the CIST. Disabling MSTP clears the
    mode.
  * ``test_mstp_member_lifecycle_across_vlans`` (testlet 2) -- MST has a single
    CIST, so a port shared by two VLANs keeps its (one) CIST state until it
    leaves the *last* VLAN, then loses it, then re-enrols when re-added.

The shared machinery (container-up guard, feature enable/disable, per-scope
enrolment helpers, and the `stp_config_env` topology fixture) lives in
`StpTestBase` / `conftest.py`; only the MST-specific scope (CIST instance 0) and
the single-CIST lifecycle semantics live here. See `test_pvst_config.py` for the
PVST counterpart (per-VLAN spanning trees).
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

CIST = 0


class TestMstpConfig(StpTestBase):

    STP_MODE = "mst"
    BLOCK_STATE = "DISCARDING"

    # =========================================================== testlet 1
    def test_mstp_enrol_on_feature_start(self, duthosts, rand_one_dut_hostname, stp_config_env):
        """MSTP + the STP feature are enabled *after* two VLANs and their member
        ports already exist; every VLAN member must enrol in the CIST. Disabling
        MSTP then clears the mode."""
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

            # --- enable MSTP, then start the STP feature ---
            self.enable_stp(duthost)
            self.enable_feature_and_wait(duthost)
            self.ensure_stp_up(duthost)

            # --- every VLAN member (across both VLANs) enrols in the CIST ---
            for intf in (p1, p2, p3, p4):
                pytest_assert(self.wait_enrolled(duthost, CIST, intf),
                              "MSTP did not enrol {} after feature start".format(intf))

            pytest_assert(self.wait_self_root(duthost, CIST),
                          "DUT is not the CIST root after feature start")
            for intf in (p1, p2, p3, p4):
                self.assert_forwarding_if_up(duthost, CIST, intf)

            # --- disable MSTP: STP|GLOBAL mode is cleared in CONFIG_DB ---
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
    def test_mstp_member_lifecycle_across_vlans(self, duthosts, rand_one_dut_hostname,
                                                stp_config_env):
        """A port shared across VLANs keeps its (single CIST) MSTP state until it
        leaves the *last* VLAN. VLAN A has p1..p4; VLAN B also gets p4. Removing
        VLAN B leaves all four enrolled; removing p4 from VLAN A (its last VLAN)
        drops p4's CIST state; re-adding p4 re-enrols it."""
        duthost = duthosts[rand_one_dut_hostname]
        env = stp_config_env
        vlan_a, vlan_b = env["vlan_a"], env["vlan_b"]
        p1, p2, p3, p4 = env["ports"]

        try:
            # VLAN A already holds p1..p4 (minigraph baseline). Also put p4 in
            # VLAN B (tagged -- it is untagged in VLAN A).
            duthost.shell("config vlan add {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {}".format(vlan_b, p4), module_ignore_errors=True)

            # all four ports run MSTP (one CIST row each)
            for p in (p1, p2, p3, p4):
                pytest_assert(self.wait_enrolled(duthost, CIST, p),
                              "MSTP not running on {} at start of lifecycle test".format(p))

            # remove VLAN B -> p4 is still in VLAN A, so all four stay enrolled
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
            self.ensure_stp_up(duthost)
            for p in (p1, p2, p3, p4):
                pytest_assert(self.is_enrolled(duthost, CIST, p),
                              "MSTP state for {} dropped after removing VLAN {} "
                              "(port still in VLAN {})".format(p, vlan_b, vlan_a))

            # remove p4 from VLAN A -> p4 is now in no VLAN, so its state is gone
            duthost.shell("config vlan member del {} {}".format(vlan_a, p4), module_ignore_errors=True)
            pytest_assert(self.wait_unenrolled(duthost, CIST, p4),
                          "MSTP state for {} not removed after it left its last VLAN".format(p4))
            for p in (p1, p2, p3):
                pytest_assert(self.is_enrolled(duthost, CIST, p),
                              "MSTP state for {} wrongly dropped when only {} left".format(p, p4))

            # re-add p4 -> it re-enrols
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)
            pytest_assert(self.wait_enrolled(duthost, CIST, p4),
                          "MSTP did not re-enrol {} after re-adding it to VLAN {}".format(p4, vlan_a))
        finally:
            # ensure VLAN B is gone and p4 is back in VLAN A
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)
