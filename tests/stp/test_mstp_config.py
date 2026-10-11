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
  * ``test_mstp_instance_created_from_cli`` (testlet 3) -- an instance made
    with the CLI reaches the daemon with its VLAN, enrols that VLAN's member
    and takes the VLAN off the CIST; deleting the mapping undoes it.
  * ``test_mstp_disable_leaves_valid_config_and_no_tree`` (testlet 4) -- a
    disable stops the protocol: the daemon's tables go, the region config
    stays, and the running config still validates.
  * ``test_mstp_after_runtime_switch_from_pvst`` (testlet 5) -- PVST then MST
    at runtime, with no daemon restart: the CIST comes up with every member
    and nothing of the PVST tree is left behind.

The shared machinery (container-up guard, feature enable/disable, per-scope
enrolment helpers, and the `stp_config_env` topology fixture) lives in
`StpTestBase` / `conftest.py`; only the MST-specific scope (CIST instance 0) and
the single-CIST lifecycle semantics live here. See `test_pvst_config.py` for the
PVST counterpart (per-VLAN spanning trees).
"""
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.stp import stp_base
from tests.stp import stp_utils
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
# The instance the CLI tests create. The CIST is 0 and cannot take a VLAN.
TEST_INSTANCE = 1
# A region identity that must survive a disable.
REGION_NAME = "cfg-region"
REGION_REVISION = 7


def _config_db_row(duthost, key):
    out = duthost.shell("redis-cli -n 4 hgetall '{}'".format(key),
                        module_ignore_errors=True).get("stdout_lines", [])
    return dict(zip(out[::2], out[1::2]))


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

    # =========================================================== testlet 3
    def test_mstp_instance_created_from_cli(self, duthosts, rand_one_dut_hostname, stp_config_env):
        """An MST instance made from the CLI must reach the daemon end to end:
        the instance row appears in APPL_DB with its VLAN, the VLAN's member
        enrols in that instance, and the VLAN is no longer carried by the
        CIST. Deleting the mapping takes the instance down again.

        This checks the whole path CLI -> CONFIG_DB -> stpmgrd -> stpd, which
        the unit tests cannot: the CLI writes the VLAN list as a leaf-list and
        the daemon has to read it as the switch delivers it."""
        duthost = duthosts[rand_one_dut_hostname]
        env = stp_config_env
        vlan_a, vlan_b = env["vlan_a"], env["vlan_b"]
        p1, p2, p3, p4 = env["ports"]
        inst = TEST_INSTANCE

        try:
            # VLAN B with p4 as its only member, p1..p3 stay in VLAN A.
            duthost.shell("config vlan member del {} {}".format(vlan_a, p4), module_ignore_errors=True)
            duthost.shell("config vlan add {}".format(vlan_b))
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_b, p4))
            pytest_assert(self.wait_enrolled(duthost, CIST, p4),
                          "{} did not enrol in the CIST after joining VLAN {}".format(p4, vlan_b))

            # Setting a priority creates the instance; the VLAN is then mapped.
            duthost.shell("config spanning-tree mst instance {} priority 4096".format(inst))
            duthost.shell("config spanning-tree mst instance {} vlan add {}".format(inst, vlan_b))

            pytest_assert(
                wait_until(60, 2, 0, lambda: inst in stp_utils.get_mst_instances(duthost)),
                "MST instance {} never appeared in APPL_DB (have {})".format(
                    inst, stp_utils.get_mst_instances(duthost)))
            pytest_assert(
                wait_until(30, 2, 0, lambda: vlan_b in stp_utils.get_instance_vlans(duthost, inst)),
                "instance {} carries VLANs {}, not {}".format(
                    inst, stp_utils.get_instance_vlans(duthost, inst), vlan_b))
            pytest_assert(self.wait_enrolled(duthost, inst, p4),
                          "{} did not enrol in instance {}".format(p4, inst))
            pytest_assert(self.wait_self_root(duthost, inst),
                          "DUT is not the root of instance {}".format(inst))
            self.assert_forwarding_if_up(duthost, inst, p4)
            pytest_assert(vlan_b not in stp_utils.get_instance_vlans(duthost, CIST),
                          "VLAN {} is mapped to instance {} but the CIST still carries it".format(
                              vlan_b, inst))

            # Unmap the VLAN: it returns to the CIST and the instance loses it.
            duthost.shell("config spanning-tree mst instance {} vlan del {}".format(inst, vlan_b))
            pytest_assert(
                wait_until(30, 2, 0, lambda: vlan_b not in stp_utils.get_instance_vlans(duthost, inst)),
                "VLAN {} still on instance {} after it was unmapped".format(vlan_b, inst))
            pytest_assert(self.wait_unenrolled(duthost, inst, p4),
                          "{} still has state in instance {} after its VLAN was unmapped".format(p4, inst))
            pytest_assert(self.wait_enrolled(duthost, CIST, p4),
                          "{} is not back in the CIST after VLAN {} was unmapped".format(p4, vlan_b))
        finally:
            duthost.shell("config spanning-tree mst instance {} vlan del {}".format(inst, vlan_b),
                          module_ignore_errors=True)
            stp_base.delete_mst_instance(duthost, inst)
            duthost.shell("config vlan member del {} {}".format(vlan_b, p4), module_ignore_errors=True)
            duthost.shell("config vlan del {}".format(vlan_b), module_ignore_errors=True)
            duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, p4),
                          module_ignore_errors=True)

    # =========================================================== testlet 4
    def test_mstp_disable_leaves_valid_config_and_no_tree(self, duthosts, rand_one_dut_hostname,
                                                          stp_config_env, setup_stp_test_data):
        """Disabling MST stops the protocol and nothing else. The daemon's
        APPL_DB tables are gone, so no show command can report a live tree;
        the region identity stays in CONFIG_DB for the next enable; and the
        kept config still passes the YANG validation every config patch runs,
        so a disabled switch is still configurable."""
        duthost = duthosts[rand_one_dut_hostname]
        p1 = stp_config_env["ports"][0]

        try:
            duthost.shell("config spanning-tree mst region-name {}".format(REGION_NAME))
            duthost.shell("config spanning-tree mst revision {}".format(REGION_REVISION))
            pytest_assert(self.wait_enrolled(duthost, CIST, p1),
                          "{} is not in the CIST before the disable".format(p1))

            self.disable_stp(duthost)
            self.assert_mode_cleared(duthost)
            self.assert_tree_cleared(duthost)

            region = _config_db_row(duthost, "STP_MST|GLOBAL")
            pytest_assert(region.get("name") == REGION_NAME
                          and region.get("revision") == str(REGION_REVISION),
                          "the disable did not keep the region config: {}".format(region))
            self.assert_config_validates(duthost)
        finally:
            if not stp_base.MST == duthost.shell(
                    "redis-cli -n 4 hget 'STP|GLOBAL' mode",
                    module_ignore_errors=True).get("stdout", "").strip():
                self.enable_stp(duthost)
            # Put back the region the class fixture set up, for the tests after this one.
            mst = setup_stp_test_data["mst"]
            self.setup_region(duthost, mst["region_name"], mst["revision"], mst["instance_vlan_map"])

    # =========================================================== testlet 5
    def test_mstp_after_runtime_switch_from_pvst(self, duthosts, rand_one_dut_hostname, stp_config_env,
                                                 setup_stp_test_data):
        """Switch modes on a running switch: MST off, PVST on and converged,
        PVST off, MST on. The CIST must come up with every member enrolled
        without restarting the daemon, and no per-VLAN row of the PVST tree
        may survive into MST."""
        duthost = duthosts[rand_one_dut_hostname]
        vlan_a = stp_config_env["vlan_a"]
        ports = stp_config_env["ports"]

        def _stpd_pid():
            return duthost.shell("docker exec stp pidof stpd",
                                 module_ignore_errors=True).get("stdout", "").strip()

        try:
            self.disable_stp(duthost)
            self.assert_tree_cleared(duthost)

            stp_base.enable_stp(duthost, stp_base.PVST)
            for p in ports:
                pytest_assert(wait_until(90, 3, 0, lambda p=p: stp_utils.get_port_data(
                    duthost, stp_base.PVST, vlan_a, p) != {}),
                    "PVST did not enrol {} in VLAN {}".format(p, vlan_a))
            pytest_assert(wait_until(60, 2, 0, lambda: stp_utils.is_self_root(duthost, stp_base.PVST, vlan_a)),
                          "DUT is not the PVST root of VLAN {}".format(vlan_a))
            pid_before = _stpd_pid()

            stp_base.disable_stp(duthost, stp_base.PVST)
            pytest_assert(stp_base.wait_tree_cleared(duthost, stp_base.PVST),
                          "PVST rows survived the disable: {}".format(
                              stp_base.tree_keys(duthost, stp_base.PVST)))

            self.enable_stp(duthost)
            for p in ports:
                pytest_assert(self.wait_enrolled(duthost, CIST, p),
                              "{} did not enrol in the CIST after the switch from PVST".format(p))
            pytest_assert(self.wait_self_root(duthost, CIST),
                          "DUT is not the CIST root after the switch from PVST")
            for p in ports:
                self.assert_forwarding_if_up(duthost, CIST, p)
            pytest_assert(not stp_base.tree_keys(duthost, stp_base.PVST),
                          "PVST rows are still in APPL_DB under MST: {}".format(
                              stp_base.tree_keys(duthost, stp_base.PVST)))
            pytest_assert(pid_before and _stpd_pid() == pid_before,
                          "stpd was restarted across the mode switch (pid {} -> {})".format(
                              pid_before, _stpd_pid()))
        finally:
            if duthost.shell("redis-cli -n 4 hget 'STP|GLOBAL' mode",
                             module_ignore_errors=True).get("stdout", "").strip() != stp_base.MST:
                stp_base.disable_stp(duthost, stp_base.PVST)
                self.enable_stp(duthost)
            # Entering PVST deletes the MST tables, so the class fixture's
            # region has to be put back for the tests after this one.
            mst = setup_stp_test_data["mst"]
            self.setup_region(duthost, mst["region_name"], mst["revision"], mst["instance_vlan_map"])
