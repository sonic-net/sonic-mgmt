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
  * ``test_pvst_portchannel_delete_leaves_no_stp_state`` (testlet 3) -- the
    config-leak counterpart: a deleted interface must take its CONFIG_DB
    spanning-tree rows with it. Covers PortChannels because they are the only
    interface class the CLI can create and delete outright. The cleanup itself
    is mode-agnostic, so there is deliberately no MST duplicate.
  * ``test_pvst_disable_leaves_valid_config_and_no_tree`` (testlet 4) -- a
    disable stops the protocol: the per-VLAN tables go, the per-VLAN config
    stays, and the running config still validates.
  * ``test_pvst_bridge_priority_must_be_a_multiple_of_4096`` -- the YANG model
    refuses a global or per-VLAN bridge priority that is not a multiple of
    4096, so the configured and the running priority cannot disagree.
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


def _config_db_exists(duthost, key):
    return duthost.shell("redis-cli -n 4 exists '{}'".format(key),
                         module_ignore_errors=True).get("stdout", "").strip() == "1"


def _stp_keys_for(duthost, intf):
    """Every CONFIG_DB STP row keyed on `intf`, across both interface-keyed tables."""
    keys = []
    for table in ("STP_PORT", "STP_VLAN_PORT"):
        out = duthost.shell("redis-cli -n 4 keys '{}|*'".format(table),
                            module_ignore_errors=True).get("stdout", "")
        keys += [k.strip() for k in out.splitlines() if k.strip().split("|")[-1] == intf]
    return keys


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

    # =========================================================== testlet 3
    def test_pvst_portchannel_delete_leaves_no_stp_state(self, duthosts, rand_one_dut_hostname,
                                                         stp_config_env, spare_portchannel):
        """Deleting an interface must take its spanning-tree configuration with it.

        A PortChannel that joins a PVST VLAN has an STP_PORT row seeded for it.
        Once the PortChannel is deleted CONFIG_DB must hold no STP row keyed on
        that name: a row for an interface that no longer exists is what makes a
        later config replace fail validation, and it would silently re-apply if a
        PortChannel of the same name were recreated.

        Three phases, because the row has three lifetimes. A PortChannel that
        never joined a VLAN never gets one. A row holding only the seeded
        defaults goes when the PortChannel leaves its last VLAN. A row the
        operator customized survives that leave by design -- so removing the
        interface is the only thing left that can clear it.
        """
        duthost = duthosts[rand_one_dut_hostname]
        vlan_a = stp_config_env["vlan_a"]
        pc = spare_portchannel
        stp_port_key = "STP_PORT|{}".format(pc)

        def _hget(field):
            return duthost.shell("redis-cli -n 4 hget '{}' {}".format(stp_port_key, field),
                                 module_ignore_errors=True).get("stdout", "").strip()

        # --- phase 1: never a VLAN member, so no row is ever created ---
        duthost.shell("config portchannel add {}".format(pc))
        # Give a late write the same 30 s the positive checks below get.
        pytest_assert(not wait_until(30, 2, 0, lambda: _config_db_exists(duthost, stp_port_key)),
                      "{} was given an STP_PORT row without ever joining a VLAN".format(pc))
        duthost.shell("config portchannel del {}".format(pc))
        pytest_assert(not _stp_keys_for(duthost, pc),
                      "create-then-delete of {} left STP rows behind: {}".format(
                          pc, _stp_keys_for(duthost, pc)))

        # --- phase 2: the seeded row goes when the PortChannel leaves its last VLAN ---
        duthost.shell("config portchannel add {}".format(pc))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, pc))
        pytest_assert(wait_until(30, 2, 0, lambda: _config_db_exists(duthost, stp_port_key)),
                      "PVST did not seed an STP_PORT row for {} on joining VLAN {}".format(pc, vlan_a))
        pytest_assert(_hget("enabled") == "true",
                      "STP_PORT row seeded for {} is not enabled".format(pc))

        duthost.shell("config vlan member del {} {}".format(vlan_a, pc))
        pytest_assert(wait_until(30, 2, 0, lambda: not _stp_keys_for(duthost, pc)),
                      "STP rows for {} survived it leaving its last VLAN: {}".format(
                          pc, _stp_keys_for(duthost, pc)))
        duthost.shell("config portchannel del {}".format(pc))

        # --- phase 3: a customized row outlives the VLAN and must go with the
        #     interface. ---
        duthost.shell("config portchannel add {}".format(pc))
        duthost.shell("config vlan member add {} {} --untagged".format(vlan_a, pc))
        pytest_assert(wait_until(30, 2, 0, lambda: _config_db_exists(duthost, stp_port_key)),
                      "PVST did not seed an STP_PORT row for {} on re-joining VLAN {}".format(pc, vlan_a))

        # Customize it while the PortChannel is still a VLAN member -- the STP
        # interface commands refuse an interface with no VLAN.
        duthost.shell("config spanning-tree interface bpdu-guard enable {}".format(pc))
        pytest_assert(_hget("bpdu_guard") == "true",
                      "could not customize the STP_PORT row for {}: bpdu_guard did not take".format(pc))

        duthost.shell("config vlan member del {} {}".format(vlan_a, pc))
        pytest_assert(_config_db_exists(duthost, stp_port_key),
                      "customized STP_PORT row for {} was dropped when it left the VLAN; "
                      "it is meant to survive membership changes".format(pc))

        duthost.shell("config portchannel del {}".format(pc))
        pytest_assert(not _config_db_exists(duthost, "PORTCHANNEL|{}".format(pc)),
                      "{} was not deleted".format(pc))
        orphaned = _stp_keys_for(duthost, pc)
        pytest_assert(not orphaned,
                      "deleting {} left orphaned STP rows in CONFIG_DB: {}".format(pc, orphaned))

    # =========================================================== testlet 4
    def test_pvst_disable_leaves_valid_config_and_no_tree(self, duthosts, rand_one_dut_hostname,
                                                          stp_config_env):
        """Disabling PVST stops the protocol and nothing else. Every per-VLAN
        and per-port row the daemon wrote to APPL_DB is gone, so no show
        command can report a live tree; the per-VLAN priority stays in
        CONFIG_DB for the next enable; and the kept config still passes the
        YANG validation every config patch runs."""
        duthost = duthosts[rand_one_dut_hostname]
        vlan_a = stp_config_env["vlan_a"]
        p1 = stp_config_env["ports"][0]
        priority = 8192

        try:
            self.set_bridge_priority(duthost, vlan_a, priority)
            stp_utils.assert_member_ready(duthost, self.wait_enrolled(duthost, vlan_a, p1),
                                          "{} is not in VLAN {}'s tree before the disable".format(p1, vlan_a))

            self.disable_stp(duthost)
            self.assert_mode_cleared(duthost)
            self.assert_tree_cleared(duthost)

            kept = duthost.shell("redis-cli -n 4 hget 'STP_VLAN|Vlan{}' priority".format(vlan_a),
                                 module_ignore_errors=True).get("stdout", "").strip()
            pytest_assert(kept == str(priority),
                          "the disable did not keep VLAN {}'s priority: {!r}".format(vlan_a, kept))
            self.assert_config_validates(duthost)
        finally:
            if duthost.shell("redis-cli -n 4 hget 'STP|GLOBAL' mode",
                             module_ignore_errors=True).get("stdout", "").strip() != self.STP_MODE:
                self.enable_stp(duthost)
            self.set_bridge_priority(duthost, vlan_a, 32768)

    # =========================================================== testlet 5
    def test_pvst_config_replace_round_trip(self, duthosts, rand_one_dut_hostname, stp_config_env):
        """The spanning-tree tables must survive a config replace of the running
        configuration: the replace is accepted, every STP row reads back as it
        was, and the tree is still there afterwards. A table missing from the
        replace path would either be refused by validation or silently dropped,
        and both show up here."""
        duthost = duthosts[rand_one_dut_hostname]
        vlan_a = stp_config_env["vlan_a"]
        p1 = stp_config_env["ports"][0]
        rows = ("STP|GLOBAL", "STP_VLAN|Vlan{}".format(vlan_a), "STP_PORT|{}".format(p1))

        def _snapshot():
            return {key: stp_utils._hgetall(duthost, key, dbnum=4) for key in rows}

        try:
            # Something non-default in every table, so a dropped table is visible.
            self.set_bridge_priority(duthost, vlan_a, 8192)
            duthost.shell("config spanning-tree interface bpdu-guard enable {}".format(p1))
            stp_utils.assert_member_ready(duthost, self.wait_enrolled(duthost, vlan_a, p1),
                                          "{} is not in VLAN {}'s tree before the replace".format(p1, vlan_a))
            before = _snapshot()
            pytest_assert(all(before.values()), "an STP table is empty before the replace: {}".format(before))

            duthost.shell("sonic-cfggen -d --print-data > /tmp/stp_running_config.json")
            res = duthost.shell("config replace /tmp/stp_running_config.json", module_ignore_errors=True)
            pytest_assert(res.get("rc", 1) == 0,
                          "config replace of the running config failed: {}".format(
                              (res.get("stderr") or res.get("stdout") or "").strip()[-600:]))

            after = _snapshot()
            pytest_assert(after == before, "STP tables changed across a replace of the same config.\n"
                          "  before: {}\n  after:  {}".format(before, after))
            pytest_assert(self.wait_enrolled(duthost, vlan_a, p1),
                          "{} left VLAN {}'s tree after the replace".format(p1, vlan_a))
            pytest_assert(self.wait_self_root(duthost, vlan_a),
                          "DUT is not the root of VLAN {} after the replace".format(vlan_a))
        finally:
            duthost.shell("config spanning-tree interface bpdu-guard disable {}".format(p1),
                          module_ignore_errors=True)
            self.set_bridge_priority(duthost, vlan_a, 32768)

    def test_pvst_bridge_priority_must_be_a_multiple_of_4096(self, duthosts, rand_one_dut_hostname,
                                                             stp_config_env):
        """The bridge priority is a 4-bit field: spanning tree uses the value
        rounded down to a multiple of 4096. The YANG model must refuse any
        other value, globally and per VLAN, so that what CONFIG_DB holds is
        what the protocol advertises. Goes through the generic config updater
        because that is the validation `config apply` relies on; the
        CLI has its own check."""
        duthost = duthosts[rand_one_dut_hostname]
        vlan_a = stp_config_env["vlan_a"]
        if not stp_base.bridge_priority_rule_present(duthost):
            pytest.skip("the image's spanning-tree YANG model accepts any bridge priority in 0..61440")
        vlan_key = "STP_VLAN|Vlan{}".format(vlan_a)

        def _priority(key):
            return stp_utils._hgetall(duthost, key, dbnum=4).get("priority")

        try:
            self.set_bridge_priority(duthost, vlan_a, 8192)
            pytest_assert(wait_until(10, 1, 0, lambda: _priority(vlan_key) == "8192"),
                          "VLAN {} priority did not reach CONFIG_DB".format(vlan_a))

            for key, path, value, name in (("STP|GLOBAL", "/STP/GLOBAL/priority", 100, "global_priority"),
                                           (vlan_key, "/STP_VLAN/Vlan{}/priority".format(vlan_a), 4097,
                                            "vlan_priority")):
                before = _priority(key)
                ok, out = stp_base.apply_config_patch(duthost, path, value, name)
                pytest_assert(not ok, "{} = {} was accepted; it is not a multiple of 4096".format(path, value))
                pytest_assert("multiple of 4096" in out,
                              "{} = {} was refused for another reason: {}".format(path, value, out[-400:]))
                pytest_assert(_priority(key) == before,
                              "{} changed in CONFIG_DB although the patch was refused".format(path))

            ok, out = stp_base.apply_config_patch(duthost, "/STP_VLAN/Vlan{}/priority".format(vlan_a),
                                                  61440, "vlan_priority_max")
            pytest_assert(ok, "VLAN {} priority 61440, the largest multiple of 4096, was refused: {}".format(
                vlan_a, out[-400:]))
            pytest_assert(_priority(vlan_key) == "61440",
                          "VLAN {} priority is {} after the patch, not 61440".format(vlan_a, _priority(vlan_key)))
            pytest_assert(self.wait_self_root(duthost, vlan_a),
                          "DUT is not the root of VLAN {} after the priority change".format(vlan_a))
        finally:
            self.set_bridge_priority(duthost, vlan_a, 32768)
