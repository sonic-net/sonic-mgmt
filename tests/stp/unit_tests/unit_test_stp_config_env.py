# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for the ``stp_config_env`` helpers in ``tests/stp/conftest.py``.

The fixture needs a DUT, but everything deciding *what it touches* is a plain
function over ``duthost.shell``. Those are exercised here against a fake.

``conftest.py`` is loaded by path with ``tests.common.*`` and the two sibling
stp modules stubbed, for the same reason as unit_test_stp_utils.py: importing
``tests.common`` pulls in paramiko, scapy and ansible.

Run with::

    python3 -m pytest --noconftest tests/stp/unit_tests/unit_test_stp_config_env.py -v
"""
import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest

# tests/pytest.ini formats logs with %(funcNamewithModule)s, added by a plugin
# --noconftest does not load. Supply it here or any log call in the code under
# test dies in the formatter. A record factory, not a filter: filters on an
# ancestor logger do not run for records that propagate up to it.
_ORIGINAL_RECORD_FACTORY = logging.getLogRecordFactory()


def _record_factory(*args, **kwargs):
    record = _ORIGINAL_RECORD_FACTORY(*args, **kwargs)
    record.funcNamewithModule = "%s.%s" % (record.module, record.funcName)
    return record


logging.setLogRecordFactory(_record_factory)


_STP_DIR = Path(__file__).resolve().parents[1]
_TESTS_DIR = _STP_DIR.parent
_CONFTEST = _STP_DIR / "conftest.py"
_ASSERTIONS = _TESTS_DIR / "common" / "helpers" / "assertions.py"


def _exec_source(path, namespace):
    exec(compile(path.read_text(), str(path), "exec"), namespace)
    return namespace


def _import_conftest():
    """Load conftest.py by path with its sonic-mgmt imports stubbed out."""
    pytest_assert = _exec_source(_ASSERTIONS, {})["pytest_assert"]

    def _module(name, **attrs):
        mod = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        return mod

    stubs = {
        "tests.common": _module("tests.common"),
        "tests.common.utilities": _module("tests.common.utilities",
                                          wait_until=lambda *a, **k: True),
        "tests.common.helpers": _module("tests.common.helpers"),
        "tests.common.helpers.assertions": _module("tests.common.helpers.assertions",
                                                   pytest_assert=pytest_assert),
        "tests.common.fixtures": _module("tests.common.fixtures"),
        "tests.common.fixtures.ptfhost_utils": _module(
            "tests.common.fixtures.ptfhost_utils",
            copy_ptftests_directory=pytest.fixture(lambda: None)),
        "tests.stp": _module("tests.stp"),
        "tests.stp.stp_base": _module("tests.stp.stp_base", PVST="pvst", MST="mst"),
        "tests.stp.stp_utils": _module("tests.stp.stp_utils"),
    }

    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location("stp_conftest_under_test", _CONFTEST)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original
    return module


conftest = _import_conftest()


class FakeDut:
    """Answers redis reads from a canned CONFIG_DB and records config writes."""

    hostname = "fake-dut"

    def __init__(self, vlans=None, members=None, fail=(), portchannels=None, stp_rows=None):
        # vlans: {vlan_id}   members: {(vlan_id, port): tagging_mode}
        # portchannels: {name}   stp_rows: {"STP_PORT|PortChannel990", ...}
        self.vlans = set(vlans or ())
        self.members = dict(members or {})
        self.fail = set(fail)
        self.portchannels = set(portchannels or ())
        self.stp_rows = set(stp_rows or ())
        self.commands = []

    def shell(self, cmd, module_ignore_errors=False):
        self.commands.append(cmd)
        if cmd in self.fail:
            return {"rc": 1, "stdout": "", "stderr": "boom"}

        if cmd.startswith("redis-cli -n 4 keys 'VLAN|Vlan*'"):
            return self._out(["VLAN|Vlan{}".format(v) for v in sorted(self.vlans)])
        if cmd.startswith("redis-cli -n 4 keys 'VLAN_MEMBER|Vlan"):
            vid = int(cmd.split("Vlan")[1].split("|")[0])
            return self._out(["VLAN_MEMBER|Vlan{}|{}".format(v, p)
                              for (v, p) in sorted(self.members) if v == vid])
        if cmd.startswith("redis-cli -n 4 keys 'VLAN_MEMBER|*'"):
            return self._out(["VLAN_MEMBER|Vlan{}|{}".format(v, p)
                              for (v, p) in sorted(self.members)])
        if cmd.startswith("redis-cli -n 4 hget 'VLAN_MEMBER|"):
            key = cmd.split("'")[1]
            _t, vlan_name, port = key.split("|")
            return self._out([self.members.get((int(vlan_name[4:]), port), "")])
        if cmd.startswith("redis-cli -n 4 keys 'PORTCHANNEL|PortChannel*'"):
            return self._out(["PORTCHANNEL|{}".format(pc) for pc in sorted(self.portchannels)])
        if cmd.startswith("redis-cli -n 4 keys 'VLAN_MEMBER|*|"):
            port = cmd.split("|*|")[1].split("'")[0]
            return self._out(["VLAN_MEMBER|Vlan{}|{}".format(v, p)
                              for (v, p) in sorted(self.members) if p == port])
        if cmd.startswith("redis-cli -n 4 keys 'STP_"):
            pattern = cmd.split("keys '")[1].rstrip("'")
            table, suffix = pattern.split("|*", 1)
            return self._out(sorted(k for k in self.stp_rows
                                    if k.startswith(table + "|") and k.endswith(suffix)))
        if cmd.startswith("redis-cli -n 4 del '"):
            self.stp_rows.discard(cmd.split("'")[1])
            return self._out([])
        return {"rc": 0, "stdout": "", "stdout_lines": []}

    @staticmethod
    def _out(lines):
        return {"rc": 0, "stdout": "\n".join(lines), "stdout_lines": lines}

    def writes(self):
        return [c for c in self.commands if c.startswith("config ")]

    def mutations(self):
        """Config commands plus the direct CONFIG_DB deletes, in order."""
        return [c for c in self.commands
                if c.startswith("config ") or c.startswith("redis-cli -n 4 del ")]


# --------------------------------------------------------------------------
# Reading what is really configured
# --------------------------------------------------------------------------

class TestVlanIdsOnDut:
    def test_reads_config_db_not_the_minigraph(self):
        dut = FakeDut(vlans={1000, 2000})
        assert conftest._vlan_ids_on_dut(dut) == {1000, 2000}

    def test_empty_switch(self):
        assert conftest._vlan_ids_on_dut(FakeDut()) == set()

    def test_ignores_rows_that_are_not_vlans(self):
        dut = FakeDut(vlans={1000})
        dut.shell = lambda cmd, module_ignore_errors=False: FakeDut._out(
            ["VLAN|Vlan1000", "VLAN|VlanSomething", "", "VLAN|Vlan2000"])
        assert conftest._vlan_ids_on_dut(dut) == {1000, 2000}


class TestPortMemberships:
    def test_reads_vlan_and_tagging_per_port(self):
        dut = FakeDut(members={(1000, "Ethernet0"): "untagged",
                               (2000, "Ethernet0"): "tagged",
                               (1000, "Ethernet4"): "untagged",
                               (1000, "Ethernet8"): "untagged"})
        got = conftest._port_memberships(dut, ["Ethernet0", "Ethernet4"])
        assert got == {"Ethernet0": {1000: "untagged", 2000: "tagged"},
                       "Ethernet4": {1000: "untagged"}}

    def test_port_with_no_membership_is_still_reported(self):
        dut = FakeDut(members={(1000, "Ethernet0"): "untagged"})
        assert conftest._port_memberships(dut, ["Ethernet0", "Ethernet4"]) == {
            "Ethernet0": {1000: "untagged"}, "Ethernet4": {}}

    def test_missing_tagging_mode_defaults_to_untagged(self):
        dut = FakeDut(members={(1000, "Ethernet0"): ""})
        assert conftest._port_memberships(dut, ["Ethernet0"]) == {
            "Ethernet0": {1000: "untagged"}}


# --------------------------------------------------------------------------
# Only removing what we created
# --------------------------------------------------------------------------

class TestScratchVlanSelection:
    """A VLAN the switch has but the minigraph does not must not be picked."""

    @staticmethod
    def _pick(dut, vlan_a, minigraph_vids):
        taken = conftest._vlan_ids_on_dut(dut) | minigraph_vids
        return next((v for v in conftest.CANDIDATE_VLAN_B
                     if v != vlan_a and v not in taken), None)

    def test_a_vlan_configured_but_not_in_the_minigraph_is_not_chosen(self):
        # Vlan2000 exists on the box; the minigraph knows nothing about it.
        dut = FakeDut(vlans={1000, 2000})
        assert self._pick(dut, vlan_a=1000, minigraph_vids={1000}) != 2000

    def test_first_genuinely_free_candidate_is_chosen(self):
        dut = FakeDut(vlans={1000, 2000})
        assert self._pick(dut, vlan_a=1000, minigraph_vids={1000}) == 2100

    def test_none_when_every_candidate_is_in_use(self):
        dut = FakeDut(vlans={1000} | set(conftest.CANDIDATE_VLAN_B))
        assert self._pick(dut, vlan_a=1000, minigraph_vids={1000}) is None

    def test_minigraph_is_still_honoured(self):
        dut = FakeDut(vlans={1000})
        assert self._pick(dut, vlan_a=1000, minigraph_vids={1000, 2000}) == 2100


class TestDeleteVlan:
    def test_members_are_removed_before_the_vlan(self):
        dut = FakeDut(vlans={2000},
                      members={(2000, "Ethernet0"): "untagged",
                               (2000, "Ethernet4"): "tagged"})
        conftest._delete_vlan(dut, 2000)
        assert dut.writes() == ["config vlan member del 2000 Ethernet0",
                                "config vlan member del 2000 Ethernet4",
                                "config vlan del 2000"]

    def test_vlan_with_no_members(self):
        conftest._delete_vlan(FakeDut(vlans={2000}), 2000)


# --------------------------------------------------------------------------
# Putting the switch back exactly as it was
# --------------------------------------------------------------------------

class TestRestoreMemberships:
    def test_nothing_to_do_when_unchanged(self):
        dut = FakeDut()
        state = {"Ethernet0": {1000: "untagged"}}
        conftest._restore_memberships(dut, state, state)
        assert dut.writes() == []

    def test_a_port_moved_to_another_vlan_is_moved_back(self):
        dut = FakeDut()
        before = {"Ethernet0": {1000: "untagged"}}
        now = {"Ethernet0": {2000: "untagged"}}
        conftest._restore_memberships(dut, before, now)
        assert dut.writes() == ["config vlan member del 2000 Ethernet0",
                                "config vlan member add 1000 Ethernet0 --untagged"]

    def test_tagging_is_restored_not_assumed_untagged(self):
        # A tagged port must come back tagged, not be re-added --untagged.
        dut = FakeDut()
        before = {"Ethernet0": {1000: "tagged"}}
        now = {"Ethernet0": {1000: "untagged"}}
        conftest._restore_memberships(dut, before, now)
        assert dut.writes() == ["config vlan member del 1000 Ethernet0",
                                "config vlan member add 1000 Ethernet0"]

    def test_a_membership_the_test_added_is_removed(self):
        dut = FakeDut()
        before = {"Ethernet0": {1000: "untagged"}}
        now = {"Ethernet0": {1000: "untagged", 2000: "tagged"}}
        conftest._restore_memberships(dut, before, now)
        assert dut.writes() == ["config vlan member del 2000 Ethernet0"]

    def test_a_membership_the_test_removed_is_put_back(self):
        dut = FakeDut()
        before = {"Ethernet0": {1000: "untagged", 2000: "tagged"}}
        now = {"Ethernet0": {1000: "untagged"}}
        conftest._restore_memberships(dut, before, now)
        assert dut.writes() == ["config vlan member add 2000 Ethernet0"]


# --------------------------------------------------------------------------
# Failing loudly
# --------------------------------------------------------------------------

class TestRunFailsLoudly:
    """A failed restore must not look the same as a successful one."""

    def test_a_failed_command_raises(self):
        dut = FakeDut(fail={"config vlan del 2000"})
        with pytest.raises(pytest.fail.Exception) as excinfo:
            conftest._run(dut, "config vlan del 2000")
        assert "config vlan del 2000" in str(excinfo.value)

    def test_a_successful_command_does_not(self):
        conftest._run(FakeDut(), "config vlan add 2000")

    def test_tolerated_failures_do_not_raise(self):
        dut = FakeDut(fail={"config vlan member del 2000 Ethernet0"})
        conftest._run(dut, "config vlan member del 2000 Ethernet0", tolerate=True)

    def test_a_failed_restore_is_not_silent(self):
        dut = FakeDut(fail={"config vlan member add 1000 Ethernet0 --untagged"})
        with pytest.raises(pytest.fail.Exception):
            conftest._restore_memberships(
                dut, {"Ethernet0": {1000: "untagged"}}, {"Ethernet0": {}})


# --------------------------------------------------------------------------
# The scratch PortChannel: choosing a free name, and cleaning up after it
# --------------------------------------------------------------------------

def _fixture_fn(fixture):
    """The undecorated generator behind a @pytest.fixture, so it can be driven
    here. Fixtures refuse to be called directly."""
    return getattr(fixture, "__wrapped__", fixture)


def _run_spare_portchannel(dut):
    """Drive the fixture: returns (chosen_name, teardown_callable)."""
    gen = _fixture_fn(conftest.spare_portchannel)({dut.hostname: dut}, dut.hostname)
    name = next(gen)

    def teardown():
        dut.commands.clear()
        next(gen, None)

    return name, teardown


class TestSparePortchannelSelection:
    def test_reads_config_db_for_the_names_in_use(self):
        dut = FakeDut(portchannels={"PortChannel0001", "PortChannel990"})
        assert conftest._portchannels_on_dut(dut) == {"PortChannel0001", "PortChannel990"}

    def test_empty_switch(self):
        assert conftest._portchannels_on_dut(FakeDut()) == set()

    def test_first_free_candidate_is_chosen(self):
        dut = FakeDut(portchannels={"PortChannel0001", conftest.CANDIDATE_PORTCHANNEL[0]})
        name, teardown = _run_spare_portchannel(dut)
        assert name == conftest.CANDIDATE_PORTCHANNEL[1]
        teardown()

    def test_skips_when_every_candidate_is_in_use(self):
        # pytest.skip raises an OutcomeException (a BaseException), so catching
        # plain Exception here would let it skip *this* test instead.
        dut = FakeDut(portchannels=set(conftest.CANDIDATE_PORTCHANNEL))
        with pytest.raises(pytest.skip.Exception, match="no spare PortChannel name"):
            _run_spare_portchannel(dut)


class TestSparePortchannelTeardown:
    """The defect under test is a row outliving its interface, so a failing test
    must not hand the next one a stale one."""

    def test_vlan_membership_goes_before_the_interface(self):
        pc = conftest.CANDIDATE_PORTCHANNEL[0]
        dut = FakeDut(members={(1000, pc): "untagged"})
        _name, teardown = _run_spare_portchannel(dut)
        dut.portchannels.add(pc)   # the test created it and left it behind
        dut.stp_rows.add("STP_PORT|{}".format(pc))
        teardown()
        assert dut.mutations() == ["config vlan member del 1000 {}".format(pc),
                                   "config portchannel del {}".format(pc),
                                   "redis-cli -n 4 del 'STP_PORT|{}'".format(pc)]

    def test_interface_already_deleted_is_not_deleted_again(self):
        dut = FakeDut()
        _name, teardown = _run_spare_portchannel(dut)
        teardown()
        assert dut.mutations() == []

    def test_a_row_the_test_left_behind_is_removed_even_so(self):
        pc = conftest.CANDIDATE_PORTCHANNEL[0]
        dut = FakeDut(stp_rows={"STP_PORT|{}".format(pc),
                                "STP_VLAN_PORT|Vlan1000|{}".format(pc)})
        _name, teardown = _run_spare_portchannel(dut)
        teardown()
        assert dut.stp_rows == set()

    def test_rows_for_other_interfaces_are_left_alone(self):
        pc, other = conftest.CANDIDATE_PORTCHANNEL[0], conftest.CANDIDATE_PORTCHANNEL[1]
        keep = {"STP_PORT|{}".format(other), "STP_PORT|Ethernet0"}
        dut = FakeDut(stp_rows={"STP_PORT|{}".format(pc)} | keep)
        _name, teardown = _run_spare_portchannel(dut)
        teardown()
        assert dut.stp_rows == keep
