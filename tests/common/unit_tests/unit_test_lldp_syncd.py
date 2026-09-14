"""Exercise LLDP convergence helpers without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_lldp_syncd.py -v
"""

import ast
from copy import deepcopy
import itertools
import json
from pathlib import Path
import sys
import traceback
from unittest.mock import Mock, call

import pytest


TESTS_PATH = Path(__file__).resolve().parents[2]
MODULE_PATH = TESTS_PATH / "lldp" / "test_lldp_syncd.py"


class Clock:
    def __init__(self):
        self.now = 0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture
def lldp():
    """Load the real helpers and polling loop, with only the clock replaced."""
    namespace = {
        "pytest": pytest, "json": json, "time": Clock(), "sys": sys,
        "traceback": traceback, "logger": Mock(), "logging": Mock(),
        "APPL_DB": "APPL_DB", "SonicDbCli": Mock(),
    }
    sources = [
        (TESTS_PATH / "common" / "helpers" / "assertions.py", {"pytest_assert"}),
        (TESTS_PATH / "common" / "utilities.py", {"wait_until"}),
        (MODULE_PATH, None),
    ]
    for path, names in sources:
        tree = ast.parse(path.read_text())
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and (names is None or node.name in names)
        ]
        for node in functions:
            node.decorator_list = []
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def neighbor(name="peer", port="Ethernet1", mac="00:11:22:33:44:55"):
    return {
        "age": "0 day, 00:00:01", "rid": "1",
        "chassis": {
            name: {"id": {"value": mac}, "descr": "test peer", "mgmt-ip": "192.0.2.1"},
        },
        "port": {"id": {"value": port}, "descr": "peer port"},
    }


def db_entry(peer):
    name, chassis = next(iter(peer["chassis"].items()))
    return {
        "lldp_rem_sys_name": name,
        "lldp_rem_chassis_id": chassis["id"]["value"],
        "lldp_rem_port_id": peer["port"]["id"]["value"],
        "lldp_rem_sys_desc": chassis["descr"],
        "lldp_rem_port_desc": peer["port"]["descr"],
        "lldp_rem_man_addr": chassis["mgmt-ip"],
        "lldp_rem_sys_cap_supported": "28 00",
        "lldp_rem_sys_cap_enabled": "28 00",
    }


def db_dump(entries):
    return {"LLDP_ENTRY_TABLE:" + name: {"type": "hash", "value": entry} for name, entry in entries.items()}


@pytest.fixture
def sample():
    interfaces = {"Ethernet0": neighbor(), "eth0": neighbor("mgmt", "Ethernet48")}
    entries = {name: db_entry(peer) for name, peer in interfaces.items()}
    return interfaces, entries


def configure_sample(lldp, interfaces, entries, cli=None):
    lldp["get_lldpctl_output"] = Mock(return_value={"lldp": {"interface": interfaces}})
    lldp["get_show_lldp_table_output"] = Mock(return_value=list(interfaces) if cli is None else cli)
    db = Mock()
    db.dump.return_value = db_dump(entries)
    return db


def verify(lldp, db, **kwargs):
    return lldp["verify_all_interfaces_lldp_content"](Mock(), [db], timeout=10, interval=5, **kwargs)


@pytest.mark.parametrize("as_list", [False, True])
def test_steady_sample_includes_management_interface(lldp, sample, as_list):
    """Both lldpctl JSON shapes retain eth0 in membership and content checks."""
    interfaces, entries = sample
    source = [{name: peer} for name, peer in interfaces.items()] if as_list else interfaces
    db = configure_sample(lldp, source, entries, cli=list(interfaces))
    assert verify(lldp, db) == entries
    assert db.dump.call_count == 1


@pytest.mark.parametrize("missing_source", ["db", "cli", "lldpctl"])
def test_membership_assertion_requires_eth0(lldp, sample, missing_source):
    """The assertion itself must not filter a missing eth0 out of any source."""
    interfaces, entries = sample
    cli = list(interfaces)
    if missing_source == "db":
        entries.pop("eth0")
    elif missing_source == "cli":
        cli.remove("eth0")
    else:
        interfaces.pop("eth0")
    with pytest.raises(pytest.fail.Exception, match="eth0"):
        lldp["assert_lldp_interfaces"](entries, cli, interfaces)


@pytest.mark.parametrize("field", ["lldp_rem_sys_cap_supported", "lldp_rem_sys_cap_enabled"])
def test_eth0_capability_checks_are_effective(lldp, sample, field):
    """Invalid eth0 capabilities must not pass through a truthy one-item tuple."""
    interfaces, entries = sample
    entries["eth0"][field] = "incorrect"
    with pytest.raises(pytest.fail.Exception, match=field):
        lldp["assert_lldp_entry_content"]("eth0", entries["eth0"], interfaces["eth0"])


@pytest.mark.parametrize("interface", ["eth0", "Ethernet0"])
@pytest.mark.parametrize("source", ["db", "cli", "lldpctl"])
def test_persistent_membership_difference_fails(lldp, sample, interface, source):
    """Missing management and front-panel entries must fail for every source."""
    interfaces, entries = sample
    cli = list(interfaces)
    if source == "db":
        entries.pop(interface)
    elif source == "cli":
        cli.remove(interface)
    else:
        interfaces.pop(interface)
    db = configure_sample(lldp, interfaces, entries, cli)
    with pytest.raises(pytest.fail.Exception, match="did not converge.*" + interface):
        verify(lldp, db)
    assert lldp["time"].now == 10
    assert db.dump.call_count == 2


@pytest.mark.parametrize("adding", [True, False])
def test_management_addition_and_aging_converge(lldp, sample, adding):
    """Accept delayed DB additions/deletions only after fresh samples agree."""
    interfaces, entries = sample
    without_mgmt = {name: entry for name, entry in entries.items() if name != "eth0"}
    old_entries, new_entries = (without_mgmt, entries) if adding else (entries, without_mgmt)
    if not adding:
        interfaces.pop("eth0")
    db = configure_sample(lldp, interfaces, new_entries)
    db.dump.side_effect = [db_dump(old_entries), db_dump(new_entries)]
    assert verify(lldp, db) == new_entries
    assert db.dump.call_count == 2
    assert lldp["get_lldpctl_output"].call_count == 4
    assert lldp["get_show_lldp_table_output"].call_count == 2


def test_neighbor_replacement_refreshes_content(lldp, sample):
    """Retry a stale DB neighbor rather than retrying against stale lldpctl data."""
    interfaces, entries = sample
    old_entries = deepcopy(entries)
    interfaces["eth0"] = neighbor("new-mgmt", "Ethernet47", "00:11:22:33:44:66")
    entries["eth0"] = db_entry(interfaces["eth0"])
    db = configure_sample(lldp, interfaces, entries)
    db.dump.side_effect = [db_dump(old_entries), db_dump(entries)]
    assert verify(lldp, db) == entries
    assert db.dump.call_count == 2


@pytest.mark.parametrize("field", [
    "lldp_rem_sys_name", "lldp_rem_chassis_id", "lldp_rem_port_id",
    "lldp_rem_sys_desc", "lldp_rem_port_desc", "lldp_rem_man_addr",
    "lldp_rem_sys_cap_supported", "lldp_rem_sys_cap_enabled",
])
def test_persistent_management_content_error_fails(lldp, sample, field):
    """Keeping eth0 must include effective content and capability assertions."""
    interfaces, entries = sample
    entries["eth0"][field] = "incorrect"
    db = configure_sample(lldp, interfaces, entries)
    with pytest.raises(pytest.fail.Exception, match="did not converge.*eth0"):
        verify(lldp, db)


@pytest.mark.parametrize("missing_field", ["lldp_rem_sys_name", "lldp_rem_sys_desc"])
def test_partial_db_entry_is_retried(lldp, sample, missing_field):
    """A transient partial hash must not escape as an unhandled missing field."""
    interfaces, entries = sample
    partial = deepcopy(entries)
    partial["eth0"].pop(missing_field)
    db = configure_sample(lldp, interfaces, entries)
    db.dump.side_effect = [db_dump(partial), db_dump(entries)]
    assert verify(lldp, db) == entries
    assert db.dump.call_count == 2


@pytest.mark.parametrize("keeps_changing", [False, True])
def test_source_changes_during_db_read(lldp, sample, keeps_changing):
    """Do not accept a DB match if LLDP changes within the sampling window."""
    interfaces, entries = sample
    old_interfaces = deepcopy(interfaces)
    old_interfaces["eth0"] = neighbor("old-mgmt")
    before = {"lldp": {"interface": old_interfaces}}
    after = {"lldp": {"interface": interfaces}}
    db = configure_sample(lldp, interfaces, entries)
    lldp["get_lldpctl_output"].side_effect = (
        itertools.cycle([before, after]) if keeps_changing else [before, after, after, after]
    )
    if keeps_changing:
        with pytest.raises(pytest.fail.Exception, match="neighbors changed while sampling"):
            verify(lldp, db)
    else:
        assert verify(lldp, db) == entries
    assert db.dump.call_count == 2


def test_age_record_id_and_order_do_not_prevent_convergence(lldp, sample):
    """Ignore elapsed age and enumeration order, but not advertised content."""
    interfaces, entries = sample
    after = deepcopy(interfaces)
    for peer in after.values():
        peer.update(age="0 day, 00:00:20", rid="99")
    after = [{name: peer} for name, peer in reversed(list(after.items()))]
    db = configure_sample(lldp, interfaces, entries)
    lldp["get_lldpctl_output"].side_effect = [
        {"lldp": {"interface": interfaces}}, {"lldp": {"interface": after}},
    ]
    assert verify(lldp, db) == entries
    assert db.dump.call_count == 1


def test_fanout_duplicates_match_full_neighbor_identity(lldp, sample):
    """Keep all neighbors, including two remote ports with the same system name."""
    interfaces, entries = sample
    other = neighbor(port="Ethernet2")
    source = [
        {"Ethernet0": other}, {"Ethernet0": interfaces["Ethernet0"]}, {"eth0": interfaces["eth0"]},
    ]
    db = configure_sample(lldp, source, entries, cli=["Ethernet0", "Ethernet0", "eth0"])
    assert verify(lldp, db) == entries


def test_empty_sources_do_not_vacuously_pass(lldp):
    """All sources being empty does not establish LLDP readiness."""
    db = configure_sample(lldp, {}, {})
    with pytest.raises(pytest.fail.Exception, match="No LLDP_ENTRY_TABLE entries"):
        verify(lldp, db)


def test_flapped_port_must_recover_even_if_missing_everywhere(lldp, sample):
    """Retain explicit recovery coverage independently of set equality."""
    interfaces, entries = sample
    interfaces.pop("Ethernet0")
    entries.pop("Ethernet0")
    db = configure_sample(lldp, interfaces, entries)
    with pytest.raises(pytest.fail.Exception, match="have not recovered.*Ethernet0"):
        verify(lldp, db, required_interfaces=["Ethernet0"])


def test_db_read_failure_cannot_pass(lldp, sample):
    """A failed command is logged and eventually fails, not treated as an empty DB."""
    interfaces, entries = sample
    db = configure_sample(lldp, interfaces, entries)
    db.dump.side_effect = RuntimeError("DB unavailable")
    with pytest.raises(pytest.fail.Exception, match="Failed to collect fresh LLDP/DB data"):
        verify(lldp, db)
    assert "DB unavailable" in lldp["logger"].error.call_args.args[0]


def test_cli_retains_eth0_and_deduplicates(lldp):
    """CLI parsing must remove duplicate rows, not management interfaces."""
    host = Mock()
    host.shell.return_value = {
        "stdout": "Capabilities\nLocalPort RemoteDevice\n--------- ------------\n"
                  "Ethernet0 peer\nEthernet0 fanout\neth0 mgmt\n---------\nTotal entries displayed: 3",
    }
    assert lldp["get_show_lldp_table_output"](host) == ["Ethernet0", "eth0"]


def test_bulk_db_snapshot_uses_one_dump_per_namespace(lldp):
    """Reading 512 ports must not add 512 remote HGETALL sampling delays."""
    dbs = [Mock(), Mock()]
    expected = {"Ethernet{}".format(i): db_entry(neighbor()) for i in range(512)}
    dbs[0].dump.return_value = db_dump(expected)
    dbs[1].dump.return_value = db_dump({"eth0": db_entry(neighbor("mgmt"))})
    expected.update({"eth0": db_entry(neighbor("mgmt"))})
    assert lldp["get_lldp_entries"](dbs) == expected
    for db in dbs:
        db.dump.assert_called_once_with("LLDP_ENTRY_TABLE:")
        db.hget_all.assert_not_called()


@pytest.mark.parametrize("namespace_ids,asic_ids", [
    ([None], [None]),
    ([None, "0", "1"], [0, 1]),
    (["0", "1"], [0, 1]),
    ([None, "0", "1"], [1]),
])
def test_lldp_and_db_use_configured_namespaces(lldp, namespace_ids, asic_ids):
    """Collect the host LLDP/DB for eth0 wherever FEATURE enables global scope."""
    host = Mock()
    host.get_namespace_ids.return_value = (namespace_ids, True)
    host.get_asic_ids.return_value = asic_ids
    host.asic_instance.side_effect = lambda asic: "asic-{}".format(asic)
    expected = [ns for ns in namespace_ids if ns is None or int(ns) in asic_ids]
    host.shell.side_effect = [
        {"stdout": json.dumps({"lldp": {"interface": (
            {"eth0": neighbor("mgmt")} if ns is None else [{"Ethernet" + ns: neighbor()}]
        )}})} for ns in expected
    ]
    result = lldp["get_lldpctl_output"](host)
    assert len(result["lldp"]["interface"]) == len(expected)
    assert host.shell.call_args_list == [
        call("docker exec lldp{} /usr/sbin/lldpctl -f json".format("" if ns is None else ns))
        for ns in expected
    ]
    lldp["get_lldp_db_instances"](host)
    assert lldp["SonicDbCli"].call_args_list == [
        call(host if ns is None else "asic-" + ns, "APPL_DB") for ns in expected
    ]


def test_namespace_discovery_failure_is_explicit(lldp):
    """Do not silently omit eth0 if FEATURE discovery fails."""
    host = Mock()
    host.get_namespace_ids.return_value = ([], False)
    with pytest.raises(pytest.fail.Exception, match="Failed to determine LLDP namespaces"):
        lldp["get_lldp_db_instances"](host)
    lldp["SonicDbCli"].assert_not_called()


def test_lldp_restart_rechecks_fresh_data_and_host_service(lldp):
    """Restart host and ASIC LLDP, then call the live convergence helper again."""
    host = Mock()
    host.get_namespace_ids.return_value = ([None, "0"], True)
    host.get_asic_ids.return_value = [0]
    host.asic_instance.return_value.get_service_name.return_value = "lldp@0"
    host.shell.return_value = {"stdout": "active (running)\nTotal entries displayed: 2"}
    check = lldp["verify_all_interfaces_lldp_content"] = Mock(return_value={"eth0": {}, "Ethernet0": {}})
    lldp["test_lldp_entry_table_after_lldp_restart"](
        {"dut": host}, "dut", ["db"], None)
    assert check.call_args_list == [
        call(host, ["db"]), call(host, ["db"], timeout=300, required_interfaces=["Ethernet0"]),
    ]
    host.shell.assert_any_call("sudo systemctl restart lldp")
    host.shell.assert_any_call("sudo systemctl restart lldp@0")


@pytest.mark.parametrize("event", ["lldp_restart", "syncd_orchagent", "reboot"])
def test_only_management_recovering_after_event_fails(lldp, sample, event):
    """eth0 staying up must not hide all front-panel neighbors failing to recover."""
    interfaces, entries = sample
    host = Mock()
    host.get_namespace_ids.return_value = ([None], True)
    host.get_asic_ids.return_value = [None]
    host.facts = {"asic_type": "broadcom"}
    host.is_multi_asic = False
    host.get_bgp_neighbors.return_value = {"peer": {}}
    host.critical_services_fully_started = lambda: True
    host.check_bgp_session_state = lambda neighbors: True
    host.shell.return_value = {"stdout": "active (running)\nTotal entries displayed: 1"}
    db = configure_sample(lldp, interfaces, entries)
    initial = {"lldp": {"interface": interfaces}}
    after = {"lldp": {"interface": {"eth0": interfaces["eth0"]}}}
    lldp["get_lldpctl_output"].side_effect = itertools.chain([initial, initial], itertools.repeat(after))
    lldp["get_show_lldp_table_output"].side_effect = itertools.chain(
        [list(interfaces)], itertools.repeat(["eth0"]))
    db.dump.side_effect = itertools.chain(
        [db_dump(entries)], itertools.repeat(db_dump({"eth0": entries["eth0"]})))
    args = [{"dut": host}, "dut", [db]]
    if event == "lldp_restart":
        args.append(None)
    elif event == "reboot":
        args.insert(0, Mock())
        lldp["reboot"] = Mock()
        lldp["REBOOT_TYPE_COLD"] = "cold"
    with pytest.raises(pytest.fail.Exception, match="have not recovered.*Ethernet0"):
        lldp["test_lldp_entry_table_after_" + event](*args)


def test_module_setup_retries_transient_collection_failure(lldp, sample):
    """A failed initial JSON read resets stability rather than aborting all tests."""
    interfaces, _ = sample
    source = {"lldp": {"interface": interfaces}}
    lldp["get_lldpctl_output"] = Mock(side_effect=itertools.chain(
        [json.JSONDecodeError("truncated", "", 0)], itertools.repeat(source)))
    lldp["get_lldp_db_instances"] = Mock(return_value=["db"])
    check = lldp["verify_all_interfaces_lldp_content"] = Mock()
    host = Mock()
    lldp["wait_for_lldp_appl_db"]({"dut": host}, "dut")
    assert lldp["get_lldpctl_output"].call_count == 5
    assert lldp["time"].now == 40
    check.assert_called_once_with(host, ["db"])
    assert "truncated" in lldp["logger"].error.call_args.args[0]
