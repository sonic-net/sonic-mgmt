"""Unit tests for the DASH config ordering helpers in
``tests/common/dash_utils.py``.

These tests load the target module in isolation using ``importlib`` so we
don't drag in the wider sonic-mgmt fixture stack. The module also does
``from constants import TEMPLATE_DIR`` at import time; we stub that out with
a fake ``constants`` module before loading so no DASH-test path needs to be
on ``sys.path``.

Run with::

    python3 -m pytest --noconftest tests/common/unit_tests/fixtures/unit_test_dash_utils.py -v
"""

import importlib.util
import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3]
               / "common" / "dash_utils.py")


def _install_stub_modules():
    """Install minimal stubs for modules ``dash_utils`` imports at module load
    time so the unit tests don't depend on the sonic-mgmt test path layout."""
    if "constants" not in sys.modules:
        constants_stub = types.ModuleType("constants")
        constants_stub.TEMPLATE_DIR = "/tmp/_unit_test_template_dir"
        sys.modules["constants"] = constants_stub

    # ``dash_utils`` also imports ``ptf.packet``, ``ptf.testutils``, ``pytest``,
    # and ``jinja2``. ptf isn't installed in lightweight unit-test environments,
    # so stub it; the other three should be present.
    if "ptf" not in sys.modules:
        ptf_stub = types.ModuleType("ptf")
        ptf_packet_stub = types.ModuleType("ptf.packet")
        ptf_testutils_stub = types.ModuleType("ptf.testutils")
        sys.modules["ptf"] = ptf_stub
        sys.modules["ptf.packet"] = ptf_packet_stub
        sys.modules["ptf.testutils"] = ptf_testutils_stub


def _load_target_module():
    _install_stub_modules()
    spec = importlib.util.spec_from_file_location(
        "unit_target_dash_utils", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules so test helpers can also resolve it by name
    # (and so any internal `importlib.import_module` lookups work).
    sys.modules["unit_target_dash_utils"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def dash_utils():
    return _load_target_module()


@pytest.fixture(autouse=True)
def _bypass_repo_log_format(monkeypatch):
    """The repo's ``tests/pytest.ini`` configures ``log_format`` with a
    custom ``%(funcNamewithModule)s`` field that is injected by the
    ``log_section_start`` pytest plugin. Under ``--noconftest`` that plugin
    isn't loaded, so any log record emitted during a test crashes pytest's
    auto-attached ``LogCaptureHandler`` with ``KeyError: 'funcNamewithModule'``.

    Replace pytest's percent-style formatter with a plain ``%(message)s``
    formatter for the duration of every test so emitted warnings don't blow
    up unrelated tests."""
    try:
        import _pytest.logging as _pylog
    except ImportError:  # pragma: no cover - pytest internals always present
        return
    plain = logging.Formatter("%(message)s")
    monkeypatch.setattr(
        _pylog.PercentStyleMultiline, "format",
        lambda self, record: plain.format(record),
    )


# --------------------------------------------------------------------------- #
# dash_table_name
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key,expected", [
    ("DASH_APPLIANCE_TABLE", "APPLIANCE"),
    ("DASH_APPLIANCE_TABLE:100", "APPLIANCE"),
    ("DASH_VNET_TABLE:Vnet1", "VNET"),
    ("DASH_VNET_MAPPING_TABLE:Vnet1:10.2.0.100", "VNET_MAPPING"),
    ("DASH_ENI_TABLE:497f23d7-f0ac-4c99-a98f-59b470e8c7bd", "ENI"),
    ("DASH_ENI_ROUTE_TABLE:eni-id", "ENI_ROUTE"),
    ("DASH_ROUTING_TYPE_TABLE:privatelink", "ROUTING_TYPE"),
    ("DASH_OUTBOUND_PORT_MAP_TABLE:portmap_1", "OUTBOUND_PORT_MAP"),
    ("DASH_OUTBOUND_PORT_MAP_RANGE_TABLE:portmap_1:8001-9000",
     "OUTBOUND_PORT_MAP_RANGE"),
    ("DASH_ROUTE_RULE_TABLE:eni:100:1.2.3.4/32", "ROUTE_RULE"),
])
def test_dash_table_name_parses_real_keys(dash_utils, key, expected):
    assert dash_utils.dash_table_name(key) == expected


@pytest.mark.parametrize("bad_key", [
    "",
    "FOO",
    "VNET_TABLE:x",                  # missing DASH_ prefix
    "DASH_VNET:foo",                 # missing _TABLE suffix
    "dash_vnet_table:foo",           # wrong case
    "PREFIX_DASH_VNET_TABLE:foo",    # DASH_ not at start
])
def test_dash_table_name_rejects_non_dash_keys(dash_utils, bad_key):
    with pytest.raises(ValueError):
        dash_utils.dash_table_name(bad_key)


# --------------------------------------------------------------------------- #
# bucket_dash_configs
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Canonical phase assignment for every known DASH table. Pinning these in a
# data-driven test makes accidental registry edits visible.
# --------------------------------------------------------------------------- #

_EXPECTED_TABLE_PHASES = {
    "APPLIANCE":               "GROUP_1",
    "ROUTING_TYPE":            "GROUP_2",
    "METER_POLICY":            "GROUP_2",
    "OUTBOUND_PORT_MAP":       "GROUP_2",
    "VNET":                    "GROUP_2",
    "METER_RULE":              "GROUP_3",
    "TUNNEL":                  "GROUP_4",
    "OUTBOUND_PORT_MAP_RANGE": "GROUP_4",
    "ENI":                     "GROUP_4",
    "ROUTE_GROUP":             "GROUP_4",
    "ROUTE_RULE":              "GROUP_5",
    "ROUTE":                   "GROUP_5",
    "VNET_MAPPING":            "GROUP_5",
    "ENI_ROUTE":               "GROUP_6",
}


def test_registry_contains_all_known_tables_with_expected_phases(dash_utils):
    actual = {tbl: phase.name
              for tbl, phase in dash_utils.DASH_TABLE_PHASE.items()}
    assert actual == _EXPECTED_TABLE_PHASES


@pytest.mark.parametrize("table,phase_name", sorted(_EXPECTED_TABLE_PHASES.items()))
def test_each_table_buckets_into_its_canonical_phase(dash_utils, table, phase_name):
    cfg = {"DASH_{}_TABLE:k".format(table): {"v": 1}}
    buckets = dash_utils.bucket_dash_configs(cfg)
    assert len(buckets) == 1
    phase, _ = buckets[0]
    assert phase.name == phase_name, (
        "{} expected in phase {} but landed in {}".format(
            table, phase_name, phase.name))


def test_bucket_groups_by_phase_and_sorts_ascending(dash_utils):
    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    vnet = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}
    eni_route = {"DASH_ENI_ROUTE_TABLE:eni-id": {"group_id": "rg1"}}

    # Pass them out of order to confirm the helper sorts.
    buckets = dash_utils.bucket_dash_configs(eni_route, vnet, appliance, eni)

    phases = [p for p, _ in buckets]
    assert phases == sorted(phases)
    phase_names = [p.name for p in phases]
    # APPLIANCE first (GROUP_1); VNET in GROUP_2; ENI in GROUP_4; ENI_ROUTE in GROUP_6.
    assert phase_names == ["GROUP_1", "GROUP_2", "GROUP_4", "GROUP_6"]


def test_bucket_merges_same_phase_dicts_into_one_batch(dash_utils):
    # TUNNEL, OUTBOUND_PORT_MAP_RANGE, ENI, ROUTE_GROUP all live in GROUP_4.
    tunnel = {"DASH_TUNNEL_TABLE:T1": {"vni": 100}}
    port_map_range = {"DASH_OUTBOUND_PORT_MAP_RANGE_TABLE:pm1:8001-9000": {}}
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}
    route_group = {"DASH_ROUTE_GROUP_TABLE:rg1": {"guid": "g"}}

    buckets = dash_utils.bucket_dash_configs(
        tunnel, port_map_range, eni, route_group)
    assert len(buckets) == 1
    phase, merged = buckets[0]
    assert phase == dash_utils.DashPhase.GROUP_4
    assert set(merged) == {
        "DASH_TUNNEL_TABLE:T1",
        "DASH_OUTBOUND_PORT_MAP_RANGE_TABLE:pm1:8001-9000",
        "DASH_ENI_TABLE:eni-id",
        "DASH_ROUTE_GROUP_TABLE:rg1",
    }


def test_bucket_empty_input_returns_empty_list(dash_utils):
    assert dash_utils.bucket_dash_configs() == []
    assert dash_utils.bucket_dash_configs({}, {}) == []


def test_bucket_warns_on_conflicting_duplicate_key(dash_utils, caplog):
    a = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    b = {"DASH_VNET_TABLE:Vnet1": {"vni": 9999}}  # same key, different value
    with caplog.at_level(logging.WARNING, logger=dash_utils.logger.name):
        buckets = dash_utils.bucket_dash_configs(a, b)
    # Later value wins (matches {**a, **b} semantics).
    _, merged = buckets[0]
    assert merged["DASH_VNET_TABLE:Vnet1"] == {"vni": 9999}
    assert any("Duplicate DASH key" in r.message for r in caplog.records)


def test_bucket_does_not_warn_on_identical_duplicate(dash_utils, caplog):
    a = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    b = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    with caplog.at_level(logging.WARNING, logger=dash_utils.logger.name):
        dash_utils.bucket_dash_configs(a, b)
    assert not any("Duplicate DASH key" in r.message for r in caplog.records)


def test_bucket_unknown_table_falls_back_to_default_phase_with_warning(
        dash_utils, caplog):
    cfg = {"DASH_FUTURE_NEW_TABLE:x": {"foo": "bar"}}
    with caplog.at_level(logging.WARNING, logger=dash_utils.logger.name):
        buckets = dash_utils.bucket_dash_configs(cfg)
    assert len(buckets) == 1
    phase, _ = buckets[0]
    assert phase == dash_utils.DEFAULT_DASH_PHASE
    assert any("Unknown DASH table" in r.message for r in caplog.records)


def test_bucket_rejects_non_dash_key(dash_utils):
    with pytest.raises(ValueError):
        dash_utils.bucket_dash_configs({"not_a_dash_key": {}})


# --------------------------------------------------------------------------- #
# apply_dash_configs
# --------------------------------------------------------------------------- #

def _fake_apply_fn():
    """Return a MagicMock that records each apply call's keys + set_db flag."""
    return MagicMock()


def _apply_call_table_summary(dash_utils, call):
    """Pull out (set_db, sorted list of DASH table names) from a fake call."""
    args = call.args
    # apply_fn(localhost, duthost, ptfhost, messages, dpu_index, set_db=..., ...)
    messages = args[3]
    set_db = call.kwargs.get("set_db", True)
    tables = sorted({dash_utils.dash_table_name(k) for k in messages})
    return set_db, tables


def test_apply_calls_apply_fn_in_phase_order_for_set(dash_utils):
    fake = _fake_apply_fn()
    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    vnet = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}
    eni_route = {"DASH_ENI_ROUTE_TABLE:eni-id": {"group_id": "rg1"}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0,
        eni_route, vnet, appliance, eni,   # out of order
        apply_fn=fake,
    )

    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    # APPLIANCE (GROUP_1), VNET (GROUP_2), ENI (GROUP_4), ENI_ROUTE (GROUP_6).
    assert summaries == [
        (True, ["APPLIANCE"]),
        (True, ["VNET"]),
        (True, ["ENI"]),
        (True, ["ENI_ROUTE"]),
    ]


def test_apply_reverses_order_for_set_db_false(dash_utils):
    fake = _fake_apply_fn()
    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}
    eni_route = {"DASH_ENI_ROUTE_TABLE:eni-id": {"group_id": "rg1"}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0,
        appliance, eni, eni_route,
        set_db=False,
        apply_fn=fake,
    )

    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    # On delete we tear down dependents first.
    assert summaries == [
        (False, ["ENI_ROUTE"]),
        (False, ["ENI"]),
        (False, ["APPLIANCE"]),
    ]


def test_apply_merges_same_phase_into_single_call(dash_utils):
    fake = _fake_apply_fn()
    vnet = {"DASH_VNET_TABLE:Vnet1": {"vni": 1000}}
    meter_policy = {"DASH_METER_POLICY_TABLE:MP": {"ip_version": "v4"}}
    port_map = {"DASH_OUTBOUND_PORT_MAP_TABLE:pm1": {}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0, vnet, meter_policy, port_map, apply_fn=fake,
    )
    # All three are in GROUP_2, so a single apply call.
    assert fake.call_count == 1
    _, tables = _apply_call_table_summary(dash_utils, fake.call_args_list[0])
    assert tables == ["METER_POLICY", "OUTBOUND_PORT_MAP", "VNET"]


def test_apply_meter_policy_before_meter_rule(dash_utils):
    """METER_RULE references METER_POLICY by name; METER_POLICY lands in
    GROUP_2 and METER_RULE in GROUP_3 (between GROUP_2 and GROUP_4) so
    meter rules are programmed after their parent policy but before any
    ENI binds to that policy."""
    fake = _fake_apply_fn()
    policy = {"DASH_METER_POLICY_TABLE:MP": {"ip_version": "v4"}}
    rule = {"DASH_METER_RULE_TABLE:MP:1": {"priority": 0}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0, rule, policy, apply_fn=fake)
    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    assert summaries == [(True, ["METER_POLICY"]), (True, ["METER_RULE"])]


def test_apply_meter_rule_before_eni(dash_utils):
    """METER_RULE must land before ENI so meter rules are present before
    any ENI binds to their parent METER_POLICY."""
    fake = _fake_apply_fn()
    rule = {"DASH_METER_RULE_TABLE:MP:1": {"priority": 0}}
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0, eni, rule, apply_fn=fake)
    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    assert summaries == [(True, ["METER_RULE"]), (True, ["ENI"])]


def test_apply_port_map_before_port_map_range(dash_utils):
    """OUTBOUND_PORT_MAP_RANGE references OUTBOUND_PORT_MAP by name;
    OUTBOUND_PORT_MAP lands in GROUP_2 and the RANGE in GROUP_4."""
    fake = _fake_apply_fn()
    port_map = {"DASH_OUTBOUND_PORT_MAP_TABLE:pm1": {}}
    port_map_range = {"DASH_OUTBOUND_PORT_MAP_RANGE_TABLE:pm1:8001-9000": {}}

    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0, port_map_range, port_map, apply_fn=fake)
    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    assert summaries == [
        (True, ["OUTBOUND_PORT_MAP"]),
        (True, ["OUTBOUND_PORT_MAP_RANGE"]),
    ]


def test_apply_eni_before_route_rule(dash_utils):
    """Under the canonical phase ordering ENI lands in GROUP_4 and
    ROUTE_RULE in GROUP_5, so ROUTE_RULE is applied after ENI exists."""
    fake = _fake_apply_fn()
    eni = {"DASH_ENI_TABLE:eni-id": {"vnet": "Vnet1"}}
    rule = {"DASH_ROUTE_RULE_TABLE:eni-id:100:1.2.3.4/32": {"priority": 0}}

    dash_utils.apply_dash_configs("lh", "dh", "ph", 0, eni, rule, apply_fn=fake)
    summaries = [_apply_call_table_summary(dash_utils, c)
                 for c in fake.call_args_list]
    assert summaries == [(True, ["ENI"]), (True, ["ROUTE_RULE"])]


def test_apply_with_no_configs_is_noop(dash_utils):
    fake = _fake_apply_fn()
    dash_utils.apply_dash_configs("lh", "dh", "ph", 0, apply_fn=fake)
    dash_utils.apply_dash_configs("lh", "dh", "ph", 0, {}, {}, apply_fn=fake)
    fake.assert_not_called()


def test_apply_skips_falsy_input_dicts(dash_utils):
    """Callers use patterns like ``*(extra if cond else [])`` which may yield
    nothing; we should silently ignore empty dicts."""
    fake = _fake_apply_fn()
    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0, appliance, {}, apply_fn=fake,
    )
    assert fake.call_count == 1


def test_apply_forwards_dpu_index_and_wait_kwargs(dash_utils):
    fake = _fake_apply_fn()
    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 7, appliance,
        wait_after_apply=12, max_updates_in_single_cmd=64,
        apply_fn=fake,
    )
    call = fake.call_args_list[0]
    # Positional args: localhost, duthost, ptfhost, messages, dpu_index
    assert call.args[:3] == ("lh", "dh", "ph")
    assert call.args[4] == 7
    assert call.kwargs["wait_after_apply"] == 12
    assert call.kwargs["max_updates_in_single_cmd"] == 64
    assert call.kwargs["set_db"] is True


def test_apply_default_apply_fn_lazy_import(dash_utils, monkeypatch):
    """When ``apply_fn`` is not provided, the helper should lazy-import
    ``gnmi_utils.apply_messages``. We stub that module to confirm it gets
    called with the expected positional + keyword arguments."""
    recorded = {}

    def fake_apply_messages(localhost, duthost, ptfhost, messages, dpu_index,
                            set_db=True, wait_after_apply=5,
                            max_updates_in_single_cmd=1024):
        recorded["args"] = (localhost, duthost, ptfhost, messages, dpu_index)
        recorded["kwargs"] = {
            "set_db": set_db,
            "wait_after_apply": wait_after_apply,
            "max_updates_in_single_cmd": max_updates_in_single_cmd,
        }

    gnmi_stub = types.ModuleType("gnmi_utils")
    gnmi_stub.apply_messages = fake_apply_messages
    monkeypatch.setitem(sys.modules, "gnmi_utils", gnmi_stub)

    appliance = {"DASH_APPLIANCE_TABLE:100": {"sip": "10.1.0.5"}}
    dash_utils.apply_dash_configs("lh", "dh", "ph", 0, appliance)

    assert recorded["args"][:3] == ("lh", "dh", "ph")
    assert recorded["args"][4] == 0
    assert recorded["kwargs"]["set_db"] is True


# --------------------------------------------------------------------------- #
# End-to-end check: the canonical phase ordering must split a representative
# fixture's configs into exactly these gNMI batches (using the
# ``test_fnic_basic.py``-style config bundle, which omits METER_RULE):
#   1. GROUP_1 — APPLIANCE
#   2. GROUP_2 — VNET, ROUTING_TYPE, METER_POLICY
#   4. GROUP_4 — TUNNEL, ENI, ROUTE_GROUP, OUTBOUND_PORT_MAP*
#   5. GROUP_5 — ROUTE_RULE, ROUTE, VNET_MAPPING
#   6. GROUP_6 — ENI_ROUTE
# (GROUP_3 / METER_RULE is empty here; fixtures that push METER_RULE
# produce 6 batches.)
# Sentinel configs below share only the DASH table-name part of each
# privatelink_config.py dict; values are placeholders.
# --------------------------------------------------------------------------- #

_SENTINEL = {
    "APPLIANCE_FNIC_CONFIG":      {"DASH_APPLIANCE_TABLE:100": {"k": "appl"}},
    "ROUTING_TYPE_PL_CONFIG":     {"DASH_ROUTING_TYPE_TABLE:privatelink": {"k": "rtpl"}},
    "ROUTING_TYPE_VNET_CONFIG":   {"DASH_ROUTING_TYPE_TABLE:vnet": {"k": "rtvnet"}},
    "VNET_CONFIG":                {"DASH_VNET_TABLE:Vnet1": {"k": "vnet"}},
    "ROUTE_GROUP1_CONFIG":        {"DASH_ROUTE_GROUP_TABLE:RG1": {"k": "rg"}},
    "METER_POLICY_V4_CONFIG":     {"DASH_METER_POLICY_TABLE:MP": {"k": "mp"}},
    "PE_VNET_MAPPING_CONFIG":     {"DASH_VNET_MAPPING_TABLE:Vnet1:10.2.0.100": {"k": "pe"}},
    "PE_SUBNET_ROUTE_CONFIG":     {"DASH_ROUTE_TABLE:RG1:10.2.0.0/16": {"k": "rpe"}},
    "VM_VNET_MAPPING_CONFIG":     {"DASH_VNET_MAPPING_TABLE:Vnet1:10.0.0.11": {"k": "vm"}},
    "VM_SUBNET_ROUTE_CONFIG":     {"DASH_ROUTE_TABLE:RG1:10.0.0.0/16": {"k": "rvm"}},
    "VM_VNI_ROUTE_RULE_CONFIG":   {"DASH_ROUTE_RULE_TABLE:eni:2001:vm/32": {"k": "rrvm"}},
    "INBOUND_VNI_ROUTE_RULE_CONFIG": {"DASH_ROUTE_RULE_TABLE:eni:100:pe/32": {"k": "rrin"}},
    "TRUSTED_VNI_ROUTE_RULE_CONFIG": {"DASH_ROUTE_RULE_TABLE:eni:800:vm/32": {"k": "rrtr"}},
    "ENI_FNIC_PL_CONFIG":         {"DASH_ENI_TABLE:eni-id": {"k": "enipl"}},
    "ENI_FNIC_CONFIG":            {"DASH_ENI_TABLE:eni-id": {"k": "enifn"}},
    "ENI_ROUTE_GROUP1_CONFIG":    {"DASH_ENI_ROUTE_TABLE:eni-id": {"k": "enirg"}},
}


def _migrated_test_fnic_basic_batches(dash_utils, is_pensando):
    """Run the migrated fixture's apply_dash_configs invocation through a
    fake apply_fn and return the captured merged messages per call."""
    s = _SENTINEL
    route_rule_configs = []
    if not is_pensando:
        route_rule_configs = [
            s["VM_VNI_ROUTE_RULE_CONFIG"],
            s["INBOUND_VNI_ROUTE_RULE_CONFIG"],
            s["TRUSTED_VNI_ROUTE_RULE_CONFIG"],
        ]
    fake = _fake_apply_fn()
    dash_utils.apply_dash_configs(
        "lh", "dh", "ph", 0,
        s["APPLIANCE_FNIC_CONFIG"],
        s["ROUTING_TYPE_PL_CONFIG"],
        s["ROUTING_TYPE_VNET_CONFIG"],
        s["VNET_CONFIG"],
        s["ROUTE_GROUP1_CONFIG"],
        s["METER_POLICY_V4_CONFIG"],
        s["PE_VNET_MAPPING_CONFIG"],
        s["PE_SUBNET_ROUTE_CONFIG"],
        s["VM_VNET_MAPPING_CONFIG"],
        s["VM_SUBNET_ROUTE_CONFIG"],
        *route_rule_configs,
        s["ENI_FNIC_PL_CONFIG"],
        s["ENI_ROUTE_GROUP1_CONFIG"],
        apply_fn=fake,
    )
    return [c.args[3] for c in fake.call_args_list]


def _expected_test_fnic_basic_batches(is_pensando):
    """The canonical phase ordering should yield exactly these batches for
    the migrated ``test_fnic_basic.py`` setup."""
    s = _SENTINEL
    routes_batch = {
        **s["PE_VNET_MAPPING_CONFIG"],
        **s["PE_SUBNET_ROUTE_CONFIG"],
        **s["VM_VNET_MAPPING_CONFIG"],
        **s["VM_SUBNET_ROUTE_CONFIG"],
    }
    if not is_pensando:
        routes_batch.update(s["VM_VNI_ROUTE_RULE_CONFIG"])
        routes_batch.update(s["INBOUND_VNI_ROUTE_RULE_CONFIG"])
        routes_batch.update(s["TRUSTED_VNI_ROUTE_RULE_CONFIG"])
    return [
        # GROUP_1: APPLIANCE
        dict(s["APPLIANCE_FNIC_CONFIG"]),
        # GROUP_2: VNET + ROUTING_TYPE + METER_POLICY
        {**s["ROUTING_TYPE_PL_CONFIG"], **s["ROUTING_TYPE_VNET_CONFIG"],
         **s["VNET_CONFIG"], **s["METER_POLICY_V4_CONFIG"]},
        # GROUP_4: ROUTE_GROUP + ENI (GROUP_3 is empty — no METER_RULE here)
        {**s["ROUTE_GROUP1_CONFIG"], **s["ENI_FNIC_PL_CONFIG"]},
        # GROUP_5: ROUTES (+ ROUTE_RULE on non-Pensando)
        routes_batch,
        # GROUP_6: ENI_ROUTE
        dict(s["ENI_ROUTE_GROUP1_CONFIG"]),
    ]


@pytest.mark.parametrize("is_pensando", [False, True],
                         ids=["non-pensando", "pensando"])
def test_pilot_migration_matches_expected_phase_batches(
        dash_utils, is_pensando):
    """The migrated ``test_fnic_basic.py`` setup should produce exactly the
    5 phase-bucketed batches defined above."""
    expected = _expected_test_fnic_basic_batches(is_pensando)
    actual = _migrated_test_fnic_basic_batches(dash_utils, is_pensando)

    assert len(actual) == len(expected), (
        "batch count differs: actual={}, expected={}".format(
            len(actual), len(expected)))
    for i, (act, exp) in enumerate(zip(actual, expected)):
        assert set(act) == set(exp), (
            "batch {} key sets differ:\n  actual only: {}\n  expected only: {}"
            .format(i, set(act) - set(exp), set(exp) - set(act)))
