"""Readiness requires actual link, named APPL profile and matching applied ASIC attributes."""

import fnmatch
import importlib
import json
from pathlib import Path
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "library"))
health = importlib.import_module("generic_hwsku_health")


class Database:
    def __init__(self, values):
        self.values = values

    def get_all(self, database, key):
        return self.values.get((database, key))

    def keys(self, database, pattern):
        return [key for db, key in self.values if db == database and fnmatch.fnmatch(key, pattern)]


def _ready(tmp_path):
    (tmp_path / "Ethernet0").mkdir()
    (tmp_path / "Ethernet0" / "carrier").write_text("1")
    request = {
        "ports": ["Ethernet0"], "pg": {"Ethernet0": {"3": {"selector": "3", "profile": "NULL"}}},
        "queues": {"Ethernet0": {"0": {"selector": "0", "profile": "egress-profile"}}},
        "profiles": {"egress-profile": {"size": "0", "pool": "egress-pool", "dynamic_th": "3"}},
        "pools": {"ingress-pool": {"size": "10000", "type": "ingress", "mode": "dynamic"},
                  "egress-pool": {"size": "20000", "type": "egress", "mode": "dynamic"}},
        "qos": {"Ethernet0": {"tc_to_queue_map": "default", "pfc_enable": ""}},
        "qos_maps": {"TC_TO_QUEUE_MAP": {"default": {"0": "0", "1": "1"}}},
        "pfc_asym": {"Ethernet0": "off"},
    }
    values = {
        ("COUNTERS_DB", "COUNTERS_PORT_NAME_MAP"): {"Ethernet0": "oid:port"},
        ("COUNTERS_DB", "COUNTERS_PG_NAME_MAP"): {"Ethernet0:3": "oid:pg"},
        ("COUNTERS_DB", "COUNTERS_PG_PORT_MAP"): {"oid:pg": "oid:port"},
        ("COUNTERS_DB", "COUNTERS_PG_INDEX_MAP"): {"oid:pg": "3"},
        ("COUNTERS_DB", "COUNTERS_QUEUE_NAME_MAP"): {"Ethernet0:0": "oid:queue"},
        ("COUNTERS_DB", "COUNTERS_QUEUE_PORT_MAP"): {"oid:queue": "oid:port"},
        ("COUNTERS_DB", "COUNTERS_QUEUE_INDEX_MAP"): {"oid:queue": "0"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:oid:pg"): {
            "NULL": "NULL",
            "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE": "oid:ingress-profile"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:oid:queue"): {
            "NULL": "NULL", "SAI_QUEUE_ATTR_INDEX": "0",
            "SAI_QUEUE_ATTR_BUFFER_PROFILE_ID": "oid:egress-profile"},
        ("APPL_DB", "BUFFER_PG_TABLE:Ethernet0:3"): {"profile": "dynamic-profile"},
        ("APPL_DB", "BUFFER_QUEUE_TABLE:Ethernet0:0"): {"profile": "egress-profile"},
        ("APPL_DB", "BUFFER_PROFILE_TABLE:dynamic-profile"): {
            "pool": "ingress-pool", "size": "100", "xon": "20", "xoff": "80", "dynamic_th": "1"},
        ("APPL_DB", "BUFFER_PROFILE_TABLE:egress-profile"): {
            "pool": "egress-pool", "size": "0", "dynamic_th": "3"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:ingress-profile"): {
            "SAI_BUFFER_PROFILE_ATTR_POOL_ID": "oid:ingress-pool",
            "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": "100", "SAI_BUFFER_PROFILE_ATTR_XON_TH": "20",
            "SAI_BUFFER_PROFILE_ATTR_XOFF_TH": "80", "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": "1"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:egress-profile"): {
            "SAI_BUFFER_PROFILE_ATTR_POOL_ID": "oid:egress-pool",
            "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": "0", "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": "3"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:port"): {"SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP": "oid:qos"},
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:qos"): {
            "SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_TC_TO_QUEUE",
            "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": json.dumps({
                "count": 2, "list": [
                    {"key": {"tc": 1}, "value": {"qidx": 1}},
                    {"key": {"tc": 0}, "value": {"qidx": 0}}]})},
    }
    for direction, size in (("ingress", "10000"), ("egress", "20000")):
        values[("APPL_DB", "BUFFER_POOL_TABLE:" + direction + "-pool")] = {
            "size": size, "type": direction, "mode": "dynamic"}
        values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:oid:" + direction + "-pool")] = {
            "SAI_BUFFER_POOL_ATTR_SIZE": size, "SAI_BUFFER_POOL_ATTR_TYPE": "SAI_BUFFER_POOL_TYPE_" + direction.upper(),
            "SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE": "SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC"}
    return request, Database(values)


def test_ready_requires_matching_applied_buffers_and_qos(tmp_path):
    request, database = _ready(tmp_path)
    observed = health.check(request, database, tmp_path)
    assert observed["ready"] and observed["applied_buffer_bindings"] == 2


def test_stale_counter_and_buffer_objects_cannot_replace_the_actual_asic_port(tmp_path):
    request, database = _ready(tmp_path)
    request["qos"]["Ethernet0"] = {"pfc_enable": ""}
    del database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:port")]
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"]
    assert any("ASIC port object" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("change", ["wrong-type", "wrong-entry", "wrong-count", "duplicate", "malformed", "unfrozen"])
def test_applied_qos_map_must_match_the_frozen_type_and_entries(tmp_path, change):
    request, database = _ready(tmp_path)
    row = database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:qos")]
    entries = json.loads(row["SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"])
    if change == "wrong-type":
        row["SAI_QOS_MAP_ATTR_TYPE"] = "SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP"
    elif change == "wrong-entry":
        entries["list"][0]["value"]["qidx"] = 7
    elif change == "wrong-count":
        entries["count"] = 1
    elif change == "duplicate":
        entries["list"][0] = entries["list"][1]
    elif change == "unfrozen":
        request["qos_maps"]["TC_TO_QUEUE_MAP"].clear()
    row["SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"] = "not-json" if change == "malformed" else json.dumps(entries)
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"]
    assert any("tc_to_queue_map" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("configured,asymmetric,attributes,ready", [
    ("", "off", {}, True),
    ("", "off", {"": "8"}, False),
    ("3,4", "off", {"": "24"}, True),
    ("3,4", "off", {"": "16"}, False),
    ("", "off", {"": "invalid"}, False),
    ("", "off", {"_MODE": "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE", "_TX": "0", "_RX": "255"}, False),
    ("3,4", "on", {"_MODE": "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE", "_TX": "24", "_RX": "255"}, True),
    ("3,4", "on", {"_MODE": "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE", "_TX": "24", "_RX": "0"}, False),
])
def test_applied_pfc_bitmap_and_mode_must_match_frozen_policy(tmp_path, configured, asymmetric, attributes, ready):
    request, database = _ready(tmp_path)
    request["qos"]["Ethernet0"]["pfc_enable"] = configured
    request["pfc_asym"]["Ethernet0"] = asymmetric
    database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:port")].update({
        "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL" + suffix: value for suffix, value in attributes.items()})
    observed = health.check(request, database, tmp_path)
    assert observed["ready"] is ready
    if not ready:
        assert any("PFC" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("change", ["missing-name", "wrong-port", "wrong-index", "missing-asic"])
def test_counter_identity_never_substitutes_for_the_matching_applied_asic_object(tmp_path, change):
    request, database = _ready(tmp_path)
    if change == "missing-name":
        del database.values[("COUNTERS_DB", "COUNTERS_PG_NAME_MAP")]["Ethernet0:3"]
    elif change == "wrong-port":
        database.values[("COUNTERS_DB", "COUNTERS_PG_PORT_MAP")]["oid:pg"] = "oid:other-port"
    elif change == "wrong-index":
        database.values[("COUNTERS_DB", "COUNTERS_PG_INDEX_MAP")]["oid:pg"] = "4"
    else:
        del database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:oid:pg")]
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"]
    assert any("INGRESS_PRIORITY_GROUP 3" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("applied,color", [
    (False, "SAI_PACKET_COLOR_GREEN"), (True, "SAI_PACKET_COLOR_GREEN"), (True, "SAI_PACKET_COLOR_RED")])
def test_tc_to_dscp_requires_the_applied_asic_port_binding(tmp_path, applied, color):
    request, database = _ready(tmp_path)
    request["qos"]["Ethernet0"]["tc_to_dscp_map"] = "AZURE"
    request["qos_maps"]["TC_TO_DSCP_MAP"] = {"AZURE": {"0": "16"}}
    if applied:
        database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:port")][
            "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP"] = "oid:dscp"
        database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:dscp")] = {
            "SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP",
            "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": json.dumps({
                "count": 1, "list": [{"key": {"tc": 0, "color": color},
                                     "value": {"dscp": 16}}]})}
    observed = health.check(request, database, tmp_path)
    assert observed["ready"] is (applied and color == "SAI_PACKET_COLOR_GREEN")
    if not applied:
        assert any("tc_to_dscp_map" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("limit, ready", [(99, False), (100, True)])
def test_applied_reservations_cannot_exceed_reclaimed_baseline_budget(tmp_path, limit, ready):
    request, database = _ready(tmp_path)
    request["headroom_limit"] = limit
    observed = health.check(request, database, tmp_path)
    assert observed["ready"] is ready
    assert observed["reserved_headroom"] == 100
    if not ready:
        assert any("frozen reclaimed headroom budget" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("port", ["old-child", "inactive-child"])
def test_reclaimed_budget_includes_residual_and_inactive_children_not_only_live_links(tmp_path, port):
    request, database = _ready(tmp_path)
    request.update(headroom_limit=100, headroom_ports=["Ethernet0", port])
    database.values[("APPL_DB", "BUFFER_PG_TABLE:" + port + ":3-4")] = {"profile": "dynamic-profile"}
    database.values[("APPL_DB", "BUFFER_PG_TABLE:unrelated-port:3-4")] = {"profile": "dynamic-profile"}
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"] and observed["reserved_headroom"] == 300
    assert any("frozen reclaimed headroom budget" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("change", ["missing-xon", "missing-xoff", "invalid-xon", "missing-pool"])
def test_unresolved_residual_lossless_pg_cannot_disappear_from_the_budget(tmp_path, change):
    request, database = _ready(tmp_path)
    request.update(headroom_limit=100, headroom_ports=["Ethernet0", "old-child"])
    profile = {"pool": "ingress-pool", "size": "0", "xon": "20", "xoff": "80"}
    if change == "missing-xon":
        del profile["xon"]
    elif change == "missing-xoff":
        del profile["xoff"]
    elif change == "invalid-xon":
        profile["xon"] = "unknown"
    else:
        del profile["pool"]
    database.values[("APPL_DB", "BUFFER_PG_TABLE:old-child:3")] = {"profile": "residual-profile"}
    database.values[("APPL_DB", "BUFFER_PROFILE_TABLE:residual-profile")] = profile
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"]
    assert any("old-child" in error and "unresolved" in error for error in observed["blocking_errors"])


@pytest.mark.parametrize("change", [
    "link-down", "wrong-asic-size", "stale-app-profile", "missing-qos", "missing-headroom"])
def test_configured_but_unconverged_resources_are_not_ready(tmp_path, change):
    request, database = _ready(tmp_path)
    if change == "link-down":
        (tmp_path / "Ethernet0" / "carrier").write_text("0")
    elif change == "wrong-asic-size":
        database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:oid:ingress-profile")][
            "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE"] = "99"
    elif change == "stale-app-profile":
        database.values[("APPL_DB", "BUFFER_QUEUE_TABLE:Ethernet0:0")]["profile"] = "stale-profile"
    elif change == "missing-qos":
        del database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:qos")]
    else:
        del database.values[("APPL_DB", "BUFFER_PROFILE_TABLE:dynamic-profile")]["xoff"]
    observed = health.check(request, database, tmp_path)
    assert not observed["ready"] and observed["blocking_errors"]


def test_overlapping_pg_profiles_are_rejected():
    config = {"BUFFER_PG": {"Ethernet0|3-4": {"profile": "one"}, "Ethernet0|4": {"profile": "two"}}}
    with pytest.raises(ValueError, match="Overlapping"):
        health.port_bindings(config, "BUFFER_PG", "Ethernet0")
