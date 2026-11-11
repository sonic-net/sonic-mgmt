"""Readiness requires actual link, named APPL profile and matching applied ASIC attributes."""

import fnmatch
import importlib
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
        "qos": {"Ethernet0": {"tc_to_queue_map": "default"}},
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
        ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:qos"): {"SAI_QOS_MAP_ATTR_TYPE": "TC_TO_QUEUE"},
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


@pytest.mark.parametrize("applied", [False, True])
def test_tc_to_dscp_requires_the_applied_asic_port_binding(tmp_path, applied):
    request, database = _ready(tmp_path)
    request["qos"]["Ethernet0"]["tc_to_dscp_map"] = "AZURE"
    if applied:
        database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:port")][
            "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP"] = "oid:dscp"
        database.values[("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:dscp")] = {
            "SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP"}
    observed = health.check(request, database, tmp_path)
    assert observed["ready"] is applied
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
