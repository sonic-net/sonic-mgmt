"""Offline tests of the live collector's canonical-parser boundary and private artifacts."""

import importlib.util
import json
import os
import sys
from types import SimpleNamespace

import pytest


_PATH = os.path.join(os.path.dirname(__file__), "..", "library", "generic_hwsku_device_facts.py")
_SPEC = importlib.util.spec_from_file_location("generic_hwsku_device_facts", _PATH)
facts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(facts)


class Entry:
    def __init__(self):
        self.supported_speed = {100000, 50000}
        self.default_speed = 100000


class CanonicalParser:
    class BreakoutCfg:
        def __init__(self, cage, mode, properties):
            self._breakout_mode_entry = [Entry()]

        def get_config(self):
            speed = self._breakout_mode_entry[0].default_speed
            return {"Ethernet7": {"alias": "actual-canonical-alias", "lanes": "9,3", "index": "11",
                                  "speed": str(speed), "subport": "2"}}


def test_collector_uses_canonical_lanes_names_aliases_and_alternate_speeds():
    """Preserve parser output rather than reconstructing ports from interface numbering."""
    platform = {"interfaces": {"Ethernet7": {"breakout_modes": {"opaque-parser-owned-mode": ["ignored"]}}}}
    variants = facts.canonical_expansions(platform, CanonicalParser)["Ethernet7"]
    assert {variant["ports"]["Ethernet7"]["speed"] for variant in variants} == {"50000", "100000"}
    for variant in variants:
        port = variant["ports"]["Ethernet7"]
        assert port["lanes"] == "9,3"
        assert port["alias"] == "actual-canonical-alias"
        assert port["index"] == "11" and port["subport"] == "2"
    assert len({variant["id"] for variant in variants}) == 2


def test_unknown_parser_contract_fails_instead_of_guessing():
    """A missing installed speed API must not silently collapse alternate capabilities."""
    class UnsupportedParser:
        class BreakoutCfg:
            def __init__(self, cage, mode, properties):
                self._breakout_mode_entry = [object()]

    platform = {"interfaces": {"Ethernet7": {"breakout_modes": {"opaque": []}}}}
    with pytest.raises(facts.FactsError, match="supported-speed contract"):
        facts.canonical_expansions(platform, UnsupportedParser)


@pytest.mark.parametrize("json_source", [False, True])
def test_base_mapping_explicitly_bypasses_running_config_and_records_all_installed_sources(tmp_path, json_source):
    port_file = tmp_path / ("platform.json" if json_source else "port_config.ini")
    port_file.write_text("installed-base-source", encoding="utf-8")
    hwsku_file = tmp_path / "hwsku.json"
    hwsku_file.write_text("installed-default-modes", encoding="utf-8")
    calls = []

    def read(**options):
        calls.append(options)
        assert options["port_config_file"] == str(port_file)
        return ({"Ethernet7": {"lanes": "9,3", "speed": "100000", "alias": "actual-base-alias"}}, {}, {})

    ports, sources = facts.canonical_baseline(
        SimpleNamespace(get_port_config=read), "platform", "base-hwsku", port_file,
        hwsku_file if json_source else None)
    assert ports["Ethernet7"]["lanes"] == "9,3"
    assert calls[0]["hwsku"] == "base-hwsku"
    assert ("hwsku_config_file" in calls[0]) == json_source
    assert set(sources) == ({"baseline_ports", "baseline_hwsku"} if json_source else {"baseline_ports"})
    assert sources["baseline_ports"]["sha256"] == facts.sha256(port_file.read_bytes())


def test_base_mapping_rejects_a_source_changed_during_the_canonical_parse(tmp_path):
    path = tmp_path / "port_config.ini"
    path.write_text("original", encoding="utf-8")

    def read(**options):
        path.write_text("concurrent-replacement", encoding="utf-8")
        return ({"Ethernet7": {"lanes": "9,3"}}, {}, {})

    with pytest.raises(facts.FactsError, match="changed during parsing"):
        facts.canonical_baseline(SimpleNamespace(get_port_config=read), "platform", "base", path)


def test_collection_records_effective_base_mapping_separately_from_running_ports(tmp_path, monkeypatch):
    platform = tmp_path / "platform"
    sku = platform / "base"
    sku.mkdir(parents=True)
    (platform / "platform.json").write_text(json.dumps({
        "interfaces": {"Ethernet7": {"breakout_modes": {"opaque-parser-owned-mode": []}}}}), encoding="utf-8")
    port_file = sku / "port_config.ini"
    port_file.write_text("installed-base-map", encoding="utf-8")
    parser_file = tmp_path / "parser.py"
    parser_file.write_text("installed-parser", encoding="utf-8")
    startup, version = tmp_path / "startup.json", tmp_path / "version.yml"
    startup.write_text("{}", encoding="utf-8")
    version.write_text("build_version: installed-image", encoding="utf-8")
    base = {"Ethernet7": {"lanes": "9,3", "speed": "100000"}}

    def read(**options):
        assert options["port_config_file"] == str(port_file)
        return base, {}, {}

    monkeypatch.setitem(sys.modules, "portconfig", SimpleNamespace(
        __file__=str(parser_file), BreakoutCfg=CanonicalParser.BreakoutCfg, get_port_config=read))
    monkeypatch.setitem(sys.modules, "sonic_py_common", SimpleNamespace(
        device_info=SimpleNamespace(get_path_to_port_config_file=lambda hwsku: str(port_file)),
        multi_asic=SimpleNamespace(get_num_asics=lambda: 1)))
    monkeypatch.setattr(facts, "_read_json_command", lambda *arguments: {
        "DEVICE_METADATA": {"localhost": {"platform": "platform", "hwsku": "base"}},
        "PORT": {"Ethernet7": {"lanes": "9", "speed": "50000"}}})
    monkeypatch.setattr(facts, "applied_buffers", lambda: {"pg": {}, "profiles": {}, "pools": {}})
    monkeypatch.setattr(facts, "transceiver_facts", lambda ports: {})
    observed = facts.collect(str(tmp_path), str(startup), str(version))
    assert observed["baseline_ports"] == base
    assert observed["running"]["PORT"] != base
    assert observed["sources"]["baseline_ports"]["sha256"] == facts.sha256(port_file.read_bytes())


def test_transceiver_collection_keeps_only_nonsecret_capability_evidence():
    module = {"type": "SFP/SFP+/SFP28", "nominal_bit_rate": "103",
              "specification_compliance": "{'10G Ethernet Compliance': '10GBASE-SR'}",
              "serial": "not-needed-for-planning"}
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda name, key: module)
    observed = facts.transceiver_facts(["actual-canonical-cage"], database)
    assert observed == {"actual-canonical-cage": {key: module[key] for key in (
        "type", "nominal_bit_rate", "specification_compliance")}}


def test_applied_resource_facts_read_exact_profile_bindings_and_reject_a_racing_snapshot():
    values = {
        "BUFFER_PG_TABLE:Ethernet0:3-4": {"profile": "active"},
        "BUFFER_PROFILE_TABLE:active": {"size": "100", "xon": "20", "xoff": "80"},
        "BUFFER_POOL_TABLE:ingress": {"size": "10000"},
        "BUFFER_MAX_PARAM_TABLE|global": {"mmu_size": "136209408"},
    }
    database = SimpleNamespace(
        connect=lambda name: None,
        keys=lambda name, pattern: [key for key in values if key.startswith(pattern[:-1])],
        get_all=lambda name, key: values[key])
    observed = facts.applied_buffers(database)
    assert observed["pg"] == {"Ethernet0:3-4": {"profile": "active"}}
    assert observed["profiles"]["active"]["size"] == "100"
    assert observed["mmu_size"] == "136209408"
    values["BUFFER_PROFILE_TABLE:active"] = None
    with pytest.raises(facts.FactsError, match="changed during collection"):
        facts.applied_buffers(database)


def test_collection_artifacts_are_exclusive_and_not_overwritten(tmp_path):
    """Existing private state must survive repeated or conflicting collector invocations."""
    destination = tmp_path / "facts.json"
    facts.write_private(destination, {"running": {"private": "original"}, "startup": "distinct-original"})
    assert json.loads(destination.read_text())["startup"] == "distinct-original"
    with pytest.raises(facts.FactsError, match="overwrite"):
        facts.write_private(destination, {"running": "replacement"})
    assert json.loads(destination.read_text())["running"] == {"private": "original"}


def test_host_collection_excludes_container_secrets_and_uses_actual_namespace(monkeypatch):
    """The host snapshot exposes transport facts, never container environment credentials."""
    path = os.path.join(os.path.dirname(_PATH), "generic_hwsku_host_facts.py")
    spec = importlib.util.spec_from_file_location("generic_hwsku_host_facts", path)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    calls = []

    def read(arguments):
        calls.append(arguments)
        if arguments[0] == "docker":
            return [{"Id": "baseline-container", "Image": "sha256:original-image", "Config": {"Image": "baseline-image",
                     "Env": ["PRIVATE_VALUE=must-not-be-exported"]}, "State": {"Running": True, "Pid": 37}}]
        return [{"ifname": "eth9", "linkinfo": {"info_kind": "vlan", "info_data": {"id": 4007}}}]

    monkeypatch.setattr(host, "_read", read)
    monkeypatch.setattr(host, "_container_ids", lambda container: ["baseline-container"])
    snapshot = host.collect("ptf_baseline", "bond0")
    assert "must-not-be-exported" not in json.dumps(snapshot)
    assert ["nsenter", "-t", "37", "-n", "ip", "-j", "-d", "link", "show"] in calls
    assert snapshot["ptf_links"][0]["linkinfo"]["info_data"]["id"] == 4007
