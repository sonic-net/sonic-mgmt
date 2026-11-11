"""Installed-template boundaries and actual, ownership-scoped native host readbacks."""

import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "library"))
host = importlib.import_module("generic_hwsku_host_action")
host_facts = importlib.import_module("generic_hwsku_host_facts")
render = importlib.import_module("generic_hwsku_render")


def test_native_media_source_guard_rejects_a_module_changed_after_planning():
    device = importlib.import_module("generic_hwsku_device_action")
    module = {"type": "SFP/SFP+/SFP28", "nominal_bit_rate": "103",
              "specification_compliance": "{'10G Ethernet Compliance': '10GBASE-SR'}"}
    expected = {"actual-canonical-cage": dict(module)}
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda name, key: module)
    device.verify_media_sources(expected, database)
    module["nominal_bit_rate"] = "255"
    with pytest.raises(device.DeviceActionError, match="transceiver changed"):
        device.verify_media_sources(expected, database)


def test_absent_original_ptf_uses_the_installed_image_without_pulling_or_recreating_it(monkeypatch):
    calls = []
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(host_facts, "_container_ids", lambda container: [])

    def read(arguments):
        calls.append(arguments)
        return [{"Id": image}] if arguments[:3] == ["docker", "image", "inspect"] else []

    monkeypatch.setattr(host_facts, "_read", read)
    observed = host_facts.collect("ptf-bed", "parent", image_reference="registry/docker-ptf:latest")
    assert not observed["container"]["exists"] and observed["container"]["image_id"] == image
    assert calls == [["docker", "image", "inspect", "registry/docker-ptf:latest"],
                     ["ip", "-j", "-d", "link", "show"]]


@pytest.mark.parametrize("reference", [None, "registry/docker-ptf:latest"])
def test_absent_ptf_cannot_succeed_without_a_verified_installed_image(monkeypatch, reference):
    monkeypatch.setattr(host_facts, "_container_ids", lambda container: [])
    monkeypatch.setattr(host_facts, "_read", lambda arguments: [])
    with pytest.raises(ValueError, match="installed"):
        host_facts.collect("ptf-bed", "parent", image_reference=reference)


def test_installed_renderer_uses_candidate_ports_not_running_db(tmp_path, monkeypatch):
    template = tmp_path / "buffers.j2"
    template.write_text("installed-template")
    context = {"PORT": {"Ethernet-new": {"lanes": "1", "subport": "canonical"}}}
    calls = []

    def run(arguments, **keywords):
        calls.append(arguments)
        assert json.loads(Path(arguments[2]).read_text()) == context
        return SimpleNamespace(returncode=0, stdout=json.dumps({
            "BUFFER_PG": {"Ethernet-new|3": {"profile": "NULL"}},
            "TC_TO_DSCP_MAP": {"AZURE": {"0": "0"}},
        }).encode(), stderr=b"")

    monkeypatch.setattr(render.subprocess, "run", run)
    tables = render.render(context, [str(template)], {
        str(template): hashlib.sha256(template.read_bytes()).hexdigest()}, tmp_path)
    assert tables["BUFFER_PG"]["Ethernet-new|3"]["profile"] == "NULL"
    assert tables["TC_TO_DSCP_MAP"] == {"AZURE": {"0": "0"}}
    assert "-d" not in calls[0]


@pytest.mark.parametrize("mode", ["dynamic", "static"])
@pytest.mark.parametrize("shared", [False, True])
def test_traditional_cache_preserves_thresholds_and_uses_valid_unbound_reservations(mode, shared):
    context = {"PORT": {"Ethernet0": {"speed": "100000"}, "Ethernet4": {"speed": "100000"}},
               "CABLE_LENGTH": {"AZURE": {"Ethernet0": "40m", "Ethernet4": "0m"}}}
    tables = {"BUFFER_POOL": {"ingress_lossless_pool": {"mode": mode, "xoff": "1024000" if shared else "0"}},
              "BUFFER_PG": {"Ethernet0|0": {"profile": "ingress_lossy_profile"}}}
    bindings = copy.deepcopy(tables["BUFFER_PG"])
    render.traditional_profile_cache(context, tables, "100000 40m 19456 19456 49152 0 1024\n", fully_lossy=True)
    assert tables["BUFFER_PROFILE"] == {
        "pg_lossless_100000_40m_profile": {
            "pool": "ingress_lossless_pool", "size": "19456" if shared else "68608", "xon": "19456", "xoff": "49152",
            mode + "_th": "0", "xon_offset": "1024"}}
    assert tables["BUFFER_PG"] == bindings


def test_nonshared_cache_does_not_reinterpret_an_unqualified_lossless_policy():
    context = {"PORT": {"Ethernet0": {"speed": "100000"}},
               "CABLE_LENGTH": {"AZURE": {"Ethernet0": "40m"}}}
    tables = {"BUFFER_POOL": {"ingress_lossless_pool": {"mode": "dynamic"}}}
    with pytest.raises(ValueError, match="source-verified fully lossy policy"):
        render.traditional_profile_cache(context, tables, "100000 40m 19456 19456 49152 0\n")
    context["BUFFER_POOL"] = {"ingress_lossless_pool": {"mode": "dynamic", "xoff": "0"}}
    tables["BUFFER_POOL"]["ingress_lossless_pool"]["xoff"] = "1024000"
    render.traditional_profile_cache(context, tables, "100000 40m 19456 19456 49152 0\n", fully_lossy=True)
    assert tables["BUFFER_PROFILE"]["pg_lossless_100000_40m_profile"]["size"] == "68608"


def test_traditional_cache_preserves_existing_policy_and_rejects_ambiguous_lookup():
    name = "pg_lossless_100000_40m_profile"
    context = {"PORT": {"Ethernet0": {"speed": "100000"}},
               "CABLE_LENGTH": {"AZURE": {"Ethernet0": "40m"}}, "BUFFER_PROFILE": {name: {"size": "protected"}}}
    tables = {"BUFFER_POOL": {"ingress_lossless_pool": {"mode": "dynamic"}}}
    row = "100000 40m 19456 19456 49152 0\n"
    render.traditional_profile_cache(context, tables, row)
    assert name not in tables["BUFFER_PROFILE"]
    assert context["BUFFER_PROFILE"][name] == {"size": "protected"}
    with pytest.raises(ValueError, match="Duplicate"):
        render.traditional_profile_cache(context, tables, row + row)


@pytest.mark.parametrize("missing", [False, True])
def test_traditional_native_render_requires_the_exact_recorded_lookup(tmp_path, monkeypatch, missing):
    template = tmp_path / "buffers.j2"
    template.write_text("installed-template")
    lookup = tmp_path / "lookup.ini"
    lookup.write_text("100000 40m 19456 19456 49152 0\n")
    source = {"path": str(lookup), "sha256": hashlib.sha256(lookup.read_bytes()).hexdigest()}
    if not missing:
        lookup.write_text("changed-after-collection")
    context = {"PORT": {}, "DEVICE_METADATA": {"localhost": {"buffer_model": "traditional"}}}
    monkeypatch.setattr(render.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=b'{"BUFFER_POOL":{"ingress_lossless_pool":{"mode":"dynamic"}}}', stderr=b""))
    with pytest.raises(ValueError, match="lookup source" if missing else "lookup changed"):
        render.render(context, [str(template)], {str(template): hashlib.sha256(template.read_bytes()).hexdigest()},
                      tmp_path, None if missing else source)


def test_installed_cable_hook_uses_frozen_lengths_instead_of_neighbor_role_defaults(tmp_path, monkeypatch):
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    template = tmp_path / "buffers.json.j2"
    template.write_text(
        "{% if cable_length is not defined %}{% macro cable_length(port) %}40m{% endmacro %}{% endif %}"
        '{"CABLE_LENGTH":{"AZURE":{"Ethernet-new":"{{ cable_length(\'Ethernet-new\') }}"}}}',
        encoding="utf-8")
    context = {"PORT": {"Ethernet-new": {"lanes": "1"}},
               "CABLE_LENGTH": {"AZURE": {"Ethernet-new": "300m"}}}

    def run(arguments, **keywords):
        wrapper = Path(arguments[arguments.index("-t") + 1])
        environment = Environment(loader=FileSystemLoader(str(tmp_path)), undefined=StrictUndefined)
        actual = json.loads(Path(arguments[2]).read_text())
        output = environment.get_template(wrapper.name).render(actual)
        return SimpleNamespace(returncode=0, stdout=output.encode(), stderr=b"")

    monkeypatch.setattr(render.subprocess, "run", run)
    tables = render.render(context, [str(template)], {
        str(template): hashlib.sha256(template.read_bytes()).hexdigest()}, tmp_path)
    assert tables["CABLE_LENGTH"] == context["CABLE_LENGTH"]


@pytest.mark.parametrize("drift", [True, False])
def test_template_source_drift_or_port_mutation_is_rejected(tmp_path, monkeypatch, drift):
    template = tmp_path / "buffers.j2"
    template.write_text("installed-template")
    expected = hashlib.sha256(template.read_bytes()).hexdigest()
    calls = []
    if drift:
        template.write_text("changed-after-collection")

    def run(*arguments, **keywords):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=b'{"PORT":{"unexpected":{}}}', stderr=b"")

    monkeypatch.setattr(render.subprocess, "run", run)
    with pytest.raises(ValueError):
        render.render({"PORT": {}}, [str(template)], {str(template): expected}, tmp_path)
    assert bool(calls) is not drift


def _spec():
    return {
        "scenario": "scenario", "hostname": "server", "container": "ptf-bed", "image_id": "sha256:" + "a" * 64,
        "parent": "trunk", "mtu": 9216, "management_root": "gm-scenario", "management_peer": "gp-scenario",
        "router_mac": "00:11:22:33:44:55", "traffic_cases": [],
        "management": {"bridge": "br-mgmt", "addresses": ["10.0.0.2/24"], "gateway": "10.0.0.1",
                       "gateway_v6": "", "mtu": 1500},
        "endpoints": [{"ptf_index": 0, "host_interface": "gg-vlan", "ptf_address": "192.0.2.1/31",
                       "vlan": 200, "mac": "02:11:22:33:44:55"}],
    }


@pytest.mark.parametrize("available", [False, True])
def test_management_only_ptf_requires_a_frozen_no_path_result(available):
    spec = _spec()
    spec["endpoints"] = []
    spec["traffic_available"] = available
    if not available:
        host.validate_spec(spec)
        assert host.candidate_state(spec)["endpoints"] == []
    else:
        with pytest.raises(host.HostActionError, match="independent PTF MAC"):
            host.validate_spec(spec)


def test_a_no_path_layout_cannot_admit_or_launch_packet_traffic(tmp_path, monkeypatch):
    spec = dict(_spec(), traffic_available=False)
    with pytest.raises(host.HostActionError, match="must not allocate traffic"):
        host.validate_spec(spec)
    spec["endpoints"] = []

    def forbidden(*arguments):
        raise AssertionError("A no-path layout must not execute packet traffic")

    monkeypatch.setattr(host, "capture", forbidden)
    with pytest.raises(host.HostActionError, match="no independent packet"):
        host.smoke(spec, tmp_path)


def _observed_host(tmp_path, monkeypatch):
    spec, operation = _spec(), "scenario:add:host"
    tag = "sonic-generic:scenario:" + operation
    root = [{"ifname": "trunk", "ifindex": 2, "mtu": 9216},
            {"ifname": "br-mgmt", "ifindex": 3, "mtu": 1500, "linkinfo": {"info_kind": "bridge"}},
            {"ifname": "gm-scenario", "ifindex": 5, "link_index": 6, "master": 3, "mtu": 1500,
             "ifalias": tag, "flags": ["UP"]}]
    namespace = [
        {"ifname": "lo", "ifindex": 1},
        {"ifname": "mgmt", "ifindex": 6, "link_index": 5, "mtu": 1500, "ifalias": tag, "flags": ["UP"]},
        {"ifname": "eth0", "ifindex": 7, "link_index": 2, "mtu": 9216, "ifalias": tag, "flags": ["UP"],
         "address": "02:11:22:33:44:55", "linkinfo": {"info_kind": "vlan", "info_data": {"id": 200}}}]
    container = {"Name": "/ptf-bed", "Id": "owned-container-id", "Image": spec["image_id"],
                 "Config": {"Labels": {host.OWNER: "scenario", host.OPERATION: operation}},
                 "State": {"Running": True, "Pid": 37}}
    calls = []

    def command(arguments, directory):
        calls.append(arguments)
        if arguments[0] == "ip":
            return json.dumps(root).encode()
        if "sysctl" in arguments:
            return "\n".join(host.NAMESPACE_SYSCTLS[key] for key in sorted(host.NAMESPACE_SYSCTLS)).encode()
        if arguments[-2:] == ["link", "show"]:
            return json.dumps(namespace).encode()
        if "address" in arguments:
            return json.dumps([
                {"ifname": "mgmt", "addr_info": [{"local": "10.0.0.2", "prefixlen": 24, "scope": "global"}]},
                {"ifname": "eth0", "addr_info": [{"local": "192.0.2.1", "prefixlen": 31, "scope": "global"}]}]).encode()
        if "-4" in arguments:
            return b'[{"gateway":"10.0.0.1","dev":"mgmt"}]'
        if "-6" in arguments:
            return b"[]"
        raise AssertionError("Unexpected native command")

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "inspect_container", lambda *arguments: container)
    return spec, operation, root, namespace, container, calls


def test_host_readback_observes_actual_vlan_not_desired_snapshot(tmp_path, monkeypatch):
    spec, operation, root, namespace, container, calls = _observed_host(tmp_path, monkeypatch)
    observed, owner = host.capture(spec, tmp_path)
    assert observed == host.candidate_state(spec) and owner == operation
    namespace[-1]["linkinfo"]["info_data"]["id"] = 201
    changed, owner = host.capture(spec, tmp_path)
    assert changed["endpoints"][0]["vlan"] == 201 and changed != host.candidate_state(spec)
    assert all(arguments[0] in ("ip", "nsenter") for arguments in calls)


def test_created_interfaces_verify_ownership_when_add_or_namespace_move_loses_alias(tmp_path, monkeypatch):
    spec, operation, root, namespace, container, calls = _observed_host(tmp_path, monkeypatch)
    for row in root + namespace:
        row.pop("ifalias", None)
    read, capture = host.command, host.capture
    created = False

    def command(arguments, directory):
        nonlocal created
        if arguments[:2] == ["docker", "create"]:
            created = True
            return b"owned-container-id"
        if arguments[:2] == ["docker", "start"]:
            return b"owned-container-id"
        native = arguments[4:] if arguments[0] == "nsenter" else arguments
        if native[:3] == ["ip", "link", "set"]:
            name = native[native.index("dev") + 1]
            row = (root[-1] if name == spec["management_root"]
                   else namespace[1] if name in {spec["management_peer"], "mgmt"} else namespace[-1])
            if "netns" in native or "name" in native or "alias" not in native:
                row.pop("ifalias", None)
            if "alias" in native:
                row["ifalias"] = native[native.index("alias") + 1]
            return b""
        if (native[:3] == ["ip", "link", "add"] or "-w" in native
                or native[:3] == ["ip", "address", "add"] or "add" in native):
            return b""
        return read(arguments, directory)

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "capture", lambda *arguments: capture(*arguments) if created else (None, None))
    host.perform(None, host.candidate_state(spec), operation, spec, tmp_path)
    observed, owner = host.capture(spec, tmp_path)
    assert observed == host.candidate_state(spec) and owner == operation


def test_another_container_owner_is_never_adopted(tmp_path, monkeypatch):
    spec, operation, root, namespace, container, calls = _observed_host(tmp_path, monkeypatch)
    container["Config"]["Labels"][host.OWNER] = "another-scenario"
    with pytest.raises(host.HostActionError, match="does not own"):
        host.capture(spec, tmp_path)
    assert not any(arguments[0] == "docker" for arguments in calls)


def test_neighbor_policy_drift_is_observed_only_inside_the_owned_namespace(tmp_path, monkeypatch):
    spec, operation, root, namespace, container, calls = _observed_host(tmp_path, monkeypatch)
    original = host.command

    def command(arguments, directory):
        if "sysctl" in arguments:
            assert arguments[:4] == ["nsenter", "-t", "37", "-n"]
            values = dict(host.NAMESPACE_SYSCTLS)
            values["net.ipv4.conf.all.arp_ignore"] = "0"
            return "\n".join(values[key] for key in sorted(values)).encode()
        return original(arguments, directory)

    monkeypatch.setattr(host, "command", command)
    observed, owner = host.capture(spec, tmp_path)
    assert observed["sysctls"]["net.ipv4.conf.all.arp_ignore"] == "0"
    assert observed != host.candidate_state(spec)


def test_unowned_interface_blocks_namespace_destruction(tmp_path, monkeypatch):
    spec = _spec()
    current = {"unowned_interfaces": ["foreign-interface"]}
    monkeypatch.setattr(host, "capture", lambda *arguments: (current, None))
    calls = []
    monkeypatch.setattr(host, "command", lambda *arguments: calls.append(arguments))
    with pytest.raises(host.HostActionError, match="Another owner's interface"):
        host.perform(current, None, "scenario:restore:host", spec, tmp_path)
    assert calls == [] and not (tmp_path / "host-intent.json").exists()


def test_partial_create_records_intent_before_write_and_observed_failure(tmp_path, monkeypatch):
    spec, state = _spec(), {"current": None}
    partial = {"container": {"name": spec["container"], "running": False}, "unowned_interfaces": []}
    monkeypatch.setattr(host, "capture", lambda *arguments: (copy.deepcopy(state["current"]), None))

    def command(arguments, directory):
        if arguments[:2] == ["docker", "create"]:
            assert json.loads((tmp_path / "host-intent.json").read_text())["operation_id"] == "scenario:add:host"
            state["current"] = partial
            return b"created-container"
        raise host.HostActionError("start failed after creation")

    monkeypatch.setattr(host, "command", command)
    with pytest.raises(host.HostActionError, match="start failed"):
        host.perform(None, host.candidate_state(spec), "scenario:add:host", spec, tmp_path)
    receipt = json.loads((tmp_path / "host-receipt.json").read_text())
    assert not receipt["completed"] and receipt["observed_sha256"] == host.digest(partial)


def test_reserved_old_vlan_remnant_blocks_before_create(tmp_path, monkeypatch):
    spec = _spec()
    root = [{"ifname": "trunk", "ifindex": 2, "mtu": 9216},
            {"ifname": "old-vlan", "link_index": 2, "linkinfo": {"info_kind": "vlan", "info_data": {"id": 200}}}]
    monkeypatch.setattr(host, "capture", lambda *arguments: (None, None))
    calls = []

    def command(arguments, directory):
        calls.append(arguments)
        return json.dumps(root).encode()

    monkeypatch.setattr(host, "command", command)
    with pytest.raises(host.HostActionError, match="VLAN remnants"):
        host.stage(spec, tmp_path)
    assert len(calls) == 1 and not (tmp_path / "request.json").exists()
