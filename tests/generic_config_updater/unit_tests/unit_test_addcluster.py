"""Offline add-cluster regressions; no device or native GCU is invoked.

Run from the repository root with:
python -m pytest --noconftest --confcutdir=tests/generic_config_updater/unit_tests \
    tests/generic_config_updater/unit_tests/unit_test_addcluster.py -q \
    -o log_format="%(levelname)s %(message)s"
"""

import ast
import copy
import importlib.util
import inspect
import json
import logging
from pathlib import Path
import shlex
from unittest.mock import Mock
import xml.etree.ElementTree as ET

import jsonpatch
import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "util" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scoped(tables, namespace):
    return {namespace: tables} if namespace else tables


@pytest.fixture
def generator():
    return load_helper("generate_patch")


def acl_patch(generator, tmp_path, current, desired, split=True):
    full, reduced = tmp_path / "full.json", tmp_path / "reduced.json"
    full.write_text(json.dumps(desired))
    reduced.write_text(json.dumps(current))
    paths = generator.generate_config_patch(str(full), str(reduced), split_phases=split)
    return [json.loads(Path(path).read_text()) for path in paths]


@pytest.mark.parametrize("namespace", [None, "asic0"])
@pytest.mark.parametrize("split", [False, True])
def test_unbound_acl_restores_mirror_and_dataplane_configuration(generator, tmp_path, namespace, split):
    """Both caller modes restore empty bindings and the known DataPlane fallback."""
    desired = {"ACL_TABLE": {
        "MIRROR4": {"type": "MIRROR", "stage": "ingress", "ports": ["PortChannel1"]},
        "MIRROR6": {"type": "MIRRORV6", "stage": "ingress", "ports": ["PortChannel1"]},
        "DATA": {"type": "L3", "stage": "ingress", "ports": ["PortChannel1"]},
    }}
    current = copy.deepcopy(desired)
    for name in ("MIRROR4", "MIRROR6"):
        current["ACL_TABLE"][name]["ports"] = [""]
    current["ACL_TABLE"]["DATA"] = {"type": "CTRLPLANE", "stage": "ingress", "services": ["DataPlane"]}
    current, desired = scoped(current, namespace), scoped(desired, namespace)
    phases = acl_patch(generator, tmp_path, current, desired, split)
    if split:
        assert phases[0] == []
    assert jsonpatch.apply_patch(current, [op for phase in phases for op in phase]) == desired


@pytest.mark.parametrize("change", [{"ports": ["PortChannel9"]}, {"policy_desc": "updated"}])
def test_unbound_acl_rejects_stale_bindings_or_metadata(generator, tmp_path, change):
    """A patch generated for an unbound ACL must not overwrite a newer entry."""
    current = {"ACL_TABLE": {"MIRROR4": {"type": "MIRROR", "ports": [""]}}}
    desired = {"ACL_TABLE": {"MIRROR4": {"type": "MIRROR", "ports": ["PortChannel1"]}}}
    _, patch = acl_patch(generator, tmp_path, current, desired)
    current["ACL_TABLE"]["MIRROR4"].update(change)
    with pytest.raises(jsonpatch.JsonPatchTestFailed):
        jsonpatch.apply_patch(current, patch)


def test_bound_acl_keeps_concurrent_bindings_and_metadata(generator, tmp_path):
    """Ordinary binding updates remain append-only rather than replacing an ACL."""
    current = {"ACL_TABLE": {"ACL": {"type": "MIRROR", "stage": "egress", "ports": ["PortChannel1"]}}}
    desired = {"ACL_TABLE": {"ACL": {
        "type": "MIRRORV6", "stage": "ingress", "ports": ["PortChannel1", "PortChannel2"]}}}
    _, patch = acl_patch(generator, tmp_path, current, desired)
    current["ACL_TABLE"]["ACL"].update(ports=["PortChannel1", "PortChannel9"], policy_desc="updated")
    expected = copy.deepcopy(current)
    expected["ACL_TABLE"]["ACL"]["ports"].append("PortChannel2")
    assert jsonpatch.apply_patch(current, patch) == expected


@pytest.mark.parametrize("services,new_type,promoted", [
    (["DataPlane"], "L3V6", True), (["SSH"], "L3", False), (["DataPlane"], "MIRROR", False),
])
def test_binding_finder_promotes_only_known_dataplane_fallback(generator, services, new_type, promoted):
    """The second binding path shares the narrow restoration guard, including IPv6."""
    old = {"type": "CTRLPLANE", "services": services, "stage": "egress"}
    new = {"type": new_type, "ports": ["PortChannel1"], "stage": "ingress"}
    current = {"asic0": {"ACL_TABLE": {"ACL": old}}}
    desired = {"asic0": {"ACL_TABLE": {"ACL": new}}}
    patch = generator.find_acl_table_bindings_for_ports(desired, current, "asic0", {"PortChannel1"}, True)
    expected = dict(old, ports=["PortChannel1"])
    if promoted:
        expected["type"] = new_type
        expected.pop("services")
    assert jsonpatch.apply_patch(current, patch) == {"asic0": {"ACL_TABLE": {"ACL": expected}}}


@pytest.mark.parametrize("ports", [None, [], [""], ["", ""]])
def test_binding_splitter_handles_empty_members_and_escaped_names(generator, ports):
    """Missing/empty port members and escaped table names preserve valid JSON pointers."""
    old = {"type": "MIRROR"}
    if ports is not None:
        old["ports"] = ports
    desired = dict(old, ports=["PortChannel1"])
    current = {"asic3": {"ACL_TABLE": {"ACL~/name": old}}}
    whole, bindings = generator.split_existing_acl_table_patches(
        [{"op": "add", "path": "/asic3/ACL_TABLE/ACL~0~1name", "value": desired}], current, True)
    assert jsonpatch.apply_patch(current, whole + bindings) == {"asic3": {"ACL_TABLE": {"ACL~/name": desired}}}


def test_minigraph_removal_preserves_same_named_objects_in_other_asic():
    """ASIC-local aliases and PortChannel names must not remove another ASIC's objects."""
    module = load_helper("process_minigraph")
    ns = module.NS
    root = ET.Element(ns + "AutopilotGraph")
    sections = {}
    for name in ("ASIC0", "ASIC1"):
        section = ET.SubElement(root, ns + "DeviceDataPlaneInfo")
        ET.SubElement(section, ns + "Hostname").text = name
        channels = ET.SubElement(section, ns + "PortChannelInterfaces")
        channel = ET.SubElement(channels, ns + "PortChannel")
        ET.SubElement(channel, ns + "Name").text = "PortChannel1"
        ET.SubElement(channel, ns + "AttachTo").text = "Eth0"
        interfaces = ET.SubElement(section, ns + "IPInterfaces")
        interface = ET.SubElement(interfaces, ns + "IPInterface")
        ET.SubElement(interface, ns + "AttachTo").text = "PortChannel1"
        sections[name] = section
    unrelated = ET.tostring(sections["ASIC1"])
    refactor = module.MinigraphRefactor(
        "T1", {"Ethernet0": "etp1"}, {"asic0": {"Ethernet0": "Eth0", "etp1": "Eth0"}})
    refactor.affected_ports = {"Ethernet0"}
    assert refactor.remove_portchannel_interfaces(root) == 1
    assert refactor.remove_ip_interfaces(root) == 1
    assert ET.tostring(sections["ASIC1"]) == unrelated
    assert not sections["ASIC0"].findall(".//" + ns + "PortChannel")
    assert not sections["ASIC0"].findall(".//" + ns + "IPInterface")


def assert_condition(condition, message=""):
    assert condition, message


@pytest.fixture
def testcase():
    """Extract actual functions without importing Ansible or Linux-only testbed modules."""
    path = ROOT / "test_multiasic_addcluster.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {"setup_env", "target_is_operational", "verify_mirror_acl_bindings"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in functions:
        node.decorator_list = []
    namespace = {
        "json": json, "pytest": pytest, "pytest_assert": assert_condition,
        "logger": logging.getLogger(__name__),
        "MINIGRAPH": "/etc/sonic/minigraph.xml", "MINIGRAPH_BACKUP": "/etc/sonic/minigraph.xml.backup",
        "config_reload": lambda dut, **kwargs: dut.reload(**kwargs),
        "wait_until": lambda timeout, interval, delay, check, *args: check(*args),
        "create_checkpoint": lambda dut: None, "delete_checkpoint": lambda dut: None,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    body = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name == "test_addcluster_workflow")
    backup = [node for node in ast.walk(body) if isinstance(node, ast.Expr)
              and isinstance(node.value, ast.Call) and node.value.args
              and "sudo cp" in (ast.get_source_segment(path.read_text(encoding="utf-8"), node) or "")
              and "MINIGRAPH_BACKUP" in (ast.get_source_segment(path.read_text(encoding="utf-8"), node) or "")]
    assert len(backup) == 1
    namespace["backup"] = compile(ast.Module(body=backup, type_ignores=[]), str(path), "exec")
    return namespace


class SnapshotDut:
    is_multi_asic = True

    def __init__(self):
        self.configs = {None: "config_db.json", "asic0": "config_db0.json", "asic3": "config_db3.json"}
        self.running = {name: {"RUNNING_ONLY": {"scope": str(name)}} for name in self.configs}
        self.original_running = copy.deepcopy(self.running)
        self.files = {"/etc/sonic/" + filename: json.dumps({"SAVED_ONLY": name})
                      for name, filename in self.configs.items()}
        self.files["/etc/sonic/minigraph.xml"] = "<original/>"
        self.original_files = self.files.copy()
        self.mtimes = {name: 1 for name in self.files}
        self.failure = None
        self.copy_attempts = []
        self.reloads = 0
        self.readiness_checks = 0

    def get_asic_ids(self):
        return [0, 3]

    def get_bgp_neighbors_per_asic(self, state):
        assert state == "established"
        return {"asic3": {"192.0.2.1": {}, "2001:db8::1": {}}}

    def check_bgp_session_state_all_asics(self, peers):
        assert peers == self.get_bgp_neighbors_per_asic("established")
        assert self.running == self.original_running
        assert all(self.files[name] == value for name, value in self.original_files.items())
        self.readiness_checks += 1
        return self.failure != "bgp"

    def stat(self, path):
        return {"stat": {"exists": path in self.files}}

    def tempfile(self, **kwargs):
        return {"path": "/tmp/addcluster-unit"}

    def shell(self, command):
        args = shlex.split(command)
        if args[0] == "sudo":
            args = args[1:]
        if args[0] == "cp":
            source, target = args[-2:]
            self.copy_attempts.append((source, target))
            if self.failure == "startup" and source == "/tmp/addcluster-unit/config_db0.json":
                raise RuntimeError("startup")
            self.files[target] = self.files[source]
            self.mtimes[target] = self.mtimes[source] if "-p" in args else 99
        elif args[0] == "sonic-cfggen":
            scope = args[args.index("-n") + 1] if "-n" in args else None
            self.files[args[-1]] = json.dumps(self.running[scope])
            self.mtimes[args[-1]] = 99
        elif args[0] == "sonic-db-cli":
            return {"stdout": "true" if self.reloads and self.failure == "traffic-shift" else ""}
        else:
            raise AssertionError(command)
        return {"stdout": ""}

    def shell_cmds(self, cmds, continue_on_fail):
        errors = []
        for command in cmds:
            try:
                self.shell(command)
            except RuntimeError as error:
                errors.append(error)
                if not continue_on_fail:
                    break
        if errors:
            raise errors[0]

    def file(self, path, state):
        assert state == "absent"
        self.files = {name: value for name, value in self.files.items()
                      if name != path and not name.startswith(path + "/")}

    def reload(self, config_source="config_db", safe_reload=False):
        self.reloads += 1
        assert config_source == "config_db" and safe_reload
        if self.failure == "reload":
            raise RuntimeError("reload")
        self.running = {scope: json.loads(self.files["/etc/sonic/" + filename])
                        for scope, filename in self.configs.items()}

    def modify(self, testcase):
        exec(testcase["backup"], dict(testcase, duthost=self))
        for name in self.original_files:
            self.files[name] = "temporary"
            self.mtimes[name] = 99
        self.running = {name: {"TEMPORARY": {}} for name in self.configs}


def start_fixture(testcase, dut):
    values = {"duthost": dut, "duthosts": {"selected": dut}, "enum_downstream_dut_hostname": "selected"}
    function = testcase["setup_env"]
    fixture = function(**{name: values[name] for name in inspect.signature(function).parameters})
    next(fixture)
    return fixture


@pytest.mark.parametrize("body_fails", [False, True])
def test_teardown_restores_host_sparse_asics_startup_and_minigraph_metadata(testcase, body_fails):
    """Normal and failed bodies restore distinct snapshots before readiness and cleanup."""
    dut = SnapshotDut()
    fixture = start_fixture(testcase, dut)
    dut.modify(testcase)
    if body_fails:
        with pytest.raises(RuntimeError, match="body"):
            fixture.throw(RuntimeError("body"))
    else:
        with pytest.raises(StopIteration):
            next(fixture)
    assert dut.running == dut.original_running
    assert dut.files == dut.original_files
    assert all(dut.mtimes[name] == 1 for name in dut.original_files)
    assert dut.reloads == 1 and dut.readiness_checks == 1


@pytest.mark.parametrize("failure", ["reload", "startup", "bgp", "traffic-shift"])
def test_failed_teardown_keeps_recovery_artifacts_and_attempts_all_startup_files(testcase, failure):
    """Cleanup errors propagate without discarding recovery snapshots or later file restores."""
    dut = SnapshotDut()
    fixture = start_fixture(testcase, dut)
    dut.modify(testcase)
    dut.failure = failure
    with pytest.raises((RuntimeError, AssertionError)):
        next(fixture)
    assert "/etc/sonic/minigraph.xml.backup" in dut.files
    assert "/tmp/addcluster-unit/running_config_db3.json" in dut.files
    assert all(("/tmp/addcluster-unit/" + filename, "/etc/sonic/" + filename) in dut.copy_attempts
               for filename in dut.configs.values())
    assert dut.files["/etc/sonic/config_db3.json"] == dut.original_files["/etc/sonic/config_db3.json"]


def test_early_skip_does_not_reload(testcase):
    """A skip before minigraph modification leaves the DUT unchanged."""
    dut = SnapshotDut()
    fixture = start_fixture(testcase, dut)
    with pytest.raises(StopIteration):
        next(fixture)
    assert dut.reloads == 0
    assert dut.files == dut.original_files


@pytest.mark.parametrize("failure", [None, "port-down", "ipv6-missing", "empty-ports", "empty-peers"])
def test_target_readiness_requires_nonempty_ports_and_both_bgp_families(testcase, failure):
    """Configuration success cannot replace actual target-port and dual-stack BGP recovery."""
    dut = Mock(is_multi_asic=True)
    dut.shell.return_value = {"stdout": "down" if failure == "port-down" else "up"}
    peers = {"192.0.2.1": {"state": "established"}, "2001:db8::1": {"state": "established"}}
    observed = copy.deepcopy(peers)
    if failure == "ipv6-missing":
        observed.pop("2001:db8::1")
    dut.asic_instance_from_namespace.return_value.bgp_facts.return_value = {
        "ansible_facts": {"bgp_neighbors": observed}}
    ports = set() if failure == "empty-ports" else {"Ethernet0"}
    expected_peers = set() if failure == "empty-peers" else set(peers)
    assert testcase["target_is_operational"](dut, "asic3", ports, expected_peers) == (failure is None)


@pytest.mark.parametrize("table,key", [
    ("PORT_QOS_MAP", "Ethernet0"), ("PORTCHANNEL_MEMBER", "PortChannel1|Ethernet0"), ("CABLE_LENGTH", "Ethernet0"),
])
@pytest.mark.parametrize("desired_present,actual_present", [(False, False), (False, True), (True, False), (True, True)])
def test_config_entry_presence_matches_desired_state(table, key, desired_present, actual_present):
    """Entry checks accept intended removals, but still reject missing additions and stale entries."""
    path = ROOT / "test_multiasic_addcluster.py"
    function = next(node for node in ast.parse(path.read_text(encoding="utf-8")).body
                    if isinstance(node, ast.FunctionDef) and node.name == "test_addcluster_workflow")
    verify = next(node for node in function.body if isinstance(node, ast.For)
                  and isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Attribute)
                  and isinstance(node.iter.func.value, ast.Name)
                  and node.iter.func.value.id == "config_entries_to_check")
    desired = {key: "5m" if table == "CABLE_LENGTH" else {}} if desired_present else {}
    if table == "CABLE_LENGTH":
        desired = {"AZURE": desired}
    entry = key if table == "CABLE_LENGTH" else table + "|" + key
    dut = Mock()
    if table == "CABLE_LENGTH":
        dut.shell.return_value = {"stdout": repr({key: "5m"} if actual_present else {})}
    else:
        dut.shell.return_value = {"stdout": entry if actual_present else ""}
    context = {
        "json": json, "pytest": pytest, "pytest_assert": assert_condition, "logger": logging.getLogger(__name__),
        "duthost": dut, "asic_id": "asic0", "ASICID": "asic0", "ns_arg": "-n asic0",
        "full_config": {"asic0": {table: desired}}, "config_entries_to_check": {table: {entry}},
    }
    code = compile(ast.Module(body=[verify], type_ignores=[]), str(path), "exec")
    if desired_present == actual_present:
        exec(code, context)
    else:
        with pytest.raises((AssertionError, pytest.fail.Exception)):
            exec(code, context)
    assert dut.shell.call_count == 1


@pytest.mark.parametrize("actual_ports", [
    ["PortChannel1", "Ethernet8"], ["Ethernet8"], ["PortChannel1", "PortChannel1", "Ethernet8"],
])
def test_legacy_mirror_check_accepts_portchannels_but_rejects_missing_or_duplicate_bindings(testcase, actual_ports):
    """Only intended bindings in the selected namespace can satisfy the legacy check."""
    desired = {"type": "MIRROR", "ports": ["Ethernet8", "PortChannel1"]}
    config = {"asic0": {"ACL_TABLE": {"MIRROR4": desired}},
              "asic1": {"ACL_TABLE": {"MIRROR4": {"type": "CTRLPLANE", "services": ["SSH"]}}}}
    dut = Mock()
    dut.shell.return_value = {"stdout": json.dumps({"MIRROR4": dict(desired, ports=actual_ports)})}
    patch = [{"op": "add", "path": "/asic0/ACL_TABLE/MIRROR4/ports/-", "value": "PortChannel1"}]
    if sorted(actual_ports) == sorted(desired["ports"]):
        testcase["verify_mirror_acl_bindings"](dut, "asic0", config, patch)
    else:
        with pytest.raises(AssertionError):
            testcase["verify_mirror_acl_bindings"](dut, "asic0", config, patch)
    dut.shell.assert_called_once_with("sonic-cfggen -n asic0 -d --var-json ACL_TABLE")


def test_legacy_mirror_check_does_not_require_unrelated_port_bindings(testcase):
    """A PORT-only patch does not imply a MIRROR binding or read another ASIC's table."""
    dut = Mock()
    testcase["verify_mirror_acl_bindings"](dut, "asic0", {"asic0": {}}, [
        {"op": "add", "path": "/asic0/PORT/Ethernet0", "value": {"admin_status": "up"}},
        {"op": "add", "path": "/asic1/ACL_TABLE/MIRROR4/ports/-", "value": "Ethernet0"},
    ])
    dut.shell.assert_not_called()
