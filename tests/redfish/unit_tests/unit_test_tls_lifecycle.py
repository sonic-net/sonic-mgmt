"""Offline Redfish fixture regression, with real pytest scheduling and config checks.

Run from the repository root (no DUT or sonic-mgmt imports required)::

    python3 -m pytest --noconftest --confcutdir=tests/redfish/unit_tests \
        tests/redfish/unit_tests/unit_test_tls_lifecycle.py -v

Only hardware-facing operations are simulated. Production fixture decorators,
setup/finalizers, backup/restore helpers and core_dump_and_config_check run as-is.
"""

import ast
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


TESTS = Path(__file__).resolve().parents[2]


def load_nodes(path, namespace, names=None):
    tree = ast.parse(path.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if names is None or node.name in names:
                nodes.append(node)
        elif names is None and isinstance(node, ast.Assign):
            if all(isinstance(target, ast.Name) and target.id.isupper() for target in node.targets):
                nodes.append(node)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


def require(condition, message="check failed"):
    assert condition, message


class Device:
    """Small in-memory CONFIG_DB/filesystem, deliberately rejecting unknown commands."""

    hostname = "bmc"
    mgmt_ip = "192.0.2.1"
    os_version = "202605"
    is_multi_asic = False

    def __init__(self, feature="enabled", provisioned=False):
        self.config = {"FEATURE": {"redfish": {"state": feature}}}
        self.files = {}
        self.events = []
        self.running = feature == "enabled"
        self.fail_command = None
        if provisioned:
            self.config["REDFISH"] = {
                "certs": {"server_crt": "/operator/server.crt", "server_key": "/operator/server.key",
                          "ca_crt": "/operator/ca.crt", "client_crt_cname": "operator", "untouched": "keep"},
                "config": {"port": "8443"}}
        self.golden = copy.deepcopy(self.config)

    def stat(self, path):
        return {"stat": {"exists": path in self.files or path == "/etc/sonic/running_golden_config.json"}}

    def get_feature_status(self):
        return {"redfish": self.config["FEATURE"]["redfish"]["state"]}, True

    def is_service_fully_started(self, service):
        return self.running

    def is_bmc(self):
        return True

    def shell(self, command, **kwargs):
        self.events.append(command)
        if command == self.fail_command:
            raise RuntimeError("injected failure: " + command)
        words = shlex.split(command)
        output = ""
        if words[0] == "sonic-db-cli":
            _, db, action, key, *args = words
            assert db == "CONFIG_DB"
            table, row = key.split("|")
            fields = self.config.get(table, {}).get(row, {})
            if action == "hexists":
                output = str(int(args[0] in fields))
            elif action == "hget":
                output = fields.get(args[0], "")
            elif action == "hset":
                fields = self.config.setdefault(table, {}).setdefault(row, {})
                fields.update(zip(args[::2], args[1::2]))
            elif action == "hdel":
                fields.pop(args[0], None)
                if not fields and table in self.config:
                    self.config[table].pop(row, None)
                    if not self.config[table]:
                        del self.config[table]
            else:
                raise AssertionError(command)
        elif command.startswith("sudo config feature state"):
            self.config["FEATURE"]["redfish"]["state"] = words[-1]
            self.running = words[-1] == "enabled"
        elif command == "cat /etc/sonic/running_golden_config.json":
            output = json.dumps(self.golden)
        elif command == "sonic-cfggen -d --print-data":
            output = json.dumps(self.config)
        elif command in ("free -h", "df -h", "ls /var/core/"):
            pass
        elif words[:2] == ["cp", "-a"]:
            self.files[words[3]] = self.files[words[2]]
        elif words[:2] == ["mv", "-f"]:
            self.files[words[3]] = self.files.pop(words[2])
        elif words[:2] == ["rm", "-f"]:
            self.files.pop(words[2], None)
        elif words[0] == "mkdir":
            pass
        elif command == "systemctl stop redfish":
            self.running = False
        elif command == "systemctl start redfish":
            self.running = True
        elif command == "docker rm -f redfish":
            assert not self.running, "watcher must stop before state restoration"
        elif command == "docker exec redfish supervisorctl status bmcweb":
            output = "bmcweb RUNNING" if self.running else "STOPPED"
        else:
            raise AssertionError("unexpected command: " + command)
        return {"stdout": output, "stderr": "", "rc": 0}


def utility_namespace():
    namespace = {"pytest": pytest, "pytest_assert": require, "pyrequire": require,
                 "logger": Mock(), "os": os, "shlex": shlex,
                 "wait_until": lambda timeout, interval, delay, fn, *args: fn(*args)}
    load_nodes(TESTS / "redfish/redfish_utils.py", namespace)
    return namespace


def install_fixtures(plugin, feature, provisioned, leak=False, fail_setup=False):
    """Install production fixtures into an isolated subprocess's conftest namespace."""
    namespace = utility_namespace()
    device = Device(feature, provisioned)
    if provisioned:
        device.files.update({path: "original:" + path for path in namespace["DEVICE_STATE_FILES"]})
    original_files = device.files.copy()
    namespace["device"] = device
    namespace["setup_count"] = 0
    namespace["recoveries"] = []
    namespace["messages"] = []

    def deliver(dut, cert_dir):
        namespace["setup_count"] += 1
        for path in namespace["DEVICE_STATE_FILES"]:
            dut.files[path] = "test certificate state"

    def trusted(dut, cn):
        namespace["db_set"](dut, "CONFIG_DB", "REDFISH|certs", client_crt_cname=cn)
        return True

    def recover(data, duts, request):
        namespace["recoveries"].append(copy.deepcopy(device.config))
        device.config = copy.deepcopy(data[device.hostname]["pre_running_config"][None])
        device.running = device.config["FEATURE"]["redfish"]["state"] == "enabled"

    class Client:
        def __init__(self, *args, **kwargs):
            self.port = kwargs["port"]

        def privileged_get(self):
            assert device.running
            assert device.config.get("REDFISH", {}).get("certs", {}).get("client_crt_cname") == "bmcweb"

    namespace.update(
        RedfishClient=Client, build_cert_chain=Mock(return_value="generator"), deliver_certs=deliver,
        set_trusted_cnames=trusted, assert_bmc_clock_in_sync=Mock(),
        listening_port=lambda dut: 8443 if provisioned else 443,
        wait_for_staging=lambda dut: not fail_setup, cert_status=lambda *args: "injected staging failure",
        SafeThreadPoolExecutor=ThreadPoolExecutor, json=json,
        refresh_core_dump_inventory=lambda before, collect, detected: (collect(), []),
        get_unrestored_runtime_managed_entries_by_context=lambda *args: {},
        restore_config_db_and_config_reload=recover, DUT_CHECK_NAMESPACE="dut_check",
        add_custom_msg=lambda request, key, value: namespace["messages"].append((key, value)),
    )
    load_nodes(TESTS / "conftest.py", namespace, {"core_dump_and_config_check", "compare_running_config"})
    load_nodes(TESTS / "redfish/conftest.py", namespace)

    @pytest.fixture(scope="session")
    def duthosts():
        return [device]

    @pytest.fixture(scope="session")
    def tbinfo():
        return {"duts": [0], "topo": {"name": "bmc"}}

    @pytest.fixture(scope="session")
    def parallel_run_context():
        return SimpleNamespace(is_par_run=False)

    @pytest.fixture(scope="module")
    def sanity_check():
        yield

    @pytest.fixture(autouse=True)
    def loganalyzer():
        device.events.append("loganalyzer start")
        yield
        device.events.append("loganalyzer check")

    def pytest_sessionfinish(session):
        Path("result.json").write_text(json.dumps({
            "config": device.config, "original_config": device.golden,
            "files": device.files, "original_files": original_files,
            "events": device.events, "setup_count": namespace["setup_count"],
            "recoveries": namespace["recoveries"], "messages": namespace["messages"],
        }))

    namespace.update(duthosts=duthosts, tbinfo=tbinfo, parallel_run_context=parallel_run_context,
                     sanity_check=sanity_check, loganalyzer=loganalyzer, pytest_sessionfinish=pytest_sessionfinish)
    plugin.update({name: value for name, value in namespace.items()
                   if hasattr(value, "_pytestfixturefunction") and not isinstance(value, Mock)})
    plugin.update(device=device, pytest_sessionfinish=pytest_sessionfinish)


@pytest.mark.parametrize("feature,provisioned,leak,fail_setup", [
    ("enabled", False, False, False), ("disabled", False, False, False),
    ("enabled", True, False, False), ("disabled", True, False, False),
    ("enabled", False, True, False), ("disabled", True, False, True),
])
def test_grouped_module_lifecycle(tmp_path, feature, provisioned, leak, fail_setup):
    # Import this standalone harness, not tests/__init__.py or the DUT plugins.
    harness = Path(__file__).resolve()
    (tmp_path / "conftest.py").write_text(
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('harness', {!r})\n".format(str(harness)) +
        "harness = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(harness)\n"
        "harness.install_fixtures(globals(), {!r}, {!r}, {!r}, {!r})\n".format(
            feature, provisioned, leak, fail_setup))
    for index in range(2):
        body = ("def test_privileged(redfish_client):\n"
                "    redfish_client.privileged_get()\n"
                "def test_same_module(redfish_client):\n"
                "    redfish_client.privileged_get()\n")
        if leak and index == 0:
            body += ("    import conftest\n"
                     "    conftest.device.config['UNRELATED_LEAK'] = {'row': {'field': 'changed'}}\n")
        (tmp_path / "test_{}.py".format(index)).write_text(body)
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "--confcutdir", str(tmp_path)],
                            cwd=tmp_path, text=True, capture_output=True,
                            env=dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"))
    assert result.returncode == (1 if fail_setup else 0), result.stdout + result.stderr
    state = json.loads((tmp_path / "result.json").read_text())
    assert state["config"] == state["original_config"]
    assert state["files"] == state["original_files"]
    assert state["setup_count"] == 2
    assert len(state["recoveries"]) == int(leak)
    assert state["events"].count("sonic-cfggen -d --print-data") == 2
    if not fail_setup:
        assert state["events"].count("loganalyzer check") == 4
    events = state["events"]
    checks = [i for i, event in enumerate(events) if event == "sonic-cfggen -d --print-data"]
    stops = [i for i, event in enumerate(events) if event == "systemctl stop redfish"]
    assert stops[0] < checks[0] < stops[1] < checks[1]
    if leak:
        assert any(key.endswith("config_db_check_failed") and value for key, value in state["messages"])


def test_config_snapshot_preserves_absent_empty_and_operator_values():
    ns = utility_namespace()
    device = Device(provisioned=True)
    fields = device.config["REDFISH"]["certs"]
    fields["client_crt_cname"] = "operator's $(literal) common name"
    fields["ca_crt"] = ""
    del fields["server_key"]
    original = copy.deepcopy(device.config)
    snapshot = ns["snapshot_redfish_config"](device)
    ns["db_set"](device, "CONFIG_DB", "REDFISH|certs", ca_crt="test", server_key="test", client_crt_cname="test")
    ns["restore_redfish_config"](device, snapshot)
    assert device.config == original


@pytest.mark.parametrize("failure", ["backup", "stale_backup", "stop", "restore", "restart", "readiness"])
def test_state_failures_are_visible(failure):
    ns = utility_namespace()
    device = Device()
    path = ns["DEVICE_STATE_FILES"][0]
    device.files[path] = "original"
    snapshot = ns["snapshot_redfish_config"](device)
    if failure == "stale_backup":
        device.files[path + ns["BACKUP_SUFFIX"]] = "older original"
    if failure == "backup":
        device.fail_command = "cp -a {} {}{}".format(path, path, ns["BACKUP_SUFFIX"])
    if failure in ("backup", "stale_backup"):
        with pytest.raises((AssertionError, RuntimeError)):
            ns["back_up_device_state"](device)
        assert device.files[path] == "original"
        return
    saved = ns["back_up_device_state"](device)
    device.files[path] = "test"
    device.fail_command = {
        "stop": "systemctl stop redfish",
        "restore": "mv -f {}{} {}".format(path, ns["BACKUP_SUFFIX"], path),
        "restart": "systemctl start redfish",
    }.get(failure)
    if failure == "readiness":
        ns["wait_until"] = Mock(return_value=False)
    with pytest.raises((AssertionError, RuntimeError)):
        ns["reset_to_bootstrap"](device, snapshot, saved)
    if failure == "stop":
        assert device.files[path] == "test"
    else:
        assert "systemctl start redfish" in device.events
    if failure == "restore":
        assert device.files[path + ns["BACKUP_SUFFIX"]] == "original"


def test_all_redfish_fixture_dependents_have_compatible_scopes():
    fixtures = {}
    for path in (TESTS / "redfish").glob("*.py"):
        for node in ast.parse(path.read_text()).body:
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if ast.unparse(target) != "pytest.fixture":
                    continue
                scope = "function"
                if isinstance(decorator, ast.Call):
                    scope = next((ast.literal_eval(kw.value) for kw in decorator.keywords if kw.arg == "scope"), scope)
                fixtures.setdefault(node.name, []).append((scope, [arg.arg for arg in node.args.args]))
    ranks = {"function": 0, "class": 1, "module": 2, "package": 3, "session": 4}
    for name, definitions in fixtures.items():
        for scope, args in definitions:
            for arg in args:
                for dependency_scope, _ in fixtures.get(arg, []):
                    assert ranks[scope] <= ranks[dependency_scope], (name, scope, arg, dependency_scope)


def test_config_read_failure_does_not_become_missing_state():
    ns = utility_namespace()
    device = Device()
    device.fail_command = 'sonic-db-cli CONFIG_DB hexists "REDFISH|certs" server_crt'
    with pytest.raises(RuntimeError, match="injected failure"):
        ns["snapshot_redfish_config"](device)


def test_feature_startup_failure_restores_original_state():
    ns = utility_namespace()
    load_nodes(TESTS / "redfish/conftest.py", ns, {"redfish_feature_enabled"})
    device = Device(feature="disabled")
    ns["wait_until"] = Mock(return_value=False)
    finalizers = []
    request = SimpleNamespace(addfinalizer=finalizers.append)
    fixture = ns["redfish_feature_enabled"].__wrapped__(request, device, None)
    with pytest.raises(AssertionError, match="redfish container did not start"):
        next(fixture)
    assert len(finalizers) == 1
    finalizers[0]()
    assert device.config == device.golden
