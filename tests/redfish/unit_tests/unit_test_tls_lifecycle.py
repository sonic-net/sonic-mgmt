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
        self.start_limit_exhausted = False
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
        elif command == "systemctl reset-failed redfish.service":
            self.start_limit_exhausted = False
        elif command == "systemctl start redfish":
            if self.start_limit_exhausted:
                raise RuntimeError("start of redfish.service was attempted too often")
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


def is_pytest_fixture(value):
    """Recognize both pytest fixture wrappers without accepting dynamic Mock attributes."""
    return not isinstance(value, Mock) and (
        hasattr(value, "_pytestfixturefunction") or hasattr(value, "_fixture_function_marker"))


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
                   if is_pytest_fixture(value)})
    plugin.update(device=device, pytest_sessionfinish=pytest_sessionfinish)


@pytest.mark.parametrize("marker", ["_pytestfixturefunction", "_fixture_function_marker"])
def test_fixture_discovery_accepts_both_pytest_markers(marker):
    assert is_pytest_fixture(SimpleNamespace(**{marker: object()}))
    assert not is_pytest_fixture(Mock(**{marker: object()}))


def test_fixture_discovery_ignores_non_fixtures_and_dynamic_mocks():
    assert not is_pytest_fixture(lambda: None)
    assert not is_pytest_fixture(Mock())


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


@pytest.mark.parametrize("failure", ["stat", "copy", "partial_copy"])
def test_later_backup_failure_rolls_back_and_allows_retry(monkeypatch, failure):
    ns = utility_namespace()
    device = Device(provisioned=True)
    paths = ns["DEVICE_STATE_FILES"]
    suffix = ns["BACKUP_SUFFIX"]
    device.files.update({path: "original:" + path for path in paths})
    original_files = device.files.copy()
    original_config = copy.deepcopy(device.config)
    stat = device.stat
    shell = device.shell
    copy_command = "cp -a {0} {0}{1}".format(paths[1], suffix)
    failure_error = RuntimeError("later backup " + failure)

    def fail_stat(path):
        if failure == "stat" and path == paths[1]:
            raise failure_error
        return stat(path)

    def fail_copy(command, **kwargs):
        if failure != "stat" and command == copy_command:
            device.events.append(command)
            if failure == "partial_copy":
                device.files[paths[1] + suffix] = "partial copy"
            raise failure_error
        return shell(command, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(device, "stat", fail_stat)
        patcher.setattr(device, "shell", fail_copy)
        with pytest.raises(RuntimeError) as error:
            ns["back_up_device_state"](device)
    assert error.value is failure_error
    assert device.files == original_files
    assert device.config == original_config
    assert "rm -f {}{}".format(paths[0], suffix) in device.events
    if failure != "stat":
        assert "rm -f {}{}".format(paths[1], suffix) in device.events

    # No stale backups from the failed attempt may poison the next module.
    saved = ns["back_up_device_state"](device)
    assert saved == list(paths)
    for path in paths:
        assert device.files[path + suffix] == original_files[path]
        device.files[path] = "test replacement"
    ns["restore_device_state"](device, saved)
    assert device.files == original_files


def test_later_stale_backup_is_preserved_without_creating_earlier_backups():
    ns = utility_namespace()
    device = Device()
    paths = ns["DEVICE_STATE_FILES"]
    device.files.update({path: "original:" + path for path in paths})
    device.files[paths[1] + ns["BACKUP_SUFFIX"]] = "pre-existing backup"
    original_files = device.files.copy()

    with pytest.raises(AssertionError, match="Device state backup already exists"):
        ns["back_up_device_state"](device)

    assert device.files == original_files
    assert device.events == []


def test_backup_preflight_stat_failure_does_not_create_backups(monkeypatch):
    ns = utility_namespace()
    device = Device()
    paths = ns["DEVICE_STATE_FILES"]
    device.files.update({path: "original:" + path for path in paths})
    original_files = device.files.copy()
    stat = device.stat

    def fail_later_preflight(path):
        if path == paths[1] + ns["BACKUP_SUFFIX"]:
            raise RuntimeError("preflight stat failed")
        return stat(path)

    monkeypatch.setattr(device, "stat", fail_later_preflight)
    with pytest.raises(RuntimeError, match="preflight stat failed"):
        ns["back_up_device_state"](device)

    assert device.files == original_files
    assert device.events == []


def test_backup_rollback_logs_failure_and_continues(monkeypatch):
    ns = utility_namespace()
    device = Device()
    paths = ns["DEVICE_STATE_FILES"]
    suffix = ns["BACKUP_SUFFIX"]
    device.files.update({path: "original:" + path for path in paths})
    shell = device.shell
    failure_error = RuntimeError("copy failed")

    def fail_copy_and_first_cleanup(command, **kwargs):
        if command == "cp -a {0} {0}{1}".format(paths[1], suffix):
            device.files[paths[1] + suffix] = "partial copy"
            raise failure_error
        if command == "rm -f {}{}".format(paths[0], suffix):
            raise RuntimeError("cleanup failed")
        return shell(command, **kwargs)

    monkeypatch.setattr(device, "shell", fail_copy_and_first_cleanup)
    with pytest.raises(RuntimeError) as error:
        ns["back_up_device_state"](device)

    assert error.value is failure_error
    assert device.files[paths[0] + suffix] == "original:" + paths[0]
    assert paths[1] + suffix not in device.files
    assert all(device.files[path] == "original:" + path for path in paths)
    ns["logger"].exception.assert_called_once_with(
        "Failed to remove partial backup: %s", paths[0] + suffix)


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


@pytest.mark.parametrize("start_limit_exhausted", [False, True])
def test_restoration_resets_start_limit_before_start(start_limit_exhausted):
    ns = utility_namespace()
    device = Device(provisioned=True)
    device.start_limit_exhausted = start_limit_exhausted
    device.files.update({path: "original:" + path for path in ns["DEVICE_STATE_FILES"]})
    original_files = device.files.copy()
    snapshot = ns["snapshot_redfish_config"](device)
    saved = ns["back_up_device_state"](device)
    device.files.update({path: "test" for path in ns["DEVICE_STATE_FILES"]})
    ns["db_set"](device, "CONFIG_DB", "REDFISH|certs", client_crt_cname="test")

    ns["reset_to_bootstrap"](device, snapshot, saved)

    assert device.config == device.golden
    assert device.files == original_files
    assert device.running
    assert not device.start_limit_exhausted
    events = device.events
    stop = events.index("systemctl stop redfish")
    remove = events.index("docker rm -f redfish")
    reset = events.index("systemctl reset-failed redfish.service")
    start = events.index("systemctl start redfish")
    ready = events.index("docker exec redfish supervisorctl status bmcweb")
    assert stop < remove < reset < start < ready
    assert events.count("systemctl reset-failed redfish.service") == 1


@pytest.mark.parametrize("failure", ["backup", "stale_backup", "stop", "restore", "reset", "restart", "readiness"])
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
        "reset": "systemctl reset-failed redfish.service",
        "restart": "systemctl start redfish",
    }.get(failure)
    if failure == "readiness":
        ns["wait_until"] = Mock(return_value=False)
    with pytest.raises((AssertionError, RuntimeError)) as error:
        ns["reset_to_bootstrap"](device, snapshot, saved)
    if failure == "stop":
        assert device.files[path] == "test"
        assert "systemctl reset-failed redfish.service" not in device.events
        assert "systemctl start redfish" not in device.events
    else:
        assert "Failed to restore Redfish device state:" in str(error.value)
        reset = device.events.index("systemctl reset-failed redfish.service")
        start = device.events.index("systemctl start redfish")
        assert reset < start
        if failure == "readiness":
            ns["wait_until"].assert_called_once_with(
                ns["BMCWEB_READY_TIMEOUT"], ns["BMCWEB_READY_POLL"], 0, ns["_bmcweb_running"], device)
        else:
            assert start < device.events.index("docker exec redfish supervisorctl status bmcweb")
            assert "injected failure: " + device.fail_command in str(error.value)
        if failure in ("restart", "readiness"):
            assert "bmcweb did not restart after restoring device state" in str(error.value)
        if failure == "reset":
            assert device.running, "successful startup must not hide a failed reset"
    if failure == "restore":
        assert device.files[path + ns["BACKUP_SUFFIX"]] == "original"


def test_failed_reset_with_exhausted_start_limit_aggregates_errors():
    ns = utility_namespace()
    device = Device()
    device.start_limit_exhausted = True
    device.fail_command = "systemctl reset-failed redfish.service"
    snapshot = ns["snapshot_redfish_config"](device)

    with pytest.raises(AssertionError, match="Failed to restore Redfish device state:") as error:
        ns["reset_to_bootstrap"](device, snapshot)

    message = str(error.value)
    assert "injected failure: systemctl reset-failed redfish.service" in message
    assert "start of redfish.service was attempted too often" in message
    assert "bmcweb did not restart after restoring device state" in message
    assert not device.running
    assert device.start_limit_exhausted
    assert device.events[-3:] == [
        "systemctl reset-failed redfish.service", "systemctl start redfish",
        "docker exec redfish supervisorctl status bmcweb"]


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
