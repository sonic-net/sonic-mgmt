"""Exercise the real telemetry lifecycle without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_telemetry_lifecycle.py -v
"""

import ast
from contextlib import contextmanager
from copy import deepcopy
import logging
from pathlib import Path
import re
import shlex
from unittest.mock import Mock

import pytest


TESTS_DIR = Path(__file__).resolve().parents[2]
HELPER_PATH = TESTS_DIR / "common" / "helpers" / "telemetry_helper.py"
IP_PATH = TESTS_DIR / "ip" / "test_mgmt_ipv6_only.py"


def _assert(condition, message="Telemetry check failed"):
    assert condition, message


class TelemetryHarness:
    def __init__(self, table="GNMI", configured=True, user_auth=None, client_auth="true",
                 platform="x86_64-kvm_x86_64-r0"):
        self.table = table
        self.config = {}
        if configured or table == "TELEMETRY":
            self.config[table + "|gnmi"] = {"port": "50052"}
            if client_auth is not None:
                self.config[table + "|gnmi"]["client_auth"] = client_auth
        if user_auth is not None:
            self.config.setdefault(table + "|gnmi", {})["user_auth"] = user_auth
        self.original = deepcopy(self.config)
        self.events = []
        self.fail_command = None
        self.get_output = "SAI_PORT_STAT_IF_IN_ERRORS: 0"
        self.service_results = iter(())
        self.tcp_results = iter(())
        self.container_running = True
        self.dut = Mock(mgmt_ip="192.0.2.1", facts={"platform": platform})
        self.dut.shell.side_effect = self.shell
        self.dut.service.side_effect = lambda **kwargs: self.events.append(("restart", kwargs))
        self.localhost = Mock()
        self.ptfhost = Mock()
        self.ptfhost.stat.return_value = {"stat": {"exists": True}}
        harness = self

        class Environment:
            TELEMETRY_MODE = 0

            def __init__(self, dut, mode):
                selected_table = table if harness.container_running else "GNMI"
                self.gnmi_config_table = selected_table
                self.gnmi_container = "gnmi" if selected_table == "GNMI" else "telemetry"
                self.gnmi_port = int(harness.config.get(selected_table + "|gnmi", {}).get("port", "8080"))

        self.namespace = {
            "contextmanager": contextmanager,
            "GNMIEnvironment": Environment,
            "py_assert": _assert,
            "pytest_assert": _assert,
            "get_mgmt_ipv6": Mock(return_value="2001:db8::1"),
            "wait_until": Mock(side_effect=self.wait_service),
            "wait_tcp_connection": Mock(side_effect=self.wait_tcp),
            "logger": logging.getLogger(__name__),
            "shlex": shlex,
            "re": re,
            "localhost": self.localhost,
            "ptfhost": self.ptfhost,
            "gnxi_path": "/gnxi/",
        }
        functions = [node for node in ast.parse(HELPER_PATH.read_text()).body
                     if isinstance(node, ast.FunctionDef)]
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(HELPER_PATH), "exec"), self.namespace)
        worker = next(node for node in ast.walk(ast.parse(IP_PATH.read_text()))
                      if isinstance(node, ast.FunctionDef) and node.name == "verify_telemetry_output_ipv6_only")
        exec(compile(ast.Module(body=[worker], type_ignores=[]), str(IP_PATH), "exec"), self.namespace)

    def shell(self, command, **kwargs):
        words = shlex.split(command)
        self.events.append(("shell", words))
        if self.fail_command is not None and self.fail_command(words):
            raise RuntimeError("injected command failure")
        stdout = ""
        if words[:2] == ["sonic-db-cli", "CONFIG_DB"]:
            operation, key, field = words[2].upper(), words[3], words[4]
            if operation == "HGET":
                stdout = self.config.get(key, {}).get(field, "")
            elif operation == "HSET":
                self.config.setdefault(key, {})[field] = words[5]
            elif operation == "HDEL":
                self.config.get(key, {}).pop(field, None)
            else:
                raise AssertionError(command)
        elif words[0] == "~/gnmi_get":
            self.events.append(("get", words))
            stdout = self.get_output
        elif words[:2] not in (["systemctl", "reset-failed"], ["docker", "cp"]):
            raise AssertionError("Unexpected shell command: " + command)
        return {"stdout": stdout, "stdout_lines": stdout.splitlines(), "rc": 0}

    def wait_service(self, *args):
        ready = next(self.service_results, True)
        self.events.append(("service-ready", ready))
        return ready

    def wait_tcp(self, localhost, address, port, timeout_s):
        ready = next(self.tcp_results, True)
        self.events.append(("tcp-ready", address, port, timeout_s, ready))
        return ready

    def context(self, ipv6=True):
        return self.namespace["setup_streaming_telemetry_context"](
            ipv6, self.dut, self.localhost, self.ptfhost, "/gnxi/")

    def run_worker(self):
        self.namespace["verify_telemetry_output_ipv6_only"](self.dut)

    def assert_restored(self):
        assert {key: value for key, value in self.config.items() if value} == self.original


@pytest.mark.parametrize("table", ["GNMI", "TELEMETRY"])
@pytest.mark.parametrize("user_auth", [None, "password", "none"])
@pytest.mark.parametrize("platform,port", [
    ("x86_64-kvm_x86_64-r0", "Ethernet0"),
    ("arm64-c8220tg_48a_o-r0", "Ethernet1"),
])
def test_worker_waits_after_restart_and_restores_auth(table, user_auth, platform, port):
    harness = TelemetryHarness(table=table, user_auth=user_auth, platform=platform)
    harness.run_worker()
    get_index = next(i for i, event in enumerate(harness.events) if event[0] == "get")
    assert [event[0] for event in harness.events[get_index - 4:get_index]] == [
        "restart", "service-ready", "tcp-ready", "shell"]
    assert harness.events[get_index - 2] == ("tcp-ready", "2001:db8::1", 50052, 60, True)
    get = harness.events[get_index][1]
    assert get[get.index("-xpath") + 1] == "COUNTERS/" + port
    assert get[get.index("-target_addr") + 1] == "[2001:db8::1]:50052"
    assert sum(event[0] == "get" for event in harness.events) == 1
    assert harness.events[-1] == ("service-ready", True)
    harness.assert_restored()


def test_worker_refreshes_port_after_creating_config():
    harness = TelemetryHarness(configured=False)
    harness.run_worker()
    assert all(event[2] == 50052 for event in harness.events if event[0] == "tcp-ready")
    harness.assert_restored()


@pytest.mark.parametrize("configured", [True, False])
@pytest.mark.parametrize("user_auth", [None, "password", "none"])
def test_get_failure_propagates_and_restores_all_auth(configured, user_auth):
    harness = TelemetryHarness(configured=configured, user_auth=user_auth)
    harness.fail_command = lambda words: words[0] == "~/gnmi_get"
    with pytest.raises(RuntimeError, match="injected command failure"):
        harness.run_worker()
    assert sum(event[0] == "shell" and event[1][0] == "~/gnmi_get" for event in harness.events) == 1
    assert harness.events[-1] == ("service-ready", True)
    harness.assert_restored()


def test_missing_counter_remains_a_failure():
    harness = TelemetryHarness(configured=False, user_auth="password")
    harness.get_output = "some other counter"
    with pytest.raises(AssertionError, match="SAI_PORT_STAT_IF_IN_ERRORS not found"):
        harness.run_worker()
    harness.assert_restored()


@pytest.mark.parametrize("gate", ["service", "tcp"])
def test_worker_does_not_get_after_readiness_failure(gate):
    harness = TelemetryHarness(configured=False)
    if gate == "service":
        harness.service_results = iter([True, False, True])
    else:
        harness.tcp_results = iter([True, False, True])
    with pytest.raises(AssertionError, match="not started|Failed to establish TCP"):
        harness.run_worker()
    assert not any(event[0] == "get" for event in harness.events)
    harness.assert_restored()


def test_worker_restoration_readiness_failure_is_not_ignored():
    harness = TelemetryHarness(configured=False)
    harness.service_results = iter([True, True, False])
    with pytest.raises(AssertionError, match="after restoring user authentication"):
        harness.run_worker()
    harness.assert_restored()


@pytest.mark.parametrize("table", ["GNMI", "TELEMETRY"])
@pytest.mark.parametrize("failed_restart", [1, 2])
def test_failed_restart_restores_auth_in_original_table(table, failed_restart):
    harness = TelemetryHarness(table=table, configured=False, user_auth="cert")
    restarts = 0

    def restart(**kwargs):
        nonlocal restarts
        restarts += 1
        harness.events.append(("restart", kwargs))
        harness.container_running = restarts != failed_restart
        if not harness.container_running:
            raise RuntimeError("restart left the container stopped")

    harness.dut.service.side_effect = restart
    with pytest.raises(RuntimeError, match="restart left the container stopped"):
        harness.run_worker()
    assert harness.container_running
    harness.assert_restored()


@pytest.mark.parametrize("ipv6", [True, False])
@pytest.mark.parametrize("client_auth", ["true", "false", None])
def test_context_restores_existing_config_on_body_failure(ipv6, client_auth):
    harness = TelemetryHarness(client_auth=client_auth)
    with pytest.raises(ValueError, match="body failed"):
        with harness.context(ipv6):
            harness.config["GNMI|gnmi"]["client_auth"] = "false"
            raise ValueError("body failed")
    harness.assert_restored()
    expected_ip = "2001:db8::1" if ipv6 else "192.0.2.1"
    assert harness.events[-1] == ("tcp-ready", expected_ip, 50052, 60, True)


@pytest.mark.parametrize("phase", ["create", "environment", "snapshot", "restart", "service", "tcp", "copy", "body"])
def test_partial_setup_and_body_failures_remove_temporary_config(phase):
    harness = TelemetryHarness(configured=False)
    if phase == "create":
        harness.fail_command = lambda words: words[:5] == [
            "sonic-db-cli", "CONFIG_DB", "hset", "GNMI|certs", "ca_crt"]
    elif phase == "environment":
        harness.namespace["GNMIEnvironment"] = Mock(side_effect=RuntimeError("environment failed"))
    elif phase == "snapshot":
        harness.fail_command = lambda words: words[:5] == [
            "sonic-db-cli", "CONFIG_DB", "HGET", "GNMI|gnmi", "client_auth"]
    elif phase == "restart":
        harness.dut.service.side_effect = [RuntimeError("restart failed"), None]
    elif phase == "service":
        harness.service_results = iter([False])
    elif phase == "tcp":
        harness.tcp_results = iter([False, True])
    elif phase == "copy":
        harness.fail_command = lambda words: words[:2] == ["docker", "cp"]

    with pytest.raises((RuntimeError, AssertionError), match="failure|failed|not started|Failed to establish"):
        with harness.context():
            if phase != "body":
                pytest.fail("setup unexpectedly yielded")
            raise RuntimeError("body failed")
    harness.assert_restored()


@pytest.mark.parametrize("failure", ["restore", "tcp"])
def test_cleanup_failure_still_removes_temporary_config(failure):
    harness = TelemetryHarness(configured=False)
    with pytest.raises((RuntimeError, AssertionError), match="failure|after restoring client authentication"):
        with harness.context():
            if failure == "restore":
                harness.fail_command = lambda words: words[:6] == [
                    "sonic-db-cli", "CONFIG_DB", "HSET", "GNMI|gnmi", "client_auth", "true"]
            else:
                harness.tcp_results = iter([False])
    harness.assert_restored()


def test_config_check_failure_does_not_attempt_cleanup():
    harness = TelemetryHarness()
    harness.fail_command = lambda words: words[:5] == [
        "sonic-db-cli", "CONFIG_DB", "HGET", "GNMI|gnmi", "port"]
    with pytest.raises(RuntimeError, match="injected command failure"):
        with harness.context():
            pytest.fail("should not yield")
    assert harness.dut.shell.call_count == 1
    harness.dut.service.assert_not_called()
    harness.assert_restored()


def test_config_mutation_errors_are_not_ignored():
    harness = TelemetryHarness(configured=False)
    with harness.context():
        pass
    for invocation in harness.dut.shell.call_args_list:
        words = shlex.split(invocation.args[0])
        if words[:2] == ["sonic-db-cli", "CONFIG_DB"] and words[2].upper() in ("HSET", "HDEL"):
            assert invocation.kwargs["module_ignore_errors"] is False
