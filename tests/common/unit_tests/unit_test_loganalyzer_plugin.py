"""Unit tests for the LogAnalyzer log maintenance setup."""

import importlib.util
import sys
import types
from pathlib import Path
from unittest import mock

import pytest


COMMON_TESTS_PATH = Path(__file__).resolve().parents[1]
MODULE_PATH = COMMON_TESTS_PATH / "plugins" / "loganalyzer" / "__init__.py"


def _load_target_module():
    package_name = "unit_target_loganalyzer"

    package_stub = types.ModuleType(package_name)
    package_stub.__path__ = [str(MODULE_PATH.parent)]

    loganalyzer_stub = types.ModuleType(
        "{}.loganalyzer".format(package_name)
    )
    loganalyzer_stub.LogAnalyzer = object

    class DisableLogrotateCronContext:
        def __init__(self, node):
            self.node = node

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    loganalyzer_stub.DisableLogrotateCronContext = (
        DisableLogrotateCronContext
    )

    bug_handler_stub = types.ModuleType(
        "{}.bug_handler_helper".format(package_name)
    )
    bug_handler_stub.get_bughandler_instance = mock.Mock()

    tests_stub = types.ModuleType("tests")
    tests_stub.__path__ = []
    common_stub = types.ModuleType("tests.common")
    common_stub.__path__ = []
    helpers_stub = types.ModuleType("tests.common.helpers")
    helpers_stub.__path__ = []

    errors_stub = types.ModuleType("tests.common.errors")

    class RunAnsibleModuleFail(Exception):
        def __init__(self, message, results=None):
            super().__init__(message)
            self.results = results

    errors_stub.RunAnsibleModuleFail = RunAnsibleModuleFail

    parallel_stub = types.ModuleType("tests.common.helpers.parallel")
    parallel_stub.parallel_run = mock.Mock()
    parallel_stub.reset_ansible_local_tmp = lambda target: target

    stubs = {
        package_name: package_stub,
        "{}.loganalyzer".format(package_name): loganalyzer_stub,
        "{}.bug_handler_helper".format(package_name): bug_handler_stub,
        "tests": tests_stub,
        "tests.common": common_stub,
        "tests.common.errors": errors_stub,
        "tests.common.helpers": helpers_stub,
        "tests.common.helpers.parallel": parallel_stub,
    }

    spec = importlib.util.spec_from_file_location(
        package_name,
        MODULE_PATH,
        submodule_search_locations=[str(MODULE_PATH.parent)]
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def loganalyzer_plugin():
    return _load_target_module()


def test_logrotate_and_cleanup_use_one_remote_call(loganalyzer_plugin):
    node = mock.Mock(hostname="dut")
    node.shell.return_value = {"rc": 0, "stdout": "", "stderr": ""}

    loganalyzer_plugin.analyzer_logrotate(node=node)

    node.shell.assert_called_once_with(
        loganalyzer_plugin.LOGROTATE_AND_CLEANUP_CMD
    )
    command = node.shell.call_args.args[0]
    assert "/usr/sbin/logrotate -f /etc/logrotate.conf" in command
    assert "logrotate_failed=1" in command
    assert "df -Pk /var/log" in command
    assert (
        "find /var/log -xdev -regextype posix-extended -type f "
        "-regex '.*\\.[0-9]+\\.gz$' -delete"
        in command
    )
    assert (
        '"$usage" -ge {}'.format(
            loganalyzer_plugin.VAR_LOG_CLEANUP_THRESHOLD
        )
        in command
    )
    assert (
        '"$available_kb" -lt {}'.format(
            loganalyzer_plugin.VAR_LOG_MIN_FREE_KB
        )
        in command
    )
    assert command.count("if var_log_is_unsafe; then") == 2


@pytest.mark.parametrize("return_code", [90, 91])
def test_log_maintenance_failure_stops_test_setup(
    loganalyzer_plugin,
    return_code
):
    node = mock.Mock(hostname="dut")
    node.shell.side_effect = loganalyzer_plugin.RunAnsibleModuleFail(
        "maintenance failed",
        {
            "rc": return_code,
            "stdout": "/var/log usage is 95%",
            "stderr": "/var/log usage remains above the safe limit",
        }
    )

    with pytest.raises(RuntimeError, match="safe /var/log usage") as error:
        loganalyzer_plugin.analyzer_logrotate(node=node)

    assert "/var/log usage is 95%" in str(error.value)
    assert "remains above the safe limit" in str(error.value)


def test_regular_logrotate_failure_remains_nonfatal(
    loganalyzer_plugin,
    monkeypatch
):
    node = mock.Mock(hostname="dut")
    node.shell.side_effect = loganalyzer_plugin.RunAnsibleModuleFail(
        "logrotate failed",
        {"rc": 1}
    )
    warning = mock.Mock()
    monkeypatch.setattr(loganalyzer_plugin.logging, "warning", warning)

    loganalyzer_plugin.analyzer_logrotate(node=node)

    warning.assert_called_once()
