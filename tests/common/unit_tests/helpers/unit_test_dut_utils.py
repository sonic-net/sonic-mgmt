"""Unit tests for DPU NAT cache validation in dut_utils."""

import contextlib
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "helpers" / "dut_utils.py"
NAT_RULE = (
    "DNAT tcp -- anywhere anywhere tcp dpt:5021 "
    "to:169.254.200.1:22"
)


def _load_target_module():
    allure_stub = types.ModuleType("allure")
    allure_stub.step = lambda *args, **kwargs: contextlib.nullcontext()
    allure_stub.attach = types.SimpleNamespace(file=mock.Mock())

    pytest_stub = types.ModuleType("pytest")
    pytest_stub.skip = mock.Mock()

    tests_stub = types.ModuleType("tests")
    tests_stub.__path__ = []
    common_stub = types.ModuleType("tests.common")
    common_stub.__path__ = []
    helpers_stub = types.ModuleType("tests.common.helpers")
    helpers_stub.__path__ = []
    connections_stub = types.ModuleType("tests.common.connections")
    connections_stub.__path__ = []

    assertions_stub = types.ModuleType("tests.common.helpers.assertions")
    assertions_stub.pytest_assert = mock.Mock()

    utilities_stub = types.ModuleType("tests.common.utilities")
    utilities_stub.get_host_visible_vars = mock.Mock()
    utilities_stub.wait_until = mock.Mock()
    utilities_stub.get_dut_current_passwd = mock.Mock()
    utilities_stub.update_console_creds = mock.Mock()

    errors_stub = types.ModuleType("tests.common.errors")
    errors_stub.RunAnsibleModuleFail = type(
        "RunAnsibleModuleFail", (Exception,), {}
    )

    console_host_stub = types.ModuleType(
        "tests.common.connections.console_host"
    )
    console_host_stub.ConsoleHost = type("ConsoleHost", (), {})
    console_host_stub.CONSOLE_LINECARD = "linecard"

    linecard_stub = types.ModuleType(
        "tests.common.connections.linecard_console_conn"
    )
    linecard_stub.UnsupportedPlatformError = type(
        "UnsupportedPlatformError", (Exception,), {}
    )

    base_console_stub = types.ModuleType(
        "tests.common.connections.base_console_conn"
    )
    base_console_stub.CONSOLE_SSH_CISCO_CONFIG = {}
    base_console_stub.CONSOLE_SSH_DIGI_CONFIG = {}
    base_console_stub.CONSOLE_SSH_SONIC_CONFIG = {}

    mellanox_stub = types.ModuleType("tests.common.mellanox_data")
    mellanox_stub.is_mellanox_device = mock.Mock()
    mellanox_stub.is_issu_enabled = mock.Mock()

    stubs = {
        "allure": allure_stub,
        "pytest": pytest_stub,
        "tests": tests_stub,
        "tests.common": common_stub,
        "tests.common.helpers": helpers_stub,
        "tests.common.helpers.assertions": assertions_stub,
        "tests.common.utilities": utilities_stub,
        "tests.common.errors": errors_stub,
        "tests.common.connections": connections_stub,
        "tests.common.connections.console_host": console_host_stub,
        "tests.common.connections.linecard_console_conn": linecard_stub,
        "tests.common.connections.base_console_conn": base_console_stub,
        "tests.common.mellanox_data": mellanox_stub,
    }

    spec = importlib.util.spec_from_file_location(
        "unit_target_dut_utils", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


class TestDpuNatCacheValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dut_utils = _load_target_module()

    def setUp(self):
        self.duthost = mock.Mock(hostname="npu-01")
        self.cache = mock.Mock()
        self.request = mock.Mock()
        self.request.config.cache = self.cache

    def test_cache_miss_does_not_probe_live_rules(self):
        """Do not add an iptables probe when the cache already requests setup."""
        self.cache.get.return_value = False

        self.assertFalse(
            self.dut_utils.is_enabled_nat_for_dpu(
                self.duthost, self.request
            )
        )

        self.duthost.shell.assert_not_called()

    def test_cached_nat_is_accepted_when_live_rule_exists(self):
        """Keep cached NAT state only when a matching live DNAT rule exists."""
        self.cache.get.return_value = True
        self.duthost.shell.return_value = {"stdout": NAT_RULE}

        self.assertTrue(
            self.dut_utils.is_enabled_nat_for_dpu(
                self.duthost, self.request
            )
        )

        self.duthost.shell.assert_called_once_with(
            "sudo iptables -t nat -L"
        )
        self.cache.set.assert_not_called()

    def test_stale_cache_is_cleared_when_live_rule_is_missing(self):
        """Clear stale cached NAT state so the fixture re-enables forwarding."""
        self.cache.get.return_value = True
        self.duthost.shell.return_value = {"stdout": ""}

        self.assertFalse(
            self.dut_utils.is_enabled_nat_for_dpu(
                self.duthost, self.request
            )
        )

        self.cache.set.assert_called_once_with(
            "nat_enabled_on_npu-01", False
        )

    def test_successful_nat_check_sets_cache(self):
        """Cache NAT state after post-configuration verification succeeds."""
        self.duthost.shell.return_value = {"stdout": NAT_RULE}

        self.assertTrue(
            self.dut_utils.check_nat_is_enabled_and_set_cache(
                self.duthost, self.request
            )
        )

        self.cache.set.assert_called_once_with(
            "nat_enabled_on_npu-01", True
        )

    def test_failed_nat_check_does_not_set_cache(self):
        """Reject and avoid caching a NAT configuration with no DNAT rule."""
        self.duthost.shell.return_value = {"stdout": ""}

        with self.assertRaisesRegex(
            Exception, "NAT is not enabled successfully"
        ):
            self.dut_utils.check_nat_is_enabled_and_set_cache(
                self.duthost, self.request
            )

        self.cache.set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
