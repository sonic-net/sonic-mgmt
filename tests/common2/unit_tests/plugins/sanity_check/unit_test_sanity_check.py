"""Unit tests for sanity check result aggregation."""

import importlib.util
import sys
import types
from pathlib import Path

import pytest


def _find_repo_root():
    current_path = Path(__file__).resolve()
    for parent in current_path.parents:
        if (parent / ".git").exists():
            return parent
    raise RuntimeError("Unable to locate repository root from test path")


MODULE_PATH = _find_repo_root() / "tests" / "common" / "plugins" / "sanity_check" / "__init__.py"


def _register_stub_module(module_name, **attributes):
    module = types.ModuleType(module_name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


def _load_sanity_check_module():
    module_name = "sanity_check_under_test"
    original_modules = {}

    stub_modules = {
        "tests": _register_stub_module("tests"),
        "tests.common": _register_stub_module("tests.common"),
        "tests.common.helpers": _register_stub_module("tests.common.helpers"),
        "tests.common.plugins": _register_stub_module("tests.common.plugins"),
        "tests.common.plugins.sanity_check": _register_stub_module("tests.common.plugins.sanity_check"),
        "tests.common.helpers.multi_thread_utils": _register_stub_module(
            "tests.common.helpers.multi_thread_utils", SafeThreadPoolExecutor=object
        ),
        "tests.common.helpers.parallel_utils": _register_stub_module(
            "tests.common.helpers.parallel_utils", ParallelCoordinator=object, ParallelStatus=object
        ),
        "tests.common.plugins.sanity_check.constants": _register_stub_module(
            "tests.common.plugins.sanity_check.constants",
            STAGE_PRE_TEST="stage_pre_test",
            STAGE_POST_TEST="stage_post_test",
            RECOVER_METHODS={"adaptive": {}},
            PRE_SANITY_CHECK_FAILED_RC=10,
            POST_SANITY_CHECK_FAILED_RC=11,
            SANITY_CHECK_FAILED_RC=12,
            INFRA_CHECK_ITEMS=[],
        ),
        "tests.common.plugins.sanity_check.checks": _register_stub_module(
            "tests.common.plugins.sanity_check.checks", CHECK_ITEMS=[], __all__=[]
        ),
        "tests.common.plugins.sanity_check.recover": _register_stub_module(
            "tests.common.plugins.sanity_check.recover",
            recover=lambda *args, **kwargs: None,
            recover_chassis=lambda *args, **kwargs: None
        ),
        "tests.common.helpers.assertions": _register_stub_module(
            "tests.common.helpers.assertions", pytest_assert=lambda condition, message="": None
        ),
        "tests.common.helpers.custom_msg_utils": _register_stub_module(
            "tests.common.helpers.custom_msg_utils", add_custom_msg=lambda *args, **kwargs: None
        ),
        "tests.common.helpers.constants": _register_stub_module(
            "tests.common.helpers.constants", DUT_CHECK_NAMESPACE="dut"
        ),
    }

    try:
        for name, module in stub_modules.items():
            original_modules[name] = sys.modules.get(name)
            sys.modules[name] = module

        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(module_name, None)
        for name, previous_module in original_modules.items():
            if previous_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous_module


class FakeRequest:
    """Minimal request stub for do_checks unit tests."""

    def __init__(self, fixtures):
        self._fixtures = fixtures

    def getfixturevalue(self, name):
        fixture = self._fixtures[name]
        if isinstance(fixture, BaseException):
            raise fixture
        return fixture


@pytest.mark.unit_test
def test_do_checks_keeps_existing_result_aggregation():
    """Test that do_checks still aggregates list and dict results."""
    sanity_check = _load_sanity_check_module()

    request = FakeRequest({
        "check_interfaces": lambda *args, **kwargs: {"failed": False, "check_item": "interfaces"},
        "check_bgp": lambda *args, **kwargs: [
            {"failed": False, "check_item": "bgp", "host": "dut1"},
            {"failed": True, "check_item": "bgp", "host": "dut2"},
        ],
    })

    results = sanity_check.do_checks(request, ["check_interfaces", "check_bgp"], stage="stage_pre_test")

    assert results == [
        {"failed": False, "check_item": "interfaces"},
        {"failed": False, "check_item": "bgp", "host": "dut1"},
        {"failed": True, "check_item": "bgp", "host": "dut2"},
    ]


@pytest.mark.unit_test
def test_do_checks_marks_fixture_exception_as_failed_result():
    """Test that do_checks converts a check exception into a failed result."""
    sanity_check = _load_sanity_check_module()

    def _failing_check(*args, **kwargs):
        raise RuntimeError("networking uptime lookup failed")

    request = FakeRequest({
        "check_processes": _failing_check,
    })

    results = sanity_check.do_checks(request, ["check_processes"], stage="stage_pre_test")

    assert len(results) == 1
    assert results[0]["failed"] is True
    assert results[0]["check_item"] == "processes"
    assert "check_processes" in results[0]["failed_reason"]
    assert "networking uptime lookup failed" in results[0]["failed_reason"]


@pytest.mark.unit_test
def test_do_checks_marks_fixture_lookup_exception_as_failed_result():
    """Test that fixture lookup exceptions are handled the same way as execution exceptions."""
    sanity_check = _load_sanity_check_module()

    request = FakeRequest({
        "check_monit": RuntimeError("fixture initialization failed"),
    })

    results = sanity_check.do_checks(request, ["check_monit"], stage="stage_post_test")

    assert len(results) == 1
    assert results[0]["failed"] is True
    assert results[0]["check_item"] == "monit"
    assert "fixture initialization failed" in results[0]["failed_reason"]
