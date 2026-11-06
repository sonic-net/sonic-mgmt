# Copyright 2026 Nexthop Systems Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the gNMI debug dump and its dedup marker in tests/common/helpers/gnmi_utils.py,
and for the code that calls it on failure: the tests/gnmi failure hook and gnmi_tls.

Run (from the repository root):
    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/helpers/unit_test_gnmi_utils.py -v
"""
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = REPO_ROOT / "tests/common/helpers/gnmi_utils.py"

pytest_plugins = ["pytester"]


@pytest.fixture
def gu(monkeypatch):
    """Load gnmi_utils.py with a GNMIEnvironment that doesn't query the DUT, and a mock logger."""
    spec = importlib.util.spec_from_file_location("unit_target_gnmi_utils", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class FakeGnmiEnvironment:
        GNMI_MODE = "gnmi"

        def __init__(self, duthost, mode):
            self.gnmi_container = "gnmi"
            self.gnmi_port = 50052

    monkeypatch.setattr(module, "GNMIEnvironment", FakeGnmiEnvironment)
    # Under --noconftest, pytest.ini's log format names a record field that only tests/conftest.py adds.
    monkeypatch.setattr(module, "logger", MagicMock())
    return module


class FakeDut:
    hostname = "dut1"
    mgmt_ip = "10.0.0.1"

    def __init__(self, fail=False):
        self.fail = fail
        self.commands = []

    def shell(self, cmd, module_ignore_errors=False):
        if self.fail:
            raise RuntimeError("DUT unreachable")
        self.commands.append(cmd)
        return {"stdout": "", "stderr": ""}


@pytest.mark.parametrize("error", [Exception("helper failed"), pytest.fail.Exception("server did not start")])
def test_dump_marks_error(gu, error):
    dut = FakeDut()
    gu.dump_gnmi_debug_state(dut, error=error)
    assert gu.gnmi_state_dumped(error)
    assert len(dut.commands) == 1
    assert "=== GNMI process ===" in dut.commands[0]
    assert "cat /root/gnmi.log" in dut.commands[0]


def test_dump_tails_gnmi_log_when_asked(gu):
    dut = FakeDut()
    gu.dump_gnmi_debug_state(dut, gnmi_log_lines=500)
    assert "tail -n 500 /root/gnmi.log" in dut.commands[0]


def test_failed_dump_neither_raises_nor_marks(gu):
    error = Exception("helper failed")
    gu.dump_gnmi_debug_state(FakeDut(fail=True), error=error)
    assert not gu.gnmi_state_dumped(error)
    gu.logger.warning.assert_called_once()


def _marked(gu):
    error = Exception("helper failed")
    gu.dump_gnmi_debug_state(FakeDut(), error=error)
    return error


def _raised(func):
    with pytest.raises(BaseException) as excinfo:
        func()
    return excinfo.value


def test_unmarked_error_is_not_dumped(gu):
    assert not gu.gnmi_state_dumped(Exception("test failed"))


def test_cause_of_marked_error_counts(gu):
    def wrap():
        raise RuntimeError("wrapped") from _marked(gu)
    assert gu.gnmi_state_dumped(_raised(wrap))


def test_context_of_marked_error_counts(gu):
    def fail_in_except():
        try:
            raise _marked(gu)
        except Exception as e:
            pytest.fail("Set request failed: " + str(e))
    assert gu.gnmi_state_dumped(_raised(fail_in_except))


def test_context_hidden_by_from_none_does_not_count(gu):
    def replace():
        try:
            raise _marked(gu)
        except Exception:
            raise RuntimeError("unrelated") from None
    assert not gu.gnmi_state_dumped(_raised(replace))


def test_caught_marked_error_does_not_count_for_a_later_failure(gu):
    def expected_error_then_failure():
        try:
            raise _marked(gu)
        except Exception:
            pass
        assert False, "real failure"
    assert not gu.gnmi_state_dumped(_raised(expected_error_then_failure))


def test_cyclic_chain_terminates(gu):
    first, second = Exception("first"), Exception("second")
    first.__cause__, second.__cause__ = second, first
    assert not gu.gnmi_state_dumped(first)


# Loads the real failure hook and gnmi_tls, with each module's dump replaced by one that records who
# dumped which error and marks it, as dump_gnmi_debug_state does.
HOOK_SESSION_CONFTEST = """
import json
import pytest
import tests.common.fixtures.grpc_fixtures as grpc_fixtures
import tests.gnmi.conftest as gnmi_conftest
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.gnmi.conftest import pytest_runtest_makereport  # noqa: F401


def recorder(source):
    def dump(duthost, localhost=None, error=None, gnmi_log_lines=None):
        with open("dumps.jsonl", "a") as f:
            f.write(json.dumps([source, str(error)]) + "\\n")
        if error is not None:
            error._gnmi_state_dumped = True
    return dump


def failing_uds_flow(duthost):
    raise RuntimeError("UDS setup failure")
    yield


gnmi_conftest.dump_gnmi_debug_state = recorder("hook")
grpc_fixtures.dump_gnmi_debug_state = recorder("gnmi_tls")
grpc_fixtures._gnmi_uds_flow = failing_uds_flow


class FakeDut:
    hostname = "dut1"


@pytest.fixture(scope="session")
def duthosts():
    return [FakeDut()]


@pytest.fixture(scope="session")
def ptfhost():
    return None
"""

HOOK_SESSION_TESTS = """
import pytest


def dumped_error(message):
    error = RuntimeError(message)
    error._gnmi_state_dumped = True
    return error


@pytest.fixture
def failing_setup(duthosts):
    raise RuntimeError("setup failure")


@pytest.fixture
def failing_teardown(duthosts):
    yield
    raise RuntimeError("teardown failure")


@pytest.fixture(scope="module")
def failing_module_setup(duthosts):
    raise RuntimeError("module setup failure")


def test_passes(duthosts):
    pass


def test_call_failure(duthosts):
    raise RuntimeError("call failure")


def test_setup_failure(failing_setup):
    pass


def test_call_and_teardown_failure(failing_teardown):
    raise RuntimeError("call failure before teardown")


def test_failure_a_helper_dumped(duthosts):
    raise dumped_error("dumped by a helper")


def test_wrapper_of_a_dumped_failure(duthosts):
    try:
        raise dumped_error("dumped by a helper, then wrapped")
    except RuntimeError as e:
        pytest.fail("wrapper: " + str(e))


def test_module_setup_failure(failing_module_setup):
    pass


def test_module_setup_failure_reraised(failing_module_setup):
    pass


def test_failure_without_duthosts():
    raise RuntimeError("failure without duthosts")


@pytest.mark.parametrize("gnmi_tls", ["uds"], indirect=True)
def test_uds_setup_failure(gnmi_tls):
    pass
"""


def test_each_failure_is_dumped_once(pytester, monkeypatch):
    """Run tests that fail in each phase through the real hook and gnmi_tls, and check what got dumped."""
    pytester.makeconftest(HOOK_SESSION_CONFTEST)
    pytester.makepyfile(HOOK_SESSION_TESTS)
    # A subprocess, so that the inner conftest's patches to the real modules don't leak into this session.
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT))
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, failed=5, errors=5)
    dumps = [json.loads(line) for line in (pytester.path / "dumps.jsonl").read_text().splitlines()]
    assert dumps == [
        ["hook", "call failure"],
        ["hook", "setup failure"],
        ["hook", "call failure before teardown"],
        ["hook", "teardown failure"],
        ["hook", "module setup failure"],
        ["gnmi_tls", "UDS setup failure"],
    ]
