"""Exercise the host-failure hooks in real, hardware-independent pytest runs."""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest


TESTS_PATH = Path(__file__).resolve().parents[3]
HOOK_NAMES = {
    "pytest_sessionstart",
    "pytest_sessionfinish",
    "update_custom_msg",
    "log_custom_msg",
    "pytest_runtest_makereport",
    "pytest_runtest_teardown",
}
CONSTANT_NAMES = {"HOST_FIXTURE_FAILED_RC", "CUSTOM_MSG_PREFIX"}


def _hook_source():
    """Load the actual hooks without importing hardware dependencies."""
    source = (TESTS_PATH / "conftest.py").read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    selected = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name in HOOK_NAMES:
            start = min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])
        elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in CONSTANT_NAMES for target in node.targets):
            start = node.lineno
        else:
            continue
        selected.append("".join(lines[start - 1:node.end_lineno]))
    return "\n\n".join(selected)


@pytest.fixture
def run_lifecycle(tmp_path):
    """Run the production hooks with real fixtures, reports, and exit codes."""
    helper_path = TESTS_PATH / "common" / "helpers" / "host_failure_utils.py"
    plugin_source = textwrap.dedent("""
        import importlib.util
        import json
        import logging
        import os
        import shutil
        from datetime import datetime
        from pathlib import Path
        import pytest

        spec = importlib.util.spec_from_file_location("host_failure_utils", {helper_path!r})
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        stop_on_testbed_unreachable = helper.stop_on_testbed_unreachable
        is_testbed_unreachable_exception = helper.is_testbed_unreachable_exception
        CONNECTION_FAILURE_TYPES = ()
        logger = logging.getLogger(__name__)
    """).format(helper_path=str(helper_path))
    plugin_source += "\n" + _hook_source() + "\n"
    plugin_source += textwrap.dedent("""
        FIRST_FAILURE = os.environ["LIFECYCLE_FIRST_FAILURE"]
        CLEANUP_FAILURES = json.loads(os.environ["LIFECYCLE_CLEANUP_FAILURES"])
        CLEANUP_ERROR = os.environ["LIFECYCLE_CLEANUP_ERROR"]

        def record(event):
            with open("events.jsonl", "a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\\n")

        def finish(request, scope):
            record("finalize-" + scope)
            logger.warning("cleanup-%s", scope)
            request.config.cache.set("sonic_custom_msg.cleanup." + scope, "complete")
            if FIRST_FAILURE == scope:
                raise RuntimeError("Host unreachable in the inventory: " + scope)
            if FIRST_FAILURE == "ordinary" and scope == "function":
                raise AssertionError("ordinary test cleanup failure")
            if scope in CLEANUP_FAILURES:
                if CLEANUP_ERROR == "pytest_fail":
                    pytest.fail(scope + " cleanup failed")
                if CLEANUP_ERROR == "keyboard_interrupt":
                    raise KeyboardInterrupt()
                if CLEANUP_ERROR == "pytest_exit":
                    pytest.exit("requested stop", returncode=7)
                raise RuntimeError(scope + " cleanup failed") from None

        @pytest.fixture(scope="session", autouse=True)
        def session_probe(request):
            yield
            finish(request, "session")

        @pytest.fixture(scope="module", autouse=True)
        def module_probe(request, session_probe):
            yield
            finish(request, "module")

        @pytest.fixture(autouse=True)
        def function_probe(request, module_probe):
            request.addfinalizer(lambda: finish(request, "function"))
            if FIRST_FAILURE == "setup":
                raise RuntimeError("Host unreachable in the inventory: setup")

        def pytest_runtest_logreport(report):
            with open("reports.jsonl", "a", encoding="utf-8") as stream:
                stream.write(json.dumps({
                    "nodeid": report.nodeid,
                    "when": report.when,
                    "outcome": report.outcome,
                    "longrepr": str(report.longrepr),
                    "sections": report.sections,
                }) + "\\n")
    """)
    (tmp_path / "conftest.py").write_text(plugin_source, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\njunit_family = xunit1\n", encoding="utf-8")

    def run(first_failure, cleanup_failures=(), next_module=False, last_item=False, cleanup_error="runtime"):
        test_source = textwrap.dedent("""
            from conftest import FIRST_FAILURE, record

            def test_first():
                record("body-first")
                if FIRST_FAILURE == "call":
                    raise RuntimeError("Host unreachable in the inventory: call")
        """)
        next_source = textwrap.dedent("""
            from conftest import record

            def test_next():
                record("body-next")
        """)
        if not last_item:
            if next_module:
                (tmp_path / "test_02_following.py").write_text(next_source, encoding="utf-8")
            else:
                test_source += next_source
        (tmp_path / "test_01_cases.py").write_text(test_source, encoding="utf-8")

        env = os.environ.copy()
        env.pop("PYTEST_ADDOPTS", None)
        env.pop("PYTEST_PLUGINS", None)
        env.update(
            PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            LIFECYCLE_FIRST_FAILURE=first_failure,
            LIFECYCLE_CLEANUP_FAILURES=json.dumps(cleanup_failures),
            LIFECYCLE_CLEANUP_ERROR=cleanup_error,
        )
        process = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--confcutdir", str(tmp_path),
             "-c", str(tmp_path / "pytest.ini"), "--junitxml", str(tmp_path / "results.xml")],
            cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=30,
        )
        events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
        reports = [json.loads(line) for line in (tmp_path / "reports.jsonl").read_text().splitlines()]
        return SimpleNamespace(
            process=process, events=events, reports=reports,
            xml=ET.parse(str(tmp_path / "results.xml")),
        )

    return run


def _assert_stopped_with_complete_cleanup(result, first_failure, cleanup_failures):
    """Check shutdown, error preservation, logging, and final JUnit metadata."""
    assert result.process.returncode == 15, result.process.stdout
    assert "body-next" not in result.events
    assert [event for event in result.events if event.startswith("finalize-")] == [
        "finalize-function", "finalize-module", "finalize-session",
    ]
    assert "INTERNALERROR" not in result.process.stdout
    assert "PluggyTeardownRaisedWarning" not in result.process.stdout

    reports = [report for report in result.reports if report["when"] == "teardown"]
    assert len(reports) == 1
    all_errors = "\n".join(report["longrepr"] for report in result.reports)
    assert "Host unreachable in the inventory: " + first_failure in all_errors
    for scope in cleanup_failures:
        assert scope + " cleanup failed" in reports[0]["longrepr"]
    captured_logs = "\n".join(text for _, text in reports[0]["sections"])
    for scope in ("function", "module", "session"):
        assert "cleanup-" + scope in captured_logs

    properties = result.xml.findall(".//testcase/properties/property[@name='CustomMsg']")
    assert properties
    for prop in properties:
        assert json.loads(prop.attrib["value"]) == {
            "cleanup": {scope: "complete" for scope in ("function", "module", "session")},
        }
    assert all(case.attrib["name"] == "test_first" for case in result.xml.findall(".//testcase"))


@pytest.mark.parametrize("first_failure", ["setup", "call", "function"])
@pytest.mark.parametrize("cleanup_failures", [(), ("module",), ("session",), ("module", "session")])
def test_unreachable_stops_with_all_finalizers_reported(run_lifecycle, first_failure, cleanup_failures):
    """Preserve exit 15 and all cleanup evidence regardless of first-failure phase."""
    result = run_lifecycle(first_failure, cleanup_failures)
    _assert_stopped_with_complete_cleanup(result, first_failure, cleanup_failures)


@pytest.mark.parametrize("cleanup_failures", [(), ("session",)])
def test_module_teardown_unreachable_stops_before_next_module(run_lifecycle, cleanup_failures):
    """Finish session fixtures when module teardown detects the first unreachable error."""
    result = run_lifecycle("module", cleanup_failures, next_module=True)
    _assert_stopped_with_complete_cleanup(result, "module", cleanup_failures)


@pytest.mark.parametrize("cleanup_failures", [(), ("module", "session")])
def test_last_item_teardown_is_not_repeated(run_lifecycle, cleanup_failures):
    """Leave pytest's complete final-item teardown intact without duplicate finalizers."""
    result = run_lifecycle("function", cleanup_failures, last_item=True)
    _assert_stopped_with_complete_cleanup(result, "function", cleanup_failures)


def test_pytest_fail_in_late_cleanup_preserves_original_error(run_lifecycle):
    """Keep pytest outcome exceptions and the original unreachable failure together."""
    result = run_lifecycle("function", ("module", "session"), cleanup_error="pytest_fail")
    _assert_stopped_with_complete_cleanup(result, "function", ("module", "session"))


@pytest.mark.parametrize("cleanup_error, exit_code", [("keyboard_interrupt", 2), ("pytest_exit", 7)])
def test_explicit_interrupt_during_cleanup_is_preserved(run_lifecycle, cleanup_error, exit_code):
    """Do not turn a user's explicit interruption into a grouped test failure."""
    result = run_lifecycle("function", ("module",), cleanup_error=cleanup_error)
    assert result.process.returncode == exit_code, result.process.stdout
    assert "body-next" not in result.events


@pytest.mark.parametrize("first_failure, exit_code", [("none", 0), ("ordinary", 1)])
def test_healthy_or_unrelated_failure_does_not_stop_session(run_lifecycle, first_failure, exit_code):
    """Retain shared fixtures and run the next case unless the testbed is unreachable."""
    result = run_lifecycle(first_failure)
    assert result.process.returncode == exit_code, result.process.stdout
    assert result.events == [
        "body-first", "finalize-function", "body-next",
        "finalize-function", "finalize-module", "finalize-session",
    ]
