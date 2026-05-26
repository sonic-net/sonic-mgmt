"""
Per-test health check logic for transceiver tests.

Used by the autouse function-scoped fixture in conftest.py to capture baselines
before each test and verify system health after each test.
"""
import logging

import pytest

from tests.common.helpers.dut_utils import get_program_info

logger = logging.getLogger(__name__)

# Critical processes monitored before/after every test.
# Key = process name, value = container name.
DEFAULT_MONITORED_PROCESSES = {
    "xcvrd": "pmon",
}

# Shell snippet used by both capture_baseline and verify_health to list files
# in /var/core/.
_FIND_CORE_FILES_CMD = "find /var/core/ -maxdepth 1 -type f -printf '%f\n'"


def _list_core_files(duthost):
    """Return the current set of files in /var/core/ on the DUT.

    Logs a warning and returns an empty set if the shell command fails so the
    health check can still complete; the caller decides whether the failure to
    enumerate cores is itself worth flagging.
    """
    result = duthost.shell(_FIND_CORE_FILES_CMD, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        logger.warning(
            "Failed to list /var/core/ (rc=%s): %s",
            result.get("rc"), result.get("stderr", "").strip(),
        )
        return set()
    stdout = result.get("stdout", "")
    return set(stdout.splitlines()) if stdout.strip() else set()


def capture_baseline(duthost, monitored_processes=None):
    """Capture pre-test health baseline.

    Args:
        duthost: DUT host handle.
        monitored_processes: dict of ``{process_name: container_name}``.
            Defaults to ``DEFAULT_MONITORED_PROCESSES``.

    Returns:
        dict: ``{"pid_baselines": {process: (status, pid)}, "core_files": set[str]}``
    """
    if monitored_processes is None:
        monitored_processes = DEFAULT_MONITORED_PROCESSES

    pid_baselines = {}
    for process, container in monitored_processes.items():
        status, pid = get_program_info(duthost, container, process)
        pid_baselines[process] = (status, pid)
        logger.debug("Baseline PID - %s (%s): status=%s pid=%s", process, container, status, pid)

    core_files = _list_core_files(duthost)
    logger.debug("Baseline core files: %d", len(core_files))

    return {"pid_baselines": pid_baselines, "core_files": core_files}


def verify_health(duthost, baseline, monitored_processes=None, expect_pid_change=None):
    """Verify post-test health against a captured baseline.

    Args:
        duthost: DUT host handle.
        baseline: baseline dict returned by ``capture_baseline``.
        monitored_processes: dict of ``{process_name: container_name}``.
        expect_pid_change: set of process names where a PID change is expected
            (e.g., after an intentional service restart).

    Returns:
        dict: ``{'passed': bool, 'failures': [str]}``
    """
    if monitored_processes is None:
        monitored_processes = DEFAULT_MONITORED_PROCESSES
    if expect_pid_change is None:
        expect_pid_change = set()

    failures = []

    # 1. Verify PIDs unchanged (unless intentionally changed)
    for process, container in monitored_processes.items():
        status, pid = get_program_info(duthost, container, process)
        if status != "RUNNING":
            failures.append(f"Process {process} ({container}) is {status}, expected RUNNING")
            continue
        baseline_pid = baseline["pid_baselines"].get(process, (None, None))[1]
        if process not in expect_pid_change and baseline_pid is not None and pid != baseline_pid:
            failures.append(
                f"Process {process} PID changed: {baseline_pid} -> {pid} (unexpected restart)"
            )

    # 2. Check for new core files
    new_cores = _list_core_files(duthost) - baseline["core_files"]
    if new_cores:
        failures.append(f"New core files detected: {', '.join(sorted(new_cores))}")

    passed = len(failures) == 0
    if passed:
        logger.info("Post-test health check passed")
    return {"passed": passed, "failures": failures}


# A "check" passed to run_pre_check / run_post_check is a 3-tuple:
#   (name: str, passed: bool, detail: str)

# Valid failure actions per phase. The first entry in each tuple is the default.
PRE_TEST_ACTIONS = ("skip", "warn")
POST_TEST_ACTIONS = ("exit", "warn")

PRE_TEST_MARKER = "xcvr_pre_test_failure_action"
POST_TEST_MARKER = "xcvr_post_test_failure_action"
PRE_TEST_OPTION = "--xcvr_pre_test_failure_action"
POST_TEST_OPTION = "--xcvr_post_test_failure_action"

# Per-phase configuration consumed by _evaluate_phase.
_PHASE_CONFIG = {
    "pre-test": (PRE_TEST_MARKER, PRE_TEST_OPTION, PRE_TEST_ACTIONS, "Pre-test"),
    "post-test": (POST_TEST_MARKER, POST_TEST_OPTION, POST_TEST_ACTIONS, "Post-test"),
}


def _resolve_action(request, marker_name, option_name, valid_actions):
    """Resolve the failure action for the current test.

    Per-test marker (if present and valid) takes precedence over the CLI option,
    which is always present and validated by argparse ``choices=`` at parse time.
    """
    marker = request.node.get_closest_marker(marker_name)
    if marker is not None and marker.args:
        action = str(marker.args[0]).lower()
        if action in valid_actions:
            return action
        logger.warning(
            "Ignoring invalid %s marker value %r; valid: %s",
            marker_name, marker.args[0], valid_actions,
        )
    return request.config.getoption(option_name)


def _evaluate_phase(request, checks, events, phase):
    """Shared dispatcher for pre-test and post-test health-check phases.

    Aggregates failed *checks*, resolves the action via marker > CLI option,
    appends a record to *events*, and invokes the matching pytest control flow.

    Args:
        request: pytest ``request`` fixture from the calling fixture.
        checks: iterable of ``(name, passed, detail)`` tuples.
        events: list to append failure events to (for terminal summary).
        phase: ``"pre-test"`` or ``"post-test"``.
    """
    failures = [f"{name}: {detail}" for name, passed, detail in checks if not passed]
    if not failures:
        return
    detail = "; ".join(failures)
    marker, option, valid, label = _PHASE_CONFIG[phase]
    action = _resolve_action(request, marker, option, valid)
    events.append({
        "test": request.node.nodeid,
        "phase": phase,
        "action": action,
        "details": detail,
    })
    msg = f"{label} health check failed for {request.node.name} -- {detail}"
    if action == "skip":
        pytest.skip(msg)
    elif action == "exit":
        pytest.exit(
            f"Aborting: environment unhealthy after {request.node.name} -- {detail}",
            returncode=1,
        )
    else:  # warn
        logger.warning("%s (action=warn, continuing)", msg)


def run_pre_check(request, checks, events):
    """Evaluate pre-test checks; act on failures per resolved action.

    Action resolution order: per-test marker ``xcvr_pre_test_failure_action`` >
    CLI option ``--xcvr_pre_test_failure_action`` > default ``skip``.

    Actions:
        skip - call ``pytest.skip`` (default).
        warn - log a warning and let the test proceed.
    """
    _evaluate_phase(request, checks, events, "pre-test")


def run_post_check(request, checks, events):
    """Evaluate post-test checks; act on failures per resolved action.

    Action resolution order: per-test marker ``xcvr_post_test_failure_action`` >
    CLI option ``--xcvr_post_test_failure_action`` > default ``exit``.

    Actions:
        exit - call ``pytest.exit`` to abort the session (default).
        warn - log a warning and let the run continue.
    """
    _evaluate_phase(request, checks, events, "post-test")
