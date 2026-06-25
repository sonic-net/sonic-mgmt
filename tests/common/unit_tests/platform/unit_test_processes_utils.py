"""Unit tests for tests/common/platform/processes_utils.py.

Run (from the repository root):
    python3 -m pytest --noconftest tests/common/unit_tests/platform/unit_test_processes_utils.py -v
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/platform/processes_utils.py")

MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * HOUR
WEEK = 7 * DAY
MONTH = 30 * DAY


def _load_target_module():
    """Load processes_utils.py in isolation, stubbing its intra-repo imports."""
    for name, attrs in {
        "tests.common.helpers.assertions": {"pytest_assert": lambda *a, **k: None},
        "tests.common.utilities": {"wait_until": None,
                                   "get_plt_reboot_ctrl": lambda *a, **k: None},
    }.items():
        module = types.ModuleType(name)
        for attr, value in attrs.items():
            setattr(module, attr, value)
        sys.modules[name] = module

    spec = importlib.util.spec_from_file_location(
        "unit_target_processes_utils", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def processes_utils():
    return _load_target_module()


@pytest.mark.parametrize("uptime_seconds, expected", [
    (str(2 * MONTH), True),         # "Up 2 months"  -- the original failing case
    (str(3 * WEEK), True),          # "Up 3 weeks"
    (str(4 * DAY), True),           # "Up 4 days"
    (str(HOUR), True),              # "Up About an hour"
    (str(7 * MINUTE), True),        # "Up 7 minutes"
    (str(6 * MINUTE), True),        # exactly at the threshold
    (str(6 * MINUTE - 1), False),   # one second below the threshold
    (str(MINUTE), False),           # "Up About a minute"
    ("30", False),                  # "Up 30 seconds"
    ("0", False),                   # just started
    ("-5", False),                  # clock skew / negative elapsed
    ("", False),                    # pmon absent or not running
])
def test_check_pmon_uptime_minutes(processes_utils, uptime_seconds, expected):
    duthost = MagicMock()
    duthost.command.return_value = {"stdout": uptime_seconds}
    assert processes_utils.check_pmon_uptime_minutes(duthost) is expected
    # Verify it reads structured docker state, not the rendered "docker ps" text.
    invoked_cmd = duthost.command.call_args[0][0]
    assert "docker inspect" in invoked_cmd
    assert "State.StartedAt" in invoked_cmd


def test_pmon_uptime_cmd_survives_ansible_jinja2_templating(processes_utils):
    """Go-template braces in _PMON_UPTIME_SECONDS_CMD must survive Ansible Jinja2 templating."""
    jinja2 = pytest.importorskip("jinja2")
    cmd = processes_utils._PMON_UPTIME_SECONDS_CMD

    try:
        rendered = jinja2.Environment().from_string(cmd).render()
        assert "{{.State.Running}}" in rendered
        assert "{{.State.StartedAt}}" in rendered
    except jinja2.exceptions.TemplateError as exc:
        pytest.fail("_PMON_UPTIME_SECONDS_CMD is not Jinja2-safe: {}".format(exc))
