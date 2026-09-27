"""Focused tests for clock command errors and non-UTC output parsing."""

import ast
import datetime as dt
import logging
import random
import time
from collections import UserDict
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest


TEST_CLOCK_PATH = Path(__file__).resolve().parents[1] / "test_clock.py"


class RunAnsibleModuleFail(Exception):
    def __init__(self, message, results=None):
        super().__init__(message)
        self.message = message
        self.results = results

    def __str__(self):
        if self.results is None:
            raise TypeError("results must be iterable")
        return "{}: {}".format(self.message, self.results)


class _Allure:
    @staticmethod
    @contextmanager
    def step(_message):
        yield


def _load_clock_classes():
    tree = ast.parse(TEST_CLOCK_PATH.read_text())
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name in {"ClockConsts", "ClockUtils"}
    ]
    namespace = {
        "allure": _Allure(),
        "dt": dt,
        "logging": logging,
        "Mapping": Mapping,
        "pytest": pytest,
        "random": random,
        "RunAnsibleModuleFail": RunAnsibleModuleFail,
        "time": time,
    }
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(TEST_CLOCK_PATH), "exec"), namespace)
    return namespace["ClockConsts"], namespace["ClockUtils"]


@pytest.mark.parametrize(
    "results, expected",
    [
        ({"stdout": "stdout", "stderr": "stderr", "msg": "message"}, "stdout"),
        ({"stdout": "", "stderr": "stderr", "msg": "message"}, "stderr"),
        ({"msg": "module-level failure"}, "module-level failure"),
        (UserDict({"stderr": "production-shaped stderr"}), "production-shaped stderr"),
        ({}, "Ansible module failed"),
        (None, "Ansible module failed"),
    ]
)
def test_run_cmd_preserves_best_available_ansible_error(results, expected):
    _, clock_utils = _load_clock_classes()
    duthost = Mock()
    duthost.command.side_effect = RunAnsibleModuleFail("Ansible module failed", results)

    assert clock_utils.run_cmd([duthost], "show clock") == expected


def test_run_cmd_raise_err_preserves_module_message():
    _, clock_utils = _load_clock_classes()
    duthost = Mock()
    duthost.command.side_effect = RunAnsibleModuleFail(
        "Ansible module failed",
        {"msg": "missing executable"}
    )

    with pytest.raises(Exception, match="missing executable"):
        clock_utils.run_cmd([duthost], "show clock", raise_err=True)


@pytest.mark.parametrize(
    "output, expected_date, expected_time, expected_timezone",
    [
        ("Thu Feb 20 05:10:25 AM IST 2025", "2025-02-20", "05:10:25", "IST"),
        ("Thu Feb 20 17:10:25 IST 2025", "2025-02-20", "17:10:25", "IST"),
        ("Thu 20 Feb 2025 05:10:25 AM IST", "2025-02-20", "05:10:25", "IST"),
        ("Thu 20 Feb 2025 17:10:25 IST", "2025-02-20", "17:10:25", "IST"),
    ]
)
def test_show_clock_parser_retains_non_utc_formats(
        output, expected_date, expected_time, expected_timezone):
    clock_consts, clock_utils = _load_clock_classes()

    parsed = clock_utils.verify_and_parse_show_clock_output(output)

    assert parsed == {
        clock_consts.DATE: expected_date,
        clock_consts.TIME: expected_time,
        clock_consts.TIMEZONE: expected_timezone,
    }
