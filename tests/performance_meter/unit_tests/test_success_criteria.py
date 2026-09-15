import datetime
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "success_criteria.py"
START_MARK = "create: request switch create with context 0"
END_MARK = "main: Create a switch, id:"
BASE = datetime.datetime(1900, 9, 15, 12, 0, 0)


def _load_success_criteria():
    pandas_stub = types.ModuleType("pandas")
    pandas_stub.Series = list
    assertions_stub = types.ModuleType("tests.common.helpers.assertions")
    assertions_stub.pytest_assert = lambda condition, message="": None
    stubs = {
        "pandas": pandas_stub,
        "tests": types.ModuleType("tests"),
        "tests.common": types.ModuleType("tests.common"),
        "tests.common.helpers": types.ModuleType("tests.common.helpers"),
        "tests.common.helpers.assertions": assertions_stub,
    }

    spec = importlib.util.spec_from_file_location(
        "performance_meter_success_criteria", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


SUCCESS_CRITERIA = _load_success_criteria()


class FakeDut:
    hostname = "dut-1"

    def __init__(self, outputs):
        self.outputs = iter(outputs)

    def shell(self, command):
        if command.startswith("stat -c"):
            return {"stdout": "123 100"}
        return {"stdout": next(self.outputs)}


class FakeRequest:
    def __init__(self, duthost):
        self.duthost = duthost

    def getfixturevalue(self, name):
        assert name == "duthost"
        return self.duthost


def _line(seconds, mark, microseconds=True):
    timestamp = BASE + datetime.timedelta(seconds=seconds)
    fmt = "%b %d %H:%M:%S.%f" if microseconds else "%b %d %H:%M:%S"
    return "{} dut-1 swss#orchagent: {}".format(timestamp.strftime(fmt), mark)


def _checker(outputs):
    result = {}
    request = FakeRequest(FakeDut(outputs))
    checker = SUCCESS_CRITERIA.success_criteria_by_bounded_syslog(
        request,
        result,
        syslog_start_mark=START_MARK,
        syslog_end_mark=END_MARK,
        result_variable="duration",
    )
    return checker, result


def test_waits_for_latest_start_visible_on_first_poll():
    partial = "\n".join([
        _line(1, START_MARK),
        _line(5, END_MARK),
        _line(10, START_MARK),
    ])
    complete = partial + "\n" + _line(40, END_MARK)
    checker, result = _checker([partial, complete])

    assert checker() is False
    assert checker() is True
    assert result["duration"] == 30


def test_retains_start_across_polls():
    checker, result = _checker([
        _line(1, START_MARK),
        _line(40, END_MARK),
    ])

    assert checker() is False
    assert checker() is True
    assert result["duration"] == 39


def test_rejects_measurement_if_boundary_is_lost():
    checker, result = _checker([
        _line(1, START_MARK),
        SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST + "\n" + _line(5, END_MARK),
    ])

    assert checker() is False
    assert checker() is False
    assert result["duration_error"] == "syslog boundary lost during measurement"


def test_accepts_new_start_with_same_second_as_capture():
    output = "\n".join([
        _line(0, START_MARK, microseconds=False),
        _line(10, END_MARK, microseconds=False),
    ])
    checker, result = _checker([output])

    assert checker() is True
    assert result["duration"] == 10


def test_skips_unparseable_marker_lines():
    output = "\n".join([
        "corrupt {}".format(START_MARK),
        _line(1, START_MARK),
        _line(5, END_MARK),
    ])
    checker, result = _checker([output])

    assert checker() is True
    assert result["duration"] == 4


def test_command_uses_byte_boundary_and_detects_lost_boundary():
    command = SUCCESS_CRITERIA._appended_lines_command(
        "/var/log/syslog", 123, 100, [START_MARK, END_MARK]
    )

    assert "tail -c +101 /var/log/syslog" in command
    assert 'rotated_inode="$(stat -c %i /var/log/syslog.1' in command
    assert '"$rotated_inode" = "123"' in command
    assert '"$current_size" -ge "100"' in command
    assert SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST in command
    assert command.count("grep -F") == 1


def test_legacy_reader_keeps_integer_duration():
    result = {}
    duthost = FakeDut([
        _line(0, "unrelated"),
        _line(1, START_MARK),
        _line(5, END_MARK),
    ])
    request = FakeRequest(duthost)
    checker = SUCCESS_CRITERIA.success_criteria_by_syslog(
        request,
        result,
        syslog_start_cmd="start",
        syslog_end_cmd="end",
        result_variable="duration",
    )

    assert checker() is True
    assert result["duration"] == 4
    assert isinstance(result["duration"], int)
