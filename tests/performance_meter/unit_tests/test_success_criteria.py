import datetime
import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "success_criteria.py"
START_MARK = "create: request switch create with context 0"
END_MARK = "main: Create a switch, id:"
BASE = datetime.datetime(1900, 9, 15, 12, 0, 0)

pytestmark = [pytest.mark.topology("any")]


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
        self.commands = []

    def shell(self, command):
        self.commands.append(command)
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


def _shell_path(path):
    path = Path(path).resolve()
    if sys.platform == "win32":
        return "/{}/{}".format(path.drive[0].lower(), path.as_posix()[3:])
    return str(path)


def _run_shell_command(command, env=None):
    bash = os.environ.get("SONIC_MGMT_TEST_BASH") or shutil.which("bash")
    assert bash is not None
    return subprocess.run(
        [bash, "-c", command],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    ).stdout


def _shell_position(path):
    output = _run_shell_command(
        "stat -c '%i %s' {}".format(shlex.quote(_shell_path(path)))
    )
    inode, size = output.split()
    return int(inode), int(size)


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
    result = {}
    duthost = FakeDut([SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST])
    request = FakeRequest(duthost)
    checker = SUCCESS_CRITERIA.success_criteria_by_bounded_syslog(
        request,
        result,
        syslog_start_mark=START_MARK,
        syslog_end_mark=END_MARK,
        result_variable="duration",
    )

    assert checker() is False
    command_count = len(duthost.commands)
    assert checker() is False
    assert len(duthost.commands) == command_count
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
    assert '"$current_inode_after" = "$current_inode"' in command
    assert '"$rotated_inode_after" = "$rotated_inode"' in command
    assert SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST in command
    assert command.count("grep -F") == 1


def test_command_reads_markers_appended_after_boundary(tmp_path):
    """The stable-current-file path must return only appended markers."""
    syslog = tmp_path / "syslog"
    syslog.write_text("existing log\n", encoding="utf-8")
    captured_inode, captured_size = _shell_position(syslog)
    with syslog.open("a", encoding="utf-8") as stream:
        stream.write("{}\n{}\n".format(_line(1, START_MARK), _line(31, END_MARK)))
    command = SUCCESS_CRITERIA._appended_lines_command(
        _shell_path(syslog), captured_inode, captured_size, [START_MARK, END_MARK]
    )

    output = _run_shell_command(command)

    assert output.splitlines() == [_line(1, START_MARK), _line(31, END_MARK)]


def test_command_reads_markers_across_one_rotation(tmp_path):
    """One completed rotation must preserve the captured byte boundary."""
    syslog = tmp_path / "syslog"
    rotated = tmp_path / "syslog.1"
    syslog.write_text("existing log\n", encoding="utf-8")
    captured_inode, captured_size = _shell_position(syslog)
    with syslog.open("a", encoding="utf-8") as stream:
        stream.write("{}\n".format(_line(1, START_MARK)))
    syslog.replace(rotated)
    syslog.write_text("{}\n".format(_line(31, END_MARK)), encoding="utf-8")
    command = SUCCESS_CRITERIA._appended_lines_command(
        _shell_path(syslog), captured_inode, captured_size, [START_MARK, END_MARK]
    )

    output = _run_shell_command(command)

    assert output.splitlines() == [_line(1, START_MARK), _line(31, END_MARK)]


def test_lost_boundary_does_not_read_log_contents(tmp_path):
    """The unavailable-boundary branch must emit only the sentinel."""
    syslog = tmp_path / "syslog"
    rotated = tmp_path / "syslog.1"
    read_flag = tmp_path / "read"
    reader_wrapper = tmp_path / "reader"
    syslog.write_text(_line(1, START_MARK), encoding="utf-8")
    rotated.write_text(_line(5, END_MARK), encoding="utf-8")
    reader_wrapper.write_text(
        "#!/bin/sh\n"
        ': > "$READ_FLAG"\n'
        'tool="$1"\n'
        "shift\n"
        'exec "$tool" "$@"\n',
        encoding="utf-8",
    )
    command = SUCCESS_CRITERIA._appended_lines_command(
        _shell_path(syslog), 0, 0, [START_MARK, END_MARK]
    )
    wrapper = "sh {}".format(shlex.quote(_shell_path(reader_wrapper)))
    command = command.replace("tail -c", "{} tail -c".format(wrapper))
    command = command.replace("cat ", "{} cat ".format(wrapper))
    env = os.environ.copy()
    env["READ_FLAG"] = _shell_path(read_flag)

    output = _run_shell_command(command, env=env)

    assert not read_flag.exists()
    assert output.splitlines() == [SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST]


def test_rejects_second_rotation_during_read(tmp_path):
    """A second rotation during the read must discard the staged markers."""
    syslog = tmp_path / "syslog"
    rotated = tmp_path / "syslog.1"
    syslog.write_text("", encoding="utf-8")
    captured_inode, captured_size = _shell_position(syslog)
    syslog.replace(rotated)
    syslog.write_text(
        "{}\n{}\n".format(_line(1, START_MARK), _line(31, END_MARK)),
        encoding="utf-8",
    )

    real_tail = shutil.which("tail")
    assert real_tail is not None
    wrapper_dir = tmp_path / "bin"
    wrapper_dir.mkdir()
    tail_wrapper = wrapper_dir / "tail"
    tail_wrapper.write_text(
        "#!/bin/sh\n"
        'if [ ! -e "$ROTATION_FLAG" ]; then\n'
        '    mv "$SYSLOG_PATH" "$SYSLOG_PATH.1"\n'
        '    printf "%s\\n" "$NEW_CURRENT_LINE" > "$SYSLOG_PATH"\n'
        '    : > "$ROTATION_FLAG"\n'
        "fi\n"
        'exec "$REAL_TAIL" "$@"\n',
        encoding="utf-8",
    )
    tail_wrapper.chmod(0o755)

    command = SUCCESS_CRITERIA._appended_lines_command(
        _shell_path(syslog), captured_inode, captured_size, [START_MARK, END_MARK]
    )
    command = command.replace(
        "tail -c",
        "sh {} -c".format(shlex.quote(_shell_path(tail_wrapper))),
    )
    env = os.environ.copy()
    env.update({
        "REAL_TAIL": _shell_path(real_tail),
        "ROTATION_FLAG": _shell_path(tmp_path / "rotated"),
        "SYSLOG_PATH": _shell_path(syslog),
        "NEW_CURRENT_LINE": _line(60, END_MARK),
    })

    output = _run_shell_command(command, env=env)

    assert (tmp_path / "rotated").exists()
    assert output.splitlines() == [SUCCESS_CRITERIA.SYSLOG_BOUNDARY_LOST]


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
