import re
import shlex

import pytest

from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

NATIVE = "gnmi-native"
LISTENER = "gnmi-config-listener"
RESTART_TIMEOUT = 30
OBSERVATION_TIME = 5


def _processes(duthost):
    result = duthost.shell(f"docker exec gnmi supervisorctl status {NATIVE} {LISTENER}", module_ignore_errors=True)
    assert result["rc"] in (0, 3), result["stdout"]
    processes = {}
    for line in result["stdout_lines"]:
        fields = line.split()
        assert len(fields) >= 2, line
        pid = int(fields[3].rstrip(",")) if fields[1] == "RUNNING" else 0
        processes[fields[0]] = (fields[1], pid)
    assert set(processes) == {NATIVE, LISTENER}, result["stdout"]
    return processes


def _container_identity(duthost):
    result = duthost.shell(
        "docker inspect --format "
        "'{% raw %}{{.State.Running}} {{.Id}} {{.RestartCount}} {{.State.StartedAt}}{% endraw %}' gnmi"
    )["stdout"]
    assert result.startswith("true "), "The gnmi container must already be running"
    return result


def _flags(duthost, pid):
    arguments = duthost.shell(f"docker exec gnmi cat /proc/{pid}/cmdline")["stdout"].replace("\0", " ")
    values = {}
    for field, flag in (("port", "port"), ("log_level", "v")):
        match = re.search(rf"(?:^| )--?{flag}(?:=| )(\d+)(?: |$)", arguments)
        assert match, f"Native gNMI has no {flag} argument"
        values[field] = match.group(1)
    return values


def _socket(duthost, port):
    return duthost.shell(f"docker exec gnmi ss -Hlnpt 'sport = :{int(port)}'")["stdout"]


def _effective_config(duthost, expected, previous_pid=None):
    state, pid = _processes(duthost)[NATIVE]
    return (
        state == "RUNNING"
        and pid != previous_pid
        and _flags(duthost, pid) == expected
        and f"pid={pid}," in _socket(duthost, expected["port"])
    )


def _read_config(duthost):
    values = {}
    for field in ("port", "log_level"):
        exists = duthost.shell(f"sonic-db-cli CONFIG_DB HEXISTS 'GNMI|gnmi' {field}")["stdout"] == "1"
        values[field] = duthost.shell(f"sonic-db-cli CONFIG_DB HGET 'GNMI|gnmi' {field}")["stdout"] if exists else None
    return values


def _write_config(duthost, values):
    # Restore absent fields and values together; an intermediate row can be invalid.
    script = (
        "for i=1,#ARGV,3 do "
        "if ARGV[i+1]=='1' then redis.call('HSET',KEYS[1],ARGV[i],ARGV[i+2]) "
        "else redis.call('HDEL',KEYS[1],ARGV[i]) end end return 1"
    )
    command = ["sonic-db-cli", "CONFIG_DB", "EVAL", script, "1", "GNMI|gnmi"]
    for field, value in values.items():
        command.extend((field, "0" if value is None else "1", value or ""))
    duthost.shell(" ".join(shlex.quote(argument) for argument in command))


def _assert_survivors(duthost, baseline):
    assert _processes(duthost)[LISTENER] == baseline["listener"], "The config listener restarted or stopped"
    assert _container_identity(duthost) == baseline["container"], "The gnmi container restarted"


@pytest.fixture
def native_gnmi(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    container = _container_identity(duthost)
    installed = duthost.shell("docker exec gnmi test -f /usr/bin/gnmi-config-listener.py", module_ignore_errors=True)
    assert installed["rc"] in (0, 1) and not installed.get("stderr"), installed
    if installed["rc"] == 1:
        pytest.skip("This image does not include the gNMI config listener")
    assert installed["rc"] == 0, installed
    assert wait_until(
        RESTART_TIMEOUT, 1, 0, lambda: all(state == "RUNNING" for state, _ in _processes(duthost).values())
    ), "Installed native gNMI and config listener must be RUNNING"
    processes = _processes(duthost)
    original = _read_config(duthost)
    effective = _flags(duthost, processes[NATIVE][1])
    assert _effective_config(duthost, effective), "Native gNMI must already own its configured TCP socket"
    assert all(
        value is None or value == effective[field] for field, value in original.items()
    ), "Resolve pre-existing desired/effective port/log drift before this test"
    baseline = {"container": container, "listener": processes[LISTENER], "config": effective}

    try:
        if original != effective:
            _write_config(duthost, effective)
            assert wait_until(
                RESTART_TIMEOUT, 1, 0, _effective_config, duthost, effective, processes[NATIVE][1]
            ), "Failed to establish explicit port/log settings from the effective defaults"
        yield duthost, baseline
    finally:
        _write_config(duthost, original)
        if _processes(duthost)[NATIVE][0] == "STOPPED":
            duthost.shell(f"docker exec gnmi supervisorctl start {NATIVE}")
        if not wait_until(RESTART_TIMEOUT, 1, OBSERVATION_TIME, _effective_config, duthost, effective):
            # A failed listener must not leave the test's configuration serving.
            duthost.shell(f"docker exec gnmi supervisorctl restart {NATIVE}")
            assert wait_until(RESTART_TIMEOUT, 1, 0, _effective_config, duthost, effective), "Native cleanup failed"
        assert _read_config(duthost) == original, "Original field values/presence were not restored"
        _assert_survivors(duthost, baseline)


def test_gnmi_config_unchanged(native_gnmi):
    """Writing unchanged settings must not restart native gNMI or its sibling/container."""
    duthost, baseline = native_gnmi
    native = _processes(duthost)[NATIVE]
    _write_config(duthost, baseline["config"])
    assert not wait_until(
        OBSERVATION_TIME, 1, 0, lambda: _processes(duthost)[NATIVE] != native
    ), "Unchanged settings restarted native gNMI"
    _assert_survivors(duthost, baseline)


@pytest.mark.parametrize("field", ["port", "log_level"])
def test_gnmi_config_change(native_gnmi, field):
    """Each relevant setting must restart only native gNMI and reach its actual flags/socket."""
    duthost, baseline = native_gnmi
    previous_pid = _processes(duthost)[NATIVE][1]
    expected = baseline["config"].copy()
    if field == "port":
        command = "import socket; s=socket.socket(); s.bind(('', 0)); print(s.getsockname()[1])"
        expected[field] = duthost.shell(f"docker exec gnmi python3 -c {shlex.quote(command)}")["stdout"]
        assert expected[field] != baseline["config"][field]
    else:
        expected[field] = "0" if int(expected[field]) else "1"
    _write_config(duthost, {field: expected[field]})
    assert wait_until(
        RESTART_TIMEOUT, 1, 0, _effective_config, duthost, expected, previous_pid
    ), f"Changing {field} did not restart native gNMI with the new flags/socket"
    if field == "port":
        assert not _socket(duthost, baseline["config"]["port"]), "The original port still has a listening socket"
    _assert_survivors(duthost, baseline)


def test_gnmi_config_preserves_stop(native_gnmi):
    """A relevant update must not start an administratively stopped native gNMI."""
    duthost, baseline = native_gnmi
    duthost.shell(f"docker exec gnmi supervisorctl stop {NATIVE}")
    assert _processes(duthost)[NATIVE][0] == "STOPPED"
    log_level = "0" if int(baseline["config"]["log_level"]) else "1"
    _write_config(duthost, {"log_level": log_level})
    assert not wait_until(
        OBSERVATION_TIME, 1, 0, lambda: _processes(duthost)[NATIVE][0] != "STOPPED"
    ), "A configuration change started administratively stopped native gNMI"
    _assert_survivors(duthost, baseline)
