"""Strict Redis result handling, quoting and selected-host/ASIC routing.

Run with pytest --noconftest in docker-sonic-mgmt.
"""
import shlex
from unittest.mock import Mock

import pytest

from tests.common.helpers.sonic_db import (
    APPL_DB, CONFIG_DB, SonicAsic, redis_exists, redis_sismember, redis_srem,
)


OPERATIONS = [redis_exists, redis_sismember, redis_srem]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("db", [APPL_DB, CONFIG_DB])
@pytest.mark.parametrize("output", ["0", "1\n"])
def test_counts_and_shell_quoting(operation, db, output):
    host = Mock()
    host.shell.return_value = {"rc": 0, "stdout": output}
    key = "key with 'quotes' | $(false)"
    member = "-member; false"
    result = operation(host, db, key, member)
    if operation is redis_sismember:
        assert result is (output.strip() == "1")
    else:
        assert type(result) is int and result == int(output)
    command = host.shell.call_args.args[0]
    assert shlex.split(command) == ["sonic-db-cli", db, "--", operation.__name__[6:].upper(), key, member]
    assert host.shell.call_args.kwargs == {"module_ignore_errors": True}


def test_exists_counts_all_keys():
    host = Mock()
    host.shell.return_value = {"rc": 0, "stdout": "2"}
    assert redis_exists(host, APPL_DB, "normal:Vnet1", "_staged:Vnet1") == 2


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("result", [
    {"rc": 1, "stdout": "0", "stderr": "connection failed"},
    {"rc": 1, "stdout": ""},
    {"stdout": "0"},
])
def test_failed_commands_never_return_absence(operation, result):
    host = Mock()
    host.shell.return_value = result
    with pytest.raises(RuntimeError, match="failed"):
        operation(host, APPL_DB, "key", "member")


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("output", ["", None, "WRONGTYPE", "-1", "3", "1.0", "0\n1", "²"])
def test_invalid_output_never_returns_absence(operation, output):
    host = Mock()
    host.shell.return_value = {"rc": 0, "stdout": output}
    with pytest.raises(ValueError, match="Unexpected"):
        operation(host, APPL_DB, "key", "member")


@pytest.mark.parametrize("operation", [redis_sismember, redis_srem])
def test_single_member_result_cannot_exceed_one(operation):
    host = Mock()
    host.shell.return_value = {"rc": 0, "stdout": "2"}
    with pytest.raises(ValueError, match="Unexpected"):
        operation(host, APPL_DB, "key", "member")


@pytest.mark.parametrize("operation", OPERATIONS)
def test_host_exceptions_propagate(operation):
    host = Mock()
    host.shell.side_effect = RuntimeError("host unavailable")
    with pytest.raises(RuntimeError, match="host unavailable"):
        operation(host, APPL_DB, "key", "member")


@pytest.mark.parametrize("operation", OPERATIONS)
def test_selected_asic_namespace_is_preserved(operation):
    host = Mock(spec=SonicAsic)
    host.sonic_db_cli = "sonic-db-cli -n asic1"
    host.shell.return_value = {"rc": 0, "stdout": "0"}
    operation(host, APPL_DB, "key", "member")
    assert host.shell.call_args.args[0].startswith("sonic-db-cli -n asic1 APPL_DB -- ")
