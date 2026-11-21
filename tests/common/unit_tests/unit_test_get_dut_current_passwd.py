"""Unit tests for get_dut_current_passwd in tests/common/utilities.py.

Covers the duplicate-SSH-attempt bug (sonic-net/sonic-mgmt#27919): under
IPv6-only management, ipv4_address and ipv6_address can be the identical
literal, and the fallback must not retry the same address twice.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_get_dut_current_passwd.py -v

get_dut_current_passwd() is normally imported directly from
tests.common.utilities with tests.common.utilities._paramiko_ssh patched.
tests/common/__init__.py pulls in paramiko transitively, so if paramiko is
not installed in the local environment, the function is instead extracted
via ast and exec'd against a mocked _paramiko_ssh/AuthenticationException,
following the convention in unit_test_dhcp_relay_cleanup.py, so these tests
do not require installing the full integration dependency tree.
"""

import ast
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "utilities.py"

try:
    import tests.common.utilities as _utilities_module
    from paramiko.ssh_exception import AuthenticationException
except ImportError:
    _utilities_module = None

    class AuthenticationException(Exception):
        """Stand-in for paramiko.ssh_exception.AuthenticationException when paramiko is unavailable."""


@pytest.fixture
def get_dut_current_passwd_env():
    """Yield (get_dut_current_passwd, mock _paramiko_ssh, AuthenticationException).

    Uses the real tests.common.utilities module with _paramiko_ssh patched when
    paramiko is importable; otherwise extracts get_dut_current_passwd via ast
    and execs it against a mocked _paramiko_ssh/AuthenticationException.
    """
    if _utilities_module is not None:
        mock_ssh = Mock()
        with patch("tests.common.utilities._paramiko_ssh", mock_ssh):
            yield _utilities_module.get_dut_current_passwd, mock_ssh, AuthenticationException
        return

    tree = ast.parse(MODULE_PATH.read_text())
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_dut_current_passwd"
    )
    mock_ssh = Mock()
    namespace = {
        "_paramiko_ssh": mock_ssh,
        "AuthenticationException": AuthenticationException,
    }
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    yield namespace["get_dut_current_passwd"], mock_ssh, AuthenticationException


def test_ipv4_fails_distinct_ipv6_succeeds(get_dut_current_passwd_env):
    func, mock_ssh, _ = get_dut_current_passwd_env
    mock_ssh.side_effect = [TimeoutError("v4 unreachable"), (Mock(), "pw2")]

    result = func("10.0.0.1", "fe80::1", "admin", ["pw1"])

    assert result == "pw2"
    assert mock_ssh.call_count == 2
    assert mock_ssh.call_args_list[0].args[0] == "10.0.0.1"
    assert mock_ssh.call_args_list[1].args[0] == "fe80::1"


def test_identical_addresses_timeout_propagates_without_retry(get_dut_current_passwd_env):
    func, mock_ssh, _ = get_dut_current_passwd_env
    mock_ssh.side_effect = TimeoutError("no route to host")

    with pytest.raises(TimeoutError, match="no route to host"):
        func("fe80::1", "fe80::1", "admin", ["pw1"])

    assert mock_ssh.call_count == 1


def test_first_address_succeeds(get_dut_current_passwd_env):
    func, mock_ssh, _ = get_dut_current_passwd_env
    mock_ssh.return_value = (Mock(), "pw1")

    result = func("10.0.0.1", "fe80::1", "admin", ["pw1"])

    assert result == "pw1"
    assert mock_ssh.call_count == 1


def test_both_distinct_addresses_fail(get_dut_current_passwd_env):
    func, mock_ssh, _ = get_dut_current_passwd_env
    mock_ssh.side_effect = [TimeoutError("v4 unreachable"), TimeoutError("v6 unreachable")]

    with pytest.raises(TimeoutError, match="v6 unreachable"):
        func("10.0.0.1", "fe80::1", "admin", ["pw1"])

    assert mock_ssh.call_count == 2


def test_authentication_exception_from_first_address_propagates(get_dut_current_passwd_env):
    func, mock_ssh, auth_exception = get_dut_current_passwd_env
    mock_ssh.side_effect = auth_exception("bad password")

    with pytest.raises(auth_exception):
        func("10.0.0.1", "fe80::1", "admin", ["pw1"])

    assert mock_ssh.call_count == 1
