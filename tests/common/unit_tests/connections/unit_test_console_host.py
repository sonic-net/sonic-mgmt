"""
Unit tests for tests/common/connections/console_host.py.

The reboot console-log collector passes a ``cancel_event`` down to the console
factory so it can abort a slow session-preparation the instant a reboot starts
(see #26351). Only ``SSHConsoleConn`` knows how to consume that kwarg -- it pops
it before delegating to netmiko. Every other console class forwards ``**kwargs``
straight into netmiko, which raises ``TypeError: __init__() got an unexpected
keyword argument 'cancel_event'`` and silently breaks console-log collection on
telnet / conserver console servers (the exception is swallowed by the
try_create_dut_console retry loop).

These tests pin the contract: ``cancel_event`` is injected ONLY when the resolved
console class is (a subclass of) ``SSHConsoleConn`` and is never leaked to the
other console classes.

Follows the repo unit-test convention (unit_test_*.py, run with --noconftest).
"""

import os
import sys
import threading
from unittest import mock

import pytest

# Make the repo root importable so ``tests.common.connections.console_host``
# resolves regardless of the pytest invocation directory. Mirrors the existing
# repo unit-test convention (see tests/common/unit_tests/devices/).
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.connections import console_host as console_host_mod  # noqa: E402
from tests.common.connections.console_host import ConsoleHost  # noqa: E402
from tests.common.connections.base_console_conn import (  # noqa: E402
    CONSOLE_SSH,
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_MENU_PORTS,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG,
    CONSOLE_TELNET,
    CONSOLE_CONSERVER,
)


_COMMON_KWARGS = dict(
    console_host="10.0.0.1",
    console_port="2001",
    sonic_username="admin",
    sonic_password="password",
    console_username="cadmin",
    console_password="cpassword",
)

# console_type -> the class ConsoleHost resolves it to.
SSH_CONSOLE_TYPES = [
    CONSOLE_SSH,
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_MENU_PORTS,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG,
]
NON_SSH_CONSOLE_TYPES = [
    CONSOLE_TELNET,
    CONSOLE_CONSERVER,
]


def _capture_init_kwargs(console_type, cancel_event):
    """Instantiate ConsoleHost with the real class __init__ patched to a no-op
    that records the kwargs it was called with. Returns the captured kwargs."""
    cls = console_host_mod.ConsoleTypeMapper[console_type]
    with mock.patch.object(cls, "__init__", return_value=None) as mocked_init:
        ConsoleHost(
            console_type=console_type,
            cancel_event=cancel_event,
            **_COMMON_KWARGS,
        )
    assert mocked_init.call_count == 1
    return mocked_init.call_args.kwargs


@pytest.mark.parametrize("console_type", SSH_CONSOLE_TYPES)
def test_cancel_event_injected_for_ssh_console(console_type):
    event = threading.Event()
    kwargs = _capture_init_kwargs(console_type, event)
    assert kwargs.get("cancel_event") is event


@pytest.mark.parametrize("console_type", NON_SSH_CONSOLE_TYPES)
def test_cancel_event_not_leaked_to_non_ssh_console(console_type):
    event = threading.Event()
    kwargs = _capture_init_kwargs(console_type, event)
    assert "cancel_event" not in kwargs, (
        "cancel_event must not be forwarded to {}; it would reach netmiko and "
        "raise an unexpected-keyword TypeError".format(console_type)
    )


@pytest.mark.parametrize("console_type", SSH_CONSOLE_TYPES + NON_SSH_CONSOLE_TYPES)
def test_no_cancel_event_never_injected(console_type):
    # When the caller does not supply a cancel_event, no console type should
    # receive the kwarg at all.
    kwargs = _capture_init_kwargs(console_type, None)
    assert "cancel_event" not in kwargs
