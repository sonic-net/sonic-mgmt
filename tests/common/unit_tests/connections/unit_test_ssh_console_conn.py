"""
Unit tests for tests/common/connections/ssh_console_conn.py.

These tests guard the console-state classifier that decides whether the reboot
console-log collector may send a Ctrl-C during recovery. Sending Ctrl-C while the
DUT is in a bootloader/boot stage (e.g. Arista Aboot autoboot window) traps the
box in the bootloader and aborts autoboot, so SONiC never boots and the device
becomes permanently unreachable. The regression was introduced by #24288; this
PR (#26351) fixes it.

The critical property is ``BOOTLOADER_BANNER_RE``:
  * it MUST match real bootloader / boot-in-progress banners (so Ctrl-C is
    suppressed while booting), and
  * it MUST NOT match ordinary SONiC shell output that merely *contains* a boot
    substring (e.g. "reloading", "downloading") -- a false positive there causes
    ``_recover_to_login_prompt`` to skip the Ctrl-C + exit recovery on a genuine
    leftover shell prompt, re-introducing the username-as-shell-command desync.

Follows the repo unit-test convention (unit_test_*.py, run with --noconftest).
"""

import collections
import os
import sys
from unittest import mock

import pytest

# Make the repo root importable so ``tests.common.connections.ssh_console_conn``
# resolves regardless of the pytest invocation directory. Mirrors the existing
# repo unit-test convention (see tests/common/unit_tests/devices/). Runs in the
# full-dependency unit-test lane.
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.connections.ssh_console_conn import BOOTLOADER_BANNER_RE, SSHConsoleConn  # noqa: E402


# Real bootloader / boot-in-progress banners -- Ctrl-C MUST be suppressed here.
POSITIVE_CASES = [
    "Press Control-C now to enter Aboot shell",
    "Press Control C now to enter Aboot shell",
    "Aboot#",
    "Aboot# ",
    "Booting flash:sonic and installing image",
    "Loading Linux 6.1.0 ...",
    "Loading initial ramdisk ...",
    "Loading vmlinuz-6.1.0-22-2-amd64",
    "GNU GRUB  version 2.06",
    "grub> ",
    "grub rescue> ",
    "Hit any key to stop autoboot:  3",
    "autoboot in 5 seconds",
    "ONIE: Starting ONIE Service Discovery",
]

# Ordinary SONiC shell / command output -- these merely CONTAIN a boot substring
# but are NOT a bootloader state, so Ctrl-C recovery must NOT be skipped.
NEGATIVE_CASES = [
    "admin@sonic-dut:~$ ",
    "root@sonic:~# ",
    "show reloading table",
    "Reloading service",
    "admin@sonic:~$ downloading package index",
    "root@sonic:~# apt-get: Downloading firmware",
    "sonic login: ",
    "admin@sonic:~$ sudo config reload -y",
    # Image filenames contain "aboot" with hyphen word boundaries -- must NOT match
    # (this is the false-positive class Copilot flagged; a bare \bAboot\b would hit).
    "  Current: sonic-aboot-broadcom.swi",
    "Next: sonic-aboot-broadcom-legacy-th.swi",
    "admin@sonic:~$ sudo sonic-installer list",
    "admin@sonic:~$ sudo sonic-installer install sonic-aboot-broadcom.swi",
    "admin@sonic:~$ ls /host/image-aboot-20240101/",
    # "show platform summary" prints an "ONIE Version" field -- must NOT match
    # (a bare \bONIE\b would hit; the token is anchored to "ONIE:").
    "ONIE Version         : 2020.11",
    "admin@sonic:~$ show platform summary",
    # Generic progress text that is not a kernel/ramdisk load must NOT match.
    "Loading configuration",
    "admin@sonic:~$ app: Loading modules ...",
]


@pytest.mark.parametrize("text", POSITIVE_CASES)
def test_bootloader_banner_matches_real_boot_states(text):
    assert BOOTLOADER_BANNER_RE.search(text) is not None, (
        f"expected a bootloader/boot banner match for {text!r}"
    )


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_bootloader_banner_ignores_ordinary_shell_output(text):
    assert BOOTLOADER_BANNER_RE.search(text) is None, (
        f"unexpected bootloader match for {text!r} -- a false positive here makes "
        f"_recover_to_login_prompt skip the Ctrl-C + exit recovery on a leftover shell"
    )


# ---------------------------------------------------------------------------
# Behavioral tests: prove no key is written to the channel once a bootloader
# banner is seen, and that the silent-console path only ever nudges with a bare
# CR (never Ctrl-C). These mock the serial channel so they assert on the actual
# bytes written, not just the classifier regex.
# ---------------------------------------------------------------------------

CTRL_C = "\x03"
RETURN = "\r"


def _make_console(read_chunks):
    """Build an SSHConsoleConn with a mocked serial channel.

    ``__new__`` bypasses the network-connecting __init__; we attach just the
    attributes/methods ``_recover_to_login_prompt`` / ``session_preparation``
    touch. ``read_channel`` yields ``read_chunks`` in order, then "" forever.
    """
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = RETURN
    conn.logger = mock.MagicMock()
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.clear_buffer = mock.MagicMock()
    conn.write_channel = mock.MagicMock()
    queue = collections.deque(read_chunks)
    conn.read_channel = mock.MagicMock(side_effect=lambda: queue.popleft() if queue else "")
    return conn


def _written(conn):
    """All positional payloads passed to write_channel."""
    return [c.args[0] for c in conn.write_channel.call_args_list if c.args]


@pytest.mark.parametrize("banner", [
    "Press Control-C now to enter Aboot shell\n",
    "Hit any key to stop autoboot:  3\n",
    "GNU GRUB  version 2.06\n",
    "ONIE: Starting ONIE Service Discovery\n",
])
def test_recover_writes_no_key_when_bootloader_detected(banner):
    """No byte (CR or Ctrl-C) may be written once a bootloader banner is seen."""
    conn = _make_console([banner])
    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        result = SSHConsoleConn._recover_to_login_prompt(conn, max_attempts=4, delay_factor=1)
    assert result is True, "bootloader/boot stage must be reported to the caller"
    assert _written(conn) == [], (
        f"no key must be written after a bootloader banner, but got {_written(conn)!r} "
        f"-- any keypress (including CR) can abort a 'hit any key' autoboot window"
    )


def test_recover_silent_console_nudges_with_cr_only():
    """A silent console is nudged with a bare CR, never Ctrl-C."""
    conn = _make_console([])  # channel stays silent forever
    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        result = SSHConsoleConn._recover_to_login_prompt(conn, max_attempts=2, delay_factor=1)
    written = _written(conn)
    assert result is False
    assert CTRL_C not in written, "Ctrl-C must never be sent to a silent/booting console"
    assert written and all(k == RETURN for k in written), (
        f"silent console must only be nudged with a bare CR, got {written!r}"
    )


def test_recover_sends_ctrl_c_only_on_leftover_shell():
    """A positively identified leftover shell still gets Ctrl-C + exit recovery."""
    conn = _make_console(["admin@sonic-dut:~$ \n", "", "", "", "sonic login: \n"])
    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn._recover_to_login_prompt(conn, max_attempts=2, delay_factor=1)
    written = _written(conn)
    assert CTRL_C in written, "leftover shell recovery must still send Ctrl-C"
    assert any(w.startswith("exit") for w in written), "recovery must send 'exit'"


def test_session_preparation_defers_login_in_bootloader():
    """session_preparation must skip login_stage_2 AND avoid any console write when a
    bootloader is detected.

    session_preparation_finalise() -> set_base_prompt() -> find_prompt() writes RETURN(s)
    to the console, which would abort a "hit any key to stop autoboot" window, so the
    bootloader path must not call it.
    """
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.logger = mock.MagicMock()
    conn.console_type = "ssh"  # not a "*config" menu type
    conn.menu_port = None
    conn._test_channel_read = mock.MagicMock(return_value="")
    conn._recover_to_login_prompt = mock.MagicMock(return_value=True)
    conn.login_stage_2 = mock.MagicMock()
    conn.session_preparation_finalise = mock.MagicMock()
    conn.set_base_prompt = mock.MagicMock()
    conn.find_prompt = mock.MagicMock()
    conn.write_channel = mock.MagicMock()

    SSHConsoleConn.session_preparation(conn)

    conn.login_stage_2.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()
    conn.set_base_prompt.assert_not_called()
    conn.find_prompt.assert_not_called()
    conn.write_channel.assert_not_called()


# ---------------------------------------------------------------------------
# Behavioral tests for the two remaining "send keys before knowing the console
# state" paths (both pre-existing/legacy, hardened here so the whole file is
# bootloader-safe): (1) the menu_port login path, which calls login_stage_2()
# before recovery, and (2) _is_at_sonic_prompt(), which cleanup() calls during
# reboot teardown. Each must observe the console passively and send NO DUT-side
# key once a bootloader banner is seen.
# ---------------------------------------------------------------------------


def test_session_preparation_menu_port_defers_login_in_bootloader():
    """A menu_port console must select the console-server port but then send NO
    DUT-side key (no CR / username / login / finalise) once a bootloader banner
    is observed on the DUT serial line."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = RETURN
    conn.host = "dut"
    conn.logger = mock.MagicMock()
    conn.console_type = "ssh"            # not a "*config" menu type
    conn.menu_port = 7
    conn.username = "console_user"
    conn.password = "console_pw"
    conn.sonic_username = "admin"
    conn.sonic_password = ["pw"]
    conn._test_channel_read = mock.MagicMock(return_value="")
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    # write_and_poll() (real, inherited) selects the console-server port; its
    # read_until_pattern() is stubbed. After port selection the DUT serial shows
    # an autoboot banner, then stays silent.
    conn.read_until_pattern = mock.MagicMock(return_value="Selection:")
    conn.read_channel = mock.MagicMock(side_effect=(
        ["Press Control-C now to enter Aboot shell\n"] + [""] * 40))
    conn.write_channel = mock.MagicMock()
    conn._recover_to_login_prompt = mock.MagicMock()
    conn.session_preparation_finalise = mock.MagicMock()

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn.session_preparation(conn)

    # Only the console-server menu selection may be written -- never a DUT-side CR.
    assert _written(conn) == ["menu ports" + RETURN, "7" + RETURN], (
        f"only the console-server port selection may be written, got {_written(conn)!r}")
    assert RETURN not in _written(conn), "no bare DUT-side wake-up CR may be sent"
    assert CTRL_C not in _written(conn), "no Ctrl-C may be sent"
    # The bootloader-safe recovery and the CR-writing finalise must be skipped.
    conn._recover_to_login_prompt.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()


@pytest.mark.parametrize("banner", [
    "Press Control-C now to enter Aboot shell\n",
    "Hit any key to stop autoboot:  3\n",
    "GNU GRUB  version 2.06\n",
    "ONIE: Starting ONIE Service Discovery\n",
])
def test_is_at_sonic_prompt_writes_no_key_in_bootloader(banner):
    """cleanup()'s prompt probe must send no key while the DUT is in a bootloader/
    boot stage -- during a reboot that CR would abort autoboot."""
    conn = _make_console([banner])
    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        result = SSHConsoleConn._is_at_sonic_prompt(conn)
    assert result is False, "a bootloader/boot stage is not a SONiC prompt"
    assert _written(conn) == [], (
        f"no key may be written when a bootloader banner is present, got {_written(conn)!r}")


def test_is_at_sonic_prompt_detects_shell_when_not_bootloader():
    """When not in a bootloader, the probe still nudges with a CR (never Ctrl-C)
    and correctly detects the SONiC shell prompt."""
    conn = _make_console(["", "", "", "", "admin@sonic:~$ \n"])
    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        result = SSHConsoleConn._is_at_sonic_prompt(conn)
    assert result is True
    written = _written(conn)
    assert CTRL_C not in written, "Ctrl-C must never be sent to probe the prompt"
    assert written and all(k == RETURN for k in written), (
        f"non-bootloader probe must only nudge with a bare CR, got {written!r}")
