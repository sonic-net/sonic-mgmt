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
import threading
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

from tests.common.connections.ssh_console_conn import (  # noqa: E402
    BOOTLOADER_BANNER_RE,
    SSHConsoleConn,
    ConsoleRebootStartedError,
)


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
    # "Press Control-C" without the Aboot autoboot phrasing ("now") must NOT match
    # (external review Finding 2: a tool or log line saying "Press Control-C to abort"
    # would otherwise defer login for the whole session and break send_command paths
    # like collect_mgmt_config_by_console()).
    "Press Control-C to abort the operation",
    "admin@sonic:~$ tool: Please Press Control-C to stop",
    # A shell/log line that merely mentions the word "autoboot" (without the real
    # countdown phrasing "autoboot in N" / "stop autoboot") must NOT match -- the bare
    # \bautoboot\b token was tightened for this (external review Finding 1); otherwise a
    # U-Boot env dump would defer login and break send_command paths.
    "admin@sonic:~$ fw_printenv | grep autoboot",
    "admin@sonic:~$ echo 'set autoboot flag' >> notes.txt",
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
    conn._read_initial_console = mock.MagicMock(return_value="")
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
    assert conn._bootloader_deferred is True


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
    conn._read_initial_console = mock.MagicMock(return_value="")
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


def test_cleanup_deferred_session_makes_no_writes():
    """Deferred-session teardown (reboot.py collect_mgmt_config_by_console ->
    disconnect() -> cleanup()) must NOT probe the prompt: _is_at_sonic_prompt()
    would send RETURNs into a one-shot bootloader autoboot window (the banner has
    already been consumed, so it no longer matches). cleanup() must close the
    transport without any write_channel()/send_command() call."""
    conn = _make_console([])
    conn._bootloader_deferred = True
    conn.send_command = mock.MagicMock()
    conn._is_at_sonic_prompt = mock.MagicMock()
    rc = conn.remote_conn = mock.MagicMock()

    SSHConsoleConn.cleanup(conn)

    conn._is_at_sonic_prompt.assert_not_called()
    conn.send_command.assert_not_called()
    assert _written(conn) == [], (
        f"a deferred-session cleanup must write nothing, got {_written(conn)!r}")
    rc.close.assert_called_once()


def test_cleanup_at_sonic_prompt_still_sends_exit():
    """Sanity: a non-deferred session still probes and logs out at a SONiC prompt,
    so the deferred short-circuit does not disable normal cleanup."""
    conn = _make_console([])
    conn._bootloader_deferred = False
    conn.send_command = mock.MagicMock()
    conn._is_at_sonic_prompt = mock.MagicMock(return_value=True)
    rc = conn.remote_conn = mock.MagicMock()

    SSHConsoleConn.cleanup(conn)

    conn.send_command.assert_called_once()
    rc.close.assert_called_once()


@pytest.mark.parametrize("banner", [
    "Press Control-C now to enter Aboot shell\n",
    "Hit any key to stop autoboot:  3\n",
    "GNU GRUB  version 2.06\n",
    "ONIE: Starting ONIE Service Discovery\n",
])
def test_session_preparation_initial_probe_writes_no_key_in_bootloader(banner):
    """Regression guard for the FIRST console read in session_preparation.

    Netmiko's inherited _test_channel_read() writes RETURN on an empty read; on a
    quiet bootloader "hit any key to stop autoboot" window that CR aborts autoboot
    and traps the DUT. This exercises the REAL initial probe (_read_initial_console)
    AND the real _recover_to_login_prompt classification -- nothing that writes is
    stubbed away -- and asserts session_preparation sends NO DUT-side key while a
    bootloader banner is present, and defers login.
    """
    # The autoboot window prints its banner continuously, so every read returns it.
    conn = _make_console([banner] * 60)
    conn.console_type = "ssh"            # not a "*config" menu type
    conn.menu_port = None
    conn.username = "console_user:7001"
    conn.sonic_username = "admin"
    conn.sonic_password = ["pw"]
    conn.login_stage_2 = mock.MagicMock()
    conn.session_preparation_finalise = mock.MagicMock()
    conn.set_base_prompt = mock.MagicMock()
    conn.find_prompt = mock.MagicMock()

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn.session_preparation(conn)

    assert conn._bootloader_deferred is True, "must defer login in a bootloader state"
    assert _written(conn) == [], (
        f"session_preparation's initial probe must write nothing while a bootloader "
        f"banner is present, but wrote {_written(conn)!r} -- any keypress (including "
        f"a bare CR) can abort a 'hit any key to stop autoboot' window")
    conn.login_stage_2.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()
    conn.set_base_prompt.assert_not_called()
    conn.find_prompt.assert_not_called()


def test_session_preparation_menu_port_defers_when_banner_lags_first_read():
    """Regression guard for residual A: on a menu_port console the autoboot
    banner may not be in the buffer on the FIRST read after port selection (a
    single read can land in a countdown gap). login_stage_2 must observe the DUT
    serial passively over a few reads before risking a wake-up CR, so a lagging
    bootloader banner still defers login and NO DUT-side key is sent. With the
    old single-read code the first empty read would have triggered a CR."""
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
    conn._read_initial_console = mock.MagicMock(return_value="")
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.read_until_pattern = mock.MagicMock(return_value="Selection:")
    # First two reads after port selection are empty (countdown gap); the banner
    # only appears on the third read -- the single-read path would CR before it.
    conn.read_channel = mock.MagicMock(side_effect=(
        ["", "", "Hit any key to stop autoboot:  3\n"] + [""] * 40))
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
    assert getattr(conn, "_bootloader_deferred", False) is True, "must defer login"
    conn._recover_to_login_prompt.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()


def test_try_session_preparation_writes_no_priming_cr():
    """Fix C: netmiko's BaseConnection._open() calls _try_session_preparation()
    with force_data=True, which writes a bare CR to the channel BEFORE
    session_preparation() runs. On a DUT sitting in a bootloader autoboot window
    at connect time that CR aborts autoboot and traps the box -- earlier than any
    of our own guards. SSHConsoleConn overrides _try_session_preparation to force
    force_data=False, so NO byte is written before session_preparation() runs."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = RETURN
    conn.logger = mock.MagicMock()
    conn.write_channel = mock.MagicMock()
    conn.disconnect = mock.MagicMock()
    conn.session_preparation = mock.MagicMock()

    SSHConsoleConn._try_session_preparation(conn)

    conn.write_channel.assert_not_called()
    conn.session_preparation.assert_called_once()


def test_session_preparation_direct_path_defers_on_bootloader():
    """Fix B: on a direct (non-menu) console the sonic-password login loop now
    calls login_stage_2(defer_on_bootloader=True). If login_stage_2 detects a
    bootloader banner mid-wait (a live autoboot that the earlier
    _recover_to_login_prompt classification missed) it sets _bootloader_deferred;
    session_preparation must then return WITHOUT calling
    session_preparation_finalise() (whose set_base_prompt writes CRs that would
    abort autoboot)."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = RETURN
    conn.logger = mock.MagicMock()
    conn.console_type = "ssh"          # not a "*config" menu type
    conn.menu_port = None              # direct path, no menu port
    conn.username = "console_user:2001"
    conn.sonic_username = "admin"
    conn.sonic_password = ["pw1"]
    conn._read_initial_console = mock.MagicMock(return_value="")
    conn._recover_to_login_prompt = mock.MagicMock(return_value=False)
    conn.session_preparation_finalise = mock.MagicMock()
    conn.write_channel = mock.MagicMock()

    def _defer(**kwargs):
        assert kwargs.get("defer_on_bootloader") is True, \
            "direct-path login must pass defer_on_bootloader=True"
        conn._bootloader_deferred = True
        return ""
    conn.login_stage_2 = mock.MagicMock(side_effect=_defer)

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn.session_preparation(conn)

    conn.login_stage_2.assert_called_once()
    conn.session_preparation_finalise.assert_not_called()
    assert getattr(conn, "_bootloader_deferred", False) is True


def test_read_initial_console_bounded_on_silent_console():
    """Fix D (regression guard for Fix C): suppressing netmiko's priming CR means
    a genuinely SILENT console returns no data here. The passive read must be
    BOUNDED to a few reads so session_preparation() stays well inside reboot.py
    collect_console_log()'s ~10s budget -- otherwise the console-log collection
    during reboot would time out and silently produce no log. With the default
    (0.5s per empty read) a bound of <=6 keeps the worst case around 3s; the old
    unbounded value (20) burned the entire 10s budget on a silent console."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.logger = mock.MagicMock()
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.write_channel = mock.MagicMock()
    conn.read_channel = mock.MagicMock(return_value="")

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep") as slept:
        out = SSHConsoleConn._read_initial_console(conn)

    assert out == ""
    conn.write_channel.assert_not_called()          # still never writes a byte
    assert conn.read_channel.call_count <= 6, \
        "silent-console read must be bounded (<=6) to fit collect_console_log's 10s budget"
    assert slept.call_count <= 6


def test_session_preparation_defers_when_bootloader_only_in_initial_read():
    """Regression guard for the initial-read classification gap (external review
    Finding 1). A one-shot bootloader banner can appear ONLY in the first console
    read (session_init_msg) and then the line goes silent. Without classifying that
    first read, _recover_to_login_prompt() re-reads a now-silent line, takes its
    ``not output.strip()`` branch and nudges with a bare CR -- which aborts autoboot
    on U-Boot/ONIE. session_preparation() must classify the initial read and defer
    with ZERO writes. Distinct from
    test_session_preparation_initial_probe_writes_no_key_in_bootloader, which feeds
    the banner on EVERY read (so _recover_to_login_prompt still sees it)."""
    # Banner is returned exactly once (the first read), then read_channel() -> "" forever.
    conn = _make_console(["Hit any key to stop autoboot:  3\n"])
    conn.console_type = "ssh"
    conn.menu_port = None
    conn.username = "console_user:7001"
    conn.sonic_username = "admin"
    conn.sonic_password = ["pw"]
    conn.login_stage_2 = mock.MagicMock()
    conn.session_preparation_finalise = mock.MagicMock()
    conn.set_base_prompt = mock.MagicMock()
    conn.find_prompt = mock.MagicMock()

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn.session_preparation(conn)

    assert conn._bootloader_deferred is True, \
        "must defer login when the bootloader banner is only in the first read"
    assert _written(conn) == [], (
        f"must write nothing when the initial read shows a bootloader banner, but "
        f"wrote {_written(conn)!r} -- even a bare CR can abort a 'hit any key' window")
    conn.login_stage_2.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()


# ---------------------------------------------------------------------------
# Cancel-event tests: once the reboot has started, the console worker must stop
# writing to the DUT serial line. reboot.py runs collect_console_log() via
# pool.apply_async().get(timeout=10); that timeout does NOT cancel the underlying
# ThreadPool task, so a worker still preparing its session could send a late CR
# into the bootloader autoboot window and trap the DUT -- the exact race this
# guards. reboot.py sets a threading.Event right before rebooting; SSHConsoleConn
# refuses every write_channel() once it is set.
# ---------------------------------------------------------------------------


def _make_gate_console(cancel_event):
    """A bare SSHConsoleConn wired only for write_channel() gate testing."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = RETURN
    conn.logger = mock.MagicMock()
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.clear_buffer = mock.MagicMock()
    conn._cancel_event = cancel_event
    return conn


def test_write_channel_delegates_when_not_cancelled():
    """With no cancel event / an unset one, write_channel() passes bytes through."""
    for cancel_event in (None, threading.Event()):
        conn = _make_gate_console(cancel_event)
        with mock.patch("netmiko.base_connection.BaseConnection.write_channel") as sup:
            SSHConsoleConn.write_channel(conn, conn.RETURN)
        sup.assert_called_once_with(conn.RETURN)


def test_write_channel_aborts_once_reboot_started():
    """Once the cancel event is set, write_channel() raises and sends NO byte."""
    cancel_event = threading.Event()
    cancel_event.set()
    conn = _make_gate_console(cancel_event)
    with mock.patch("netmiko.base_connection.BaseConnection.write_channel") as sup:
        with pytest.raises(ConsoleRebootStartedError):
            SSHConsoleConn.write_channel(conn, conn.RETURN)
        sup.assert_not_called()


def test_worker_stops_nudging_silent_console_when_reboot_starts():
    """End-to-end: a silent-console recovery begins BEFORE the reboot sends its first
    bare-CR nudge, but the reboot then starts -- the worker must not send any further
    CR. Simulates reboot.py setting the event immediately after the first CR reaches
    the DUT serial line; a second nudge would risk aborting a 'hit any key' autoboot
    window on U-Boot/ONIE."""
    cancel_event = threading.Event()
    conn = _make_gate_console(cancel_event)
    conn.read_channel = mock.MagicMock(return_value="")  # fully silent console

    writes = []

    def record_and_start_reboot(out):
        # The real bytes that reach the DUT serial line. The reboot begins right
        # after the first CR lands, so subsequent write_channel() calls must abort.
        writes.append(out)
        cancel_event.set()

    with mock.patch("netmiko.base_connection.BaseConnection.write_channel",
                    side_effect=record_and_start_reboot):
        with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
            result = SSHConsoleConn._recover_to_login_prompt(conn, max_attempts=4, delay_factor=1)

    # _recover_to_login_prompt swallows the abort (its I/O is wrapped in
    # try/except -> return False); the guarantee we assert is that exactly ONE CR
    # ever reached the DUT and it was a bare RETURN (never Ctrl-C).
    assert result is False
    assert writes == [RETURN], (
        f"exactly one bare-CR nudge may reach the DUT before the reboot starts, "
        f"got {writes!r} -- a second write would risk aborting bootloader autoboot")
    assert CTRL_C not in writes
