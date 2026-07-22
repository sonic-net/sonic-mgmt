"""
Unit tests for tests/common/connections/ssh_console_conn.py.

These tests guard the console-state classifier that decides whether the reboot
console-log collector may send a Ctrl-C during recovery. Sending Ctrl-C while the
DUT is in a bootloader/boot stage (e.g. Arista Aboot autoboot window) traps the
box in the bootloader and aborts autoboot, so SONiC never boots and the device
becomes permanently unreachable (the regression PR #26351 fixes).

The critical property is ``BOOTLOADER_BANNER_RE``:
  * it MUST match real bootloader / boot-in-progress banners (so Ctrl-C is
    suppressed while booting), and
  * it MUST NOT match ordinary SONiC shell output that merely *contains* a boot
    substring (e.g. "reloading", "downloading") -- a false positive there causes
    ``_recover_to_login_prompt`` to skip the Ctrl-C + exit recovery on a genuine
    leftover shell prompt, re-introducing the username-as-shell-command desync.

Follows the repo unit-test convention (unit_test_*.py, run with --noconftest).
"""

import os
import sys

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

from tests.common.connections.ssh_console_conn import BOOTLOADER_BANNER_RE  # noqa: E402


# Real bootloader / boot-in-progress banners -- Ctrl-C MUST be suppressed here.
POSITIVE_CASES = [
    "Press Control-C now to enter Aboot shell",
    "Press Control C now to enter Aboot shell",
    "Aboot#",
    "Aboot# ",
    "Booting flash:sonic and installing image",
    "Loading Linux 6.1.0 ...",
    "Loading initial ramdisk ...",
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
