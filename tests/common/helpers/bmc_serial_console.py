"""Shared UART mux helpers for SONiC BMC serial-console auto-switch tests.

Cases set or observe console on BMC or CPU through a vendor-overridable hook.
Boot-side classification uses UART fingerprints, not mux-register names.
"""

import logging
import time

import pexpect
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.console_helper import disconnect_console_client
from tests.common.utilities import wait_until
from tests.common.helpers.platform_api import chassis, module as module_api
from tests.common.platform.bmc_utils import (
    get_host_boot_id,
    recover_switch_host_after_power_off,
    wait_host_on,
    wait_host_rebooted,
)

logger = logging.getLogger(__name__)

CONSOLE_BMC = "bmc"
CONSOLE_CPU = "cpu"

BMC_BOOT_PATTERNS = ["U-Boot", "Hit any key to stop autoboot"]
HOST_BOOT_PATTERNS = ["GNU GRUB", r"Copyright \(C\) \d{4} AMI"]
PANIC_PATTERNS = ["Kernel panic", "SysRq", "sysrq"]

BMC_BOOT_TIMEOUT = 180
HOST_BOOT_TIMEOUT = 180
PANIC_TIMEOUT = 120
BMC_REBOOT_SSH_TIMEOUT = 300
UART_DRAIN_MAX_WAIT = 60
# After a wanted boot fingerprint, keep reading this long and fail on the other side.
UART_MIXED_WATCH = 30


class ConsoleMux:
    """Vendor hook: set or observe which side owns the shared console UART."""

    @classmethod
    def matches(cls, duthost):
        return False

    def available(self):
        return True

    def wait_ready(self, timeout=120):
        pytest_assert(wait_until(timeout, 5, 0, self.available), "Console mux did not become ready")

    def set_console(self, side):
        raise NotImplementedError

    def get_console(self):
        raise NotImplementedError

    def assert_console(self, side):
        actual = self.get_console()
        pytest_assert(actual == side, "Console is on {}, expected {}".format(actual, side))


class NvidiaConsoleMux(ConsoleMux):
    """NVIDIA hw-management mux: uart_sel 0 = BMC, 2 = host CPU."""

    PATH = "/var/run/hw-management/system/uart_sel"
    _VALUES = {CONSOLE_BMC: "0", CONSOLE_CPU: "2"}
    _SIDES = {"0": CONSOLE_BMC, "2": CONSOLE_CPU}

    def __init__(self, duthost):
        self.duthost = duthost

    @classmethod
    def matches(cls, duthost):
        platform = duthost.facts.get("platform", "") or ""
        asic_type = duthost.facts.get("asic_type", "") or ""
        return ("mlnx" in platform) or ("nvidia" in platform) or (asic_type == "mellanox")

    def available(self):
        result = self.duthost.shell("test -e {} && echo yes || echo no".format(self.PATH),
                                    module_ignore_errors=True)
        return result.get("stdout", "").strip() == "yes"

    def set_console(self, side):
        pytest_assert(side in self._VALUES, "Unknown console side {}".format(side))
        value = self._VALUES[side]
        self.duthost.shell("sudo sh -c 'echo {} > {}'".format(value, self.PATH))
        logger.info("Set console mux to %s (%s)", side, value)

    def get_console(self):
        result = self.duthost.shell("cat {}".format(self.PATH), module_ignore_errors=True)
        pytest_assert(result.get("rc") == 0, "Failed to read console mux: {}".format(result.get("stderr")))
        raw = result.get("stdout", "").strip()
        pytest_assert(raw in self._SIDES,
                      "Console mux value {} is not BMC or CPU".format(raw))
        return self._SIDES[raw]


CONSOLE_MUX_CLASSES = (
    NvidiaConsoleMux,
)


def get_console_mux(duthost):
    """Return the vendor console-mux hook, or skip if this platform has none."""
    platform = duthost.facts.get("platform", "") or ""
    for mux_cls in CONSOLE_MUX_CLASSES:
        if not mux_cls.matches(duthost):
            continue
        mux = mux_cls(duthost)
        if not mux.available():
            pytest.skip("Console mux {} is not present on {}".format(
                getattr(mux, "PATH", mux_cls.__name__), platform))
        return mux
    pytest.skip("No vendor console-mux override for platform {}".format(platform))


class SharedUart:
    """pexpect session on the lab console-server line to the BMC front-panel UART."""

    def __init__(self, client, line, release="ctrl-z"):
        self.client = client
        self.line = line
        self.release = release

    def drain(self, timeout=1, max_wait=UART_DRAIN_MAX_WAIT):
        # expect(TIMEOUT) does not consume pexpect.buffer. Drop the Python
        # buffer, then pull from the pty until a quiet window.
        leftover = self.client.buffer
        self.client.buffer = leftover[:0] if leftover is not None else b""
        deadline = time.time() + max_wait
        try:
            while time.time() < deadline:
                remaining = min(timeout, deadline - time.time())
                if remaining <= 0:
                    break
                try:
                    leftover = self.client.read_nonblocking(
                        self.client.maxread, timeout=remaining)
                except pexpect.TIMEOUT:
                    return
        except (pexpect.EOF, OSError) as exc:
            pytest.fail("UART session dropped while draining: {}".format(exc))
        snippet = leftover if leftover is not None else b""
        if not isinstance(snippet, str):
            snippet = snippet.decode("utf-8", "replace")
        pytest.fail(
            "UART did not go quiet within {}s (last {!r})".format(max_wait, snippet[-200:]))

    def sendline(self, line=""):
        self.client.sendline(line)

    def _expect_patterns(self, wanted, forbidden, timeout, what, mixed_watch=UART_MIXED_WATCH):
        """Wait for a wanted fingerprint. Fail if a forbidden one appears before or after it."""
        patterns = list(wanted) + list(forbidden) + [pexpect.TIMEOUT, pexpect.EOF]
        n_wanted = len(wanted)
        deadline = time.time() + timeout
        matched = None
        try:
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                index = self.client.expect(patterns, timeout=remaining)
                if index < n_wanted:
                    matched = wanted[index]
                    logger.info("UART captured %s via %r", what, matched)
                    if mixed_watch <= 0:
                        return matched
                    deadline = min(deadline, time.time() + mixed_watch)
                    continue
                if index < n_wanted + len(forbidden):
                    other = forbidden[index - n_wanted]
                    pytest.fail("UART showed {} while waiting for {} (matched {!r})".format(
                        other, what, other))
                if patterns[index] is pexpect.EOF:
                    pytest.fail("UART EOF while waiting for {}".format(what))
                if matched is not None:
                    return matched
                pytest.fail("UART did not show {} within {}s".format(what, timeout))
        except (pexpect.EOF, OSError) as exc:
            pytest.fail("UART session dropped while waiting for {}: {}".format(what, exc))
        if matched is not None:
            return matched
        pytest.fail("UART did not show {} within {}s".format(what, timeout))

    def expect_bmc_boot_log(self, timeout=BMC_BOOT_TIMEOUT):
        return self._expect_patterns(BMC_BOOT_PATTERNS, HOST_BOOT_PATTERNS, timeout, "BMC boot")

    def expect_host_boot_log(self, timeout=HOST_BOOT_TIMEOUT):
        return self._expect_patterns(HOST_BOOT_PATTERNS, ["U-Boot"], timeout, "host boot")

    def expect_panic(self, timeout=PANIC_TIMEOUT):
        # Host U-Boot follows panic on CPU and uses the same strings as BMC boot.
        return self._expect_patterns(
            PANIC_PATTERNS, BMC_BOOT_PATTERNS, timeout, "kernel panic", mixed_watch=0)

    def expect_no_boot_log(self, timeout=2):
        patterns = BMC_BOOT_PATTERNS + HOST_BOOT_PATTERNS + [pexpect.TIMEOUT, pexpect.EOF]
        try:
            index = self.client.expect(patterns, timeout=timeout)
        except (pexpect.EOF, OSError) as exc:
            pytest.fail("UART session dropped while expecting no boot output: {}".format(exc))
        n_boot = len(BMC_BOOT_PATTERNS) + len(HOST_BOOT_PATTERNS)
        if index < n_boot:
            pytest.fail("UART showed boot output while expecting none")
        if patterns[index] is pexpect.EOF:
            pytest.fail("UART EOF while expecting no boot output")

    def close(self):
        if self.client is None:
            return
        try:
            if self.release == "ctrl-z":
                self.client.sendcontrol("z")
            else:
                disconnect_console_client(self.client)
        except Exception:
            pass
        try:
            self.client.terminate()
        except Exception:
            pass


def open_bmc_shared_uart(duthost, conn_graph_facts, _creds):
    """Open the physical lab-con → BMC UART. Skip if the DUT has no console link."""
    hostname = duthost.hostname
    console_info = conn_graph_facts.get("device_console_info", {}).get(hostname, {})
    console_link = conn_graph_facts.get("device_console_link", {}).get(hostname, {})
    if "ManagementIp" not in console_info:
        pytest.skip("No console link for BMC DUT {} in conn-graph".format(hostname))

    console_host = console_info["ManagementIp"]
    if "/" in console_host:
        console_host = console_host.split("/")[0]
    console_port_info = console_link.get("ConsolePort") or {}
    console_type = console_port_info.get("type")
    pytest_assert(console_type == "ssh",
                  "Unsupported console type {} for {}".format(console_type, hostname))
    console_port = console_port_info.get("peerport")
    pytest_assert(console_port, "No console peerport for {}".format(hostname))

    console_user = console_port_info.get("proxy")
    pytest_assert(console_user, "No console proxy user for {}".format(hostname))
    ssh_login = "{}:{}".format(console_user, console_port)
    client = None
    connect_error = None
    release = "ctrl-z"
    try:
        client = pexpect.spawn(
            "ssh -l {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}".format(
                ssh_login, console_host),
            echo=False,
        )
        index = client.expect_exact([
            "Type the hot key to suspend the connection",
            "Successful connection to line [{}]".format(console_port),
        ], timeout=30)
        if index == 1:
            client.expect_exact("Press ^A ^X to disconnect")
            release = "sonic"
        else:
            release = "ctrl-z"
    except Exception as exc:
        connect_error = "{}: {}".format(type(exc).__name__, exc)
        if client is not None:
            try:
                client.close(force=True)
            except Exception:
                pass
        client = None

    pytest_assert(client is not None,
                  "Cannot connect to console device for {}: {}".format(hostname, connect_error))
    client.sendline()
    return SharedUart(client, console_port, release)


def cmd_exists(host, command):
    result = host.shell("command -v {}".format(command), module_ignore_errors=True)
    return result.get("rc") == 0


def ensure_host_on(duthost, host):
    rows = duthost.show_and_parse("show chassis module status")
    online = False
    for row in rows or []:
        if (row.get("name") or "").strip().startswith("SWITCH-HOST"):
            online = (row.get("oper-status") or "").strip().lower() == "online"
            break
    if not online:
        recover_switch_host_after_power_off(duthost, host, context="ensure host on")
    pytest_assert(wait_host_on(host), "SWITCH-HOST is not fully started")


def find_switch_host_index(platform_api_conn):
    num_modules = chassis.get_num_modules(platform_api_conn) or 0
    for index in range(num_modules):
        name = module_api.get_name(platform_api_conn, index)
        if name and str(name).startswith("SWITCH-HOST"):
            return index
    pytest.skip("SWITCH-HOST module not found")


def reset_host(platform_api_conn, host):
    boot_id_before = get_host_boot_id(host)
    pytest_assert(boot_id_before, "Could not read SWITCH-HOST boot_id before reset")
    index = find_switch_host_index(platform_api_conn)
    result = module_api.do_power_cycle(platform_api_conn, index)
    pytest_assert(result is True, "do_power_cycle() returned {}".format(result))
    pytest_assert(wait_host_rebooted(host, boot_id_before),
                  "SWITCH-HOST did not reboot after reset")
