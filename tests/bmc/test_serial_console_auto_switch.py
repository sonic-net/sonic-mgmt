"""BMC shared-UART auto-switch tests.

Cases set or observe console on BMC or CPU. They do not name a vendor mux API.
"""

import random
from enum import Enum

import pytest
from ansible.errors import AnsibleConnectionFailure
from pytest_ansible.errors import AnsibleConnectionFailure as PytestAnsibleConnectionFailure

from tests.common.helpers.bmc_serial_console import (
    CONSOLE_BMC,
    CONSOLE_CPU,
    BMC_REBOOT_SSH_TIMEOUT,
    ensure_host_on,
    reset_host,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.bmc_utils import (
    bmc_control_ready,
    get_host_boot_id,
    bmc_power_off_host,
    recover_switch_host_after_power_off,
    wait_host_on,
    wait_host_rebooted,
)

from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import pdu_reboot, wait_until

pytestmark = [
    pytest.mark.topology("bmc"),
    pytest.mark.disable_loganalyzer,
]


class Restart(Enum):
    REBOOT = "reboot"
    WARM_REBOOT = "warm-reboot"
    FAST_REBOOT = "fast-reboot"
    WATCHDOG = "watchdog"
    PANIC = "panic"


# Same budget wait_host_rebooted() uses, spent racing the restart command
# against the boot ID instead of waiting for the command alone.
_HOST_REBOOT_TIMEOUT = 420

_WATCHDOG_ARM_SEC = 5

_RESTART_COMMAND = {
    Restart.REBOOT: "sudo reboot",
    Restart.WARM_REBOOT: "sudo warm-reboot",
    Restart.FAST_REBOOT: "sudo fast-reboot",
    Restart.WATCHDOG: "sudo watchdogutil arm -s {}".format(_WATCHDOG_ARM_SEC),
    Restart.PANIC: "sudo sh -c 'echo c > /proc/sysrq-trigger'",
}

# Exit codes the fast-reboot script uses for "this platform cannot do it".
# Every other nonzero code is a real failure and must not be read as a skip.
_EXIT_NOT_SUPPORTED = 2
_MLNX_EXIT_FFB_FAILURE = 101
_UNSUPPORTED_RCS = (_EXIT_NOT_SUPPORTED, _MLNX_EXIT_FFB_FAILURE)

# Only these two may be skipped on an unsupported rc. warm-reboot is a symlink
# to fast-reboot, so they share the codes above. The rest do not: 'reboot' is a
# different script where rc 2 means a shutdown timeout, and 'panic' is a sysrq
# write with no rc contract at all. Without this guard a reboot timeout would
# be silently skipped as "unsupported".
_OPTIONAL_RESTARTS = (Restart.WARM_REBOOT, Restart.FAST_REBOOT)

# CPU/BMC-side host restarts that share set → assert → restart → assert.
# uart_expect None: prove reboot with boot_id. Otherwise watch UART then wait_host_on.
# warm-reboot and watchdog are not here: each needs its own support check.
_SWITCH_HOST_RESTART_SCENARIOS = {
    "reboot": (Restart.REBOOT, CONSOLE_CPU, "host_boot"),
    "panic": (Restart.PANIC, CONSOLE_CPU, "panic"),
    "reboot-bmc": (Restart.REBOOT, CONSOLE_BMC, None),
    "fast-reboot": (Restart.FAST_REBOOT, CONSOLE_CPU, None),
}


@pytest.fixture(scope="module", autouse=True)
def restore_switch_host(duthost, switch_host, console_mux, request):
    original = console_mux.get_console()
    failed_before = request.session.testsfailed
    yield
    # Green run: host is up. recover() would wait_host_off for 180 s.
    # A failed case may have shutdown in flight while chassis still says
    # Online; recover waits for off, then powers on.
    try:
        if request.session.testsfailed > failed_before:
            recover_switch_host_after_power_off(
                duthost, switch_host, context="serial-console auto-switch teardown")
        else:
            ensure_host_on(duthost, switch_host)
    finally:
        # Restore the mux even if recovery failed: that is the run whose console
        # someone is about to attach to.
        console_mux.set_console(original)


@pytest.fixture(autouse=True)
def _ensure_switch_host_on(duthost, switch_host):
    with allure.step("Ensure SWITCH-HOST is on"):
        ensure_host_on(duthost, switch_host)


@pytest.fixture(autouse=True)
def _drain_uart_after_case(bmc_shared_uart):
    yield
    bmc_shared_uart.drain()


def _enable_panic_reboot(host, after=10):
    """Enable sysrq panic and reboot `after` seconds later."""
    host.shell("sudo sh -c 'echo 1 > /proc/sys/kernel/sysrq'")
    host.shell(
        "sudo sh -c 'echo {} > /proc/sys/kernel/panic'".format(after),
        module_ignore_errors=True)


def _require_watchdog_support(host):
    """Skip unless the platform exposes a watchdog.

    `watchdogutil`'s group callback loads the platform watchdog class and exits 2
    when the chassis has none. `status` triggers that load without arming
    anything, so it is a side-effect-free probe. Any other nonzero code is a
    broken utility, not an unsupported platform.
    """
    res = host.shell("sudo watchdogutil status", module_ignore_errors=True)
    rc = res.get("rc")
    if rc == _EXIT_NOT_SUPPORTED:
        pytest.skip("Platform has no watchdog: {}".format(
            (res.get("stderr") or res.get("stdout") or "").strip()))
    pytest_assert(rc == 0, "'watchdogutil status' failed (rc={}): {}".format(
        rc, (res.get("stderr") or res.get("stdout") or "").strip()))


def _arm_watchdog(host, seconds=_WATCHDOG_ARM_SEC):
    """Arm the hardware watchdog, failing on the exit-0 refusal.

    `watchdogutil arm` echoes "Failed to arm Watchdog for N seconds" and exits 0
    when the vendor arm() returns negative, so the exit code proves nothing. A
    refusal here is a defect or a bad timeout value, never an unsupported
    platform -- _require_watchdog_support() already cleared that.
    """
    res = host.shell(_RESTART_COMMAND[Restart.WATCHDOG], module_ignore_errors=True)
    output = "{}\n{}".format(res.get("stdout") or "", res.get("stderr") or "").strip()
    pytest_assert(res.get("rc") == 0,
                  "'watchdogutil arm' failed (rc={}): {}".format(res.get("rc"), output))
    pytest_assert("Failed to arm Watchdog" not in output,
                  "Watchdog refused to arm for {}s, so no reset will follow: {}".format(
                      seconds, output))


def _boot_id_changed(host, boot_id_before):
    """True once the host reports a new kernel boot ID. False while SSH is down."""
    try:
        boot_id = get_host_boot_id(host)
    except (AnsibleConnectionFailure, PytestAnsibleConnectionFailure):
        return False
    return bool(boot_id) and boot_id != boot_id_before


def _read_restart_refusal(restart_type, async_res):
    """Return a skip/fail verdict if the command refused, else None.

    Only a nonzero rc is a refusal: a successful restart exits 0 while the host
    is still up.
    """
    result = async_res.get()
    rc = result.get("rc")
    if not rc:
        return None
    detail = (result.get("stderr") or result.get("stdout") or "").strip()
    if rc in _UNSUPPORTED_RCS and restart_type in _OPTIONAL_RESTARTS:
        return lambda: pytest.skip("{} is not supported on this platform (rc={}): {}".format(
            restart_type.value, rc, detail))
    return lambda: pytest.fail("{} refused to restart the host (rc={}): {}".format(
        restart_type.value, rc, detail))


def _trigger_self_rebooting(host, restart_type, boot_id_before, reboot_timeout):
    """Run a command that is meant to take the host down with it.

    Race the reboot against a refusal over the full boot budget. A refusal can
    take minutes to arrive (fast-reboot checks), so it cannot be given a
    short head start, and only a refusal may end the race early.
    """
    verdict = None
    command_read = False

    def _settled():
        # Boot ID first: if both land in the same poll, the reboot happened.
        nonlocal verdict, command_read
        if _boot_id_changed(host, boot_id_before):
            return True
        if not command_read and async_res.ready():
            command_read = True
            verdict = _read_restart_refusal(restart_type, async_res)
        return verdict is not None

    pool, async_res = host.shell(
        _RESTART_COMMAND[restart_type], module_async=True, module_ignore_errors=True)
    # Terminate the ThreadPool either way. Do not join: a dropped SSH leaves the
    # worker blocked until Ansible's timeout, and join would delay the UART /
    # boot_id watch (see tests/common/reboot.py).
    try:
        settled = wait_until(reboot_timeout, 1, 0, _settled)
        if verdict is not None:
            verdict()
        if not settled:
            pytest.fail("{} neither refused nor rebooted the host in {}s".format(
                restart_type.value, reboot_timeout))
    finally:
        pool.terminate()


def _trigger_panic(host, restart_type, boot_id_before, reboot_timeout):
    """Same shape as a reboot command, but sysrq has to be armed first."""
    _enable_panic_reboot(host)
    _trigger_self_rebooting(host, restart_type, boot_id_before, reboot_timeout)


def _trigger_watchdog(host, restart_type, boot_id_before, reboot_timeout):
    """Arm the watchdog and return while the host is still up.

    Unlike the reboot commands this one is not self-rebooting: `arm` exits
    normally and the hardware resets seconds later. Racing it against the boot
    ID would read that prompt return as a refusal, so arm synchronously and let
    the caller's boot_id wait prove the reset happened.
    """
    _arm_watchdog(host)


# How to set each restart off. The judgment that follows differs per type too,
# but that lives in _judge_restart_command() / _arm_watchdog(), so _restart()
# itself stays free of per-type branches.
_RESTART_TRIGGER = {
    Restart.REBOOT: _trigger_self_rebooting,
    Restart.WARM_REBOOT: _trigger_self_rebooting,
    Restart.FAST_REBOOT: _trigger_self_rebooting,
    Restart.PANIC: _trigger_panic,
    Restart.WATCHDOG: _trigger_watchdog,
}


def _restart(host, restart_type, wait=True, reboot_timeout=_HOST_REBOOT_TIMEOUT):
    """Restart `host` the chosen way and return the boot ID it had before.

    `reboot_timeout` budgets one phase, not the whole call: how long to wait for
    a new boot ID. With wait=True the service-startup wait that follows gets the
    same budget again, so the worst case is twice this value.
    """
    trigger = _RESTART_TRIGGER.get(restart_type)
    pytest_assert(trigger, "Unknown restart type {}".format(restart_type))
    boot_id_before = get_host_boot_id(host)
    pytest_assert(boot_id_before, "Could not read boot_id before {}".format(restart_type.value))
    trigger(host, restart_type, boot_id_before, reboot_timeout)
    if wait:
        pytest_assert(
            wait_host_rebooted(host, boot_id_before, timeout=reboot_timeout),
            "Host did not reboot after {}".format(restart_type.value))
    return boot_id_before


def _wait_bmc_up(duthost, boot_id_before, mux=None):
    pytest_assert(
        wait_host_rebooted(duthost, boot_id_before, timeout=BMC_REBOOT_SSH_TIMEOUT),
        "BMC did not reboot")
    duthost.meta("clear_facts")
    if mux is not None:
        mux.wait_ready()
    pytest_assert(
        wait_until(BMC_REBOOT_SSH_TIMEOUT, 10, 0, bmc_control_ready, duthost),
        "bmcctld did not become ready after BMC boot")


def pytest_generate_tests(metafunc):
    if "switch_host_restart" not in metafunc.fixturenames:
        return
    option = metafunc.config.getoption("--switch_host_restart")
    names = list(_SWITCH_HOST_RESTART_SCENARIOS)
    if option == "all":
        selected = names
    elif option == "random":
        selected = [random.choice(names)]
    else:
        selected = [name.strip() for name in option.split(",") if name.strip()]
        unknown = [name for name in selected if name not in _SWITCH_HOST_RESTART_SCENARIOS]
        if unknown:
            raise pytest.UsageError(
                "Unknown --switch_host_restart {}: choose from {}".format(
                    ",".join(unknown), ",".join(names)))
    metafunc.parametrize("switch_host_restart", selected, ids=selected)


def _assert_host_restart_leaves_console(switch_host, console_mux, uart, restart_type,
                                        side=CONSOLE_CPU, uart_expect=None):
    wait = uart_expect is None
    with allure.step("Run {} with console on {} and expect console stays".format(
            restart_type.value, side)):
        console_mux.set_console(side)
        console_mux.assert_console(side)
        uart.drain()
        boot_id_before = _restart(switch_host, restart_type, wait=wait)
        if uart_expect == "host_boot":
            uart.expect_host_boot_log()
        elif uart_expect == "panic":
            uart.expect_panic()
        if uart_expect is not None:
            pytest_assert(
                wait_host_rebooted(switch_host, boot_id_before),
                "SWITCH-HOST did not come back after {}".format(restart_type.value))
        console_mux.assert_console(side)


def test_host_power_off_routes_console_to_bmc(duthost, switch_host, console_mux):
    """Power-off moves the console to BMC. Power-on leaves it there."""
    with allure.step("Set console on CPU"):
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)

    with allure.step("Power off SWITCH-HOST and expect console on BMC"):
        bmc_power_off_host(duthost, switch_host)
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Power on SWITCH-HOST and expect console still on BMC"):
        recover_switch_host_after_power_off(
            duthost, switch_host, context="serial-console power-on")
        console_mux.assert_console(CONSOLE_BMC)


def test_host_initiated_restart_leaves_console_unchanged(duthost, switch_host, console_mux,
                                                         bmc_shared_uart, switch_host_restart):
    """Host software restart does not move the console.

    Scenarios: reboot (CPU + UART), panic, reboot-bmc, fast-reboot.
    Select with --switch_host_restart all|random|reboot,panic,reboot-bmc,fast-reboot.
    warm-reboot and watchdog live in their own cases so each can skip on its own terms.
    """
    restart_type, side, uart_expect = _SWITCH_HOST_RESTART_SCENARIOS[switch_host_restart]
    _assert_host_restart_leaves_console(
        switch_host, console_mux, bmc_shared_uart, restart_type, side, uart_expect)


def test_host_initiated_warm_reboot_leaves_console_unchanged(duthost, switch_host, console_mux,
                                                             bmc_shared_uart):
    """Warm reboot does not move the console.

    Kept out of `_SWITCH_HOST_RESTART_SCENARIOS` so the whole case can skip when the
    platform refuses warm-reboot, instead of failing the shared parametrized case.
    """
    _assert_host_restart_leaves_console(
        switch_host, console_mux, bmc_shared_uart, Restart.WARM_REBOOT)


def test_host_initiated_watchdog_reset_leaves_console_unchanged(duthost, switch_host, console_mux,
                                                                bmc_shared_uart):
    """A watchdog-driven reset does not move the console.

    Kept out of `_SWITCH_HOST_RESTART_SCENARIOS` because `watchdogutil` cannot be
    judged by exit code the way the reboot scripts can, so it needs its own probe
    and its own arm check.
    """
    _require_watchdog_support(switch_host)
    _assert_host_restart_leaves_console(
        switch_host, console_mux, bmc_shared_uart, Restart.WATCHDOG)


def test_bmc_power_cycle_routes_console_to_bmc(duthost, switch_host, console_mux, bmc_shared_uart,
                                               get_pdu_controller):
    """Board/PDU cycle returns the console to BMC. Skip if the testbed has no PDU."""
    pdu = get_pdu_controller(switch_host)
    if pdu is None:
        pytest.skip("No PDU for board power cycle")
    uart = bmc_shared_uart

    with allure.step("Initialized at CPU, Power cycle and expect BMC boot log, console on BMC"):
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)
        uart.drain()
        boot_id_before = get_host_boot_id(duthost)
        pytest_assert(boot_id_before, "Could not read BMC boot_id before PDU cycle")
        pytest_assert(pdu_reboot(pdu), "Board power cycle failed")
        uart.expect_bmc_boot_log()
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)
        pytest_assert(wait_host_on(switch_host), "SWITCH-HOST did not come back after PDU cycle")

    with allure.step("Initialized at BMC, Power cycle and expect BMC boot log, console on BMC"):
        console_mux.set_console(CONSOLE_BMC)
        console_mux.assert_console(CONSOLE_BMC)
        uart.drain()
        boot_id_before = get_host_boot_id(duthost)
        pytest_assert(boot_id_before, "Could not read BMC boot_id before PDU cycle")
        pytest_assert(pdu_reboot(pdu), "Board power cycle failed")
        uart.expect_bmc_boot_log()
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)
        pytest_assert(wait_host_on(switch_host), "SWITCH-HOST did not come back after PDU cycle")


def test_bmc_reboot_uart_shows_bmc_boot(duthost, switch_host, console_mux, bmc_shared_uart):
    """BMC reboot shows BMC boot on the console with no software console switch."""
    uart = bmc_shared_uart

    with allure.step("""
        Initialized the console on CPU,
        Rebooting BMC with command `sudo reboot`,
        expect BMC boot log,
        console back to BMC
    """):
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)
        uart.drain()
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False,
                                  reboot_timeout=BMC_REBOOT_SSH_TIMEOUT)
        try:
            uart.expect_bmc_boot_log()
        finally:
            _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)


def test_bmc_boot_host_power_and_console_default(duthost, switch_host, console_mux):
    """BMC reboot never auto-switches the console to CPU."""
    with allure.step("Set console on BMC and power off SWITCH-HOST"):
        console_mux.set_console(CONSOLE_BMC)
        console_mux.assert_console(CONSOLE_BMC)
        bmc_power_off_host(duthost, switch_host)

    with allure.step("Reboot BMC with host off and expect console on BMC"):
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False,
                                  reboot_timeout=BMC_REBOOT_SSH_TIMEOUT)
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Ensure SWITCH-HOST is on, reboot BMC, and expect console on BMC"):
        ensure_host_on(duthost, switch_host)
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False,
                                  reboot_timeout=BMC_REBOOT_SSH_TIMEOUT)
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)


def test_set_console_same_side_is_noop(duthost, switch_host, console_mux, bmc_shared_uart):
    """Setting console to the side it is already on is a no-op."""
    uart = bmc_shared_uart

    with allure.step("Set console to BMC twice and expect no boot log"):
        console_mux.set_console(CONSOLE_BMC)
        console_mux.assert_console(CONSOLE_BMC)
        uart.drain()
        console_mux.set_console(CONSOLE_BMC)
        uart.expect_no_boot_log()
        console_mux.assert_console(CONSOLE_BMC)
        uart.sendline()

    with allure.step("Set console to CPU twice and expect no boot log"):
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)
        uart.drain()
        console_mux.set_console(CONSOLE_CPU)
        uart.expect_no_boot_log()
        console_mux.assert_console(CONSOLE_CPU)
        uart.sendline()


def test_power_action_while_console_already_on_bmc(duthost, switch_host, console_mux,
                                                   platform_api_conn):  # noqa: F811
    """From console on BMC, host power-off / power-on / reset leave the console on BMC."""
    with allure.step("Set console on BMC"):
        console_mux.set_console(CONSOLE_BMC)
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Power off SWITCH-HOST and expect console on BMC"):
        bmc_power_off_host(duthost, switch_host)
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Power on SWITCH-HOST and expect console on BMC"):
        recover_switch_host_after_power_off(
            duthost, switch_host, context="serial-console power-on")
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Reset SWITCH-HOST and expect console on BMC"):
        reset_host(platform_api_conn, switch_host)
        console_mux.assert_console(CONSOLE_BMC)


def test_host_reset_leaves_console_unchanged(duthost, switch_host, console_mux,
                                             platform_api_conn):  # noqa: F811
    """Host reset does not move the console off CPU."""
    with allure.step("Set console on CPU"):
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)

    with allure.step("Reset SWITCH-HOST and expect console stays on CPU"):
        reset_host(platform_api_conn, switch_host)
        console_mux.assert_console(CONSOLE_CPU)
