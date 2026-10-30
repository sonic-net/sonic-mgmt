"""BMC shared-UART auto-switch tests.

Cases set or observe console on BMC or CPU. They do not name a vendor mux API.
"""

import random
from enum import Enum

import pytest

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


_RESTART_COMMAND = {
    Restart.REBOOT: "sudo reboot",
    Restart.WARM_REBOOT: "sudo warm-reboot",
    Restart.FAST_REBOOT: "sudo fast-reboot",
    Restart.WATCHDOG: "sudo watchdogutil arm -s 5",
    Restart.PANIC: "sudo sh -c 'echo c > /proc/sysrq-trigger'",
}

# CPU/BMC-side host restarts that share set → assert → restart → assert.
# uart_expect None: prove reboot with boot_id. Otherwise watch UART then wait_host_on.
_SWITCH_HOST_RESTART_SCENARIOS = {
    "reboot": (Restart.REBOOT, CONSOLE_CPU, "host_boot"),
    "panic": (Restart.PANIC, CONSOLE_CPU, "panic"),
    "watchdog": (Restart.WATCHDOG, CONSOLE_CPU, None),
    "reboot-bmc": (Restart.REBOOT, CONSOLE_BMC, None),
    "fast-reboot": (Restart.FAST_REBOOT, CONSOLE_CPU, None),
}


@pytest.fixture(scope="module", autouse=True)
def restore_switch_host(duthost, switch_host):
    yield
    recover_switch_host_after_power_off(
        duthost, switch_host, context="serial-console auto-switch teardown")


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


def _restart(host, restart_type, wait=True):
    pytest_assert(isinstance(restart_type, Restart), "Unknown restart type {}".format(restart_type))
    command = _RESTART_COMMAND[restart_type]
    boot_id_before = get_host_boot_id(host)
    pytest_assert(boot_id_before, "Could not read boot_id before {}".format(restart_type.value))
    if restart_type == Restart.PANIC:
        _enable_panic_reboot(host)
    host.shell(command, module_async=True)
    if wait:
        pytest_assert(
            wait_host_rebooted(host, boot_id_before),
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
        _restart(switch_host, restart_type, wait=wait)
        if uart_expect == "host_boot":
            uart.expect_host_boot_log()
            pytest_assert(
                wait_host_on(switch_host),
                "SWITCH-HOST did not come back after {}".format(restart_type.value))
        elif uart_expect == "panic":
            uart.expect_panic()
            pytest_assert(
                wait_host_on(switch_host),
                "SWITCH-HOST did not come back after {}".format(restart_type.value))
        console_mux.assert_console(side)


def test_host_power_off_routes_console_to_bmc(duthost, switch_host, console_mux):
    """Power-off moves the console to BMC. Power-on leaves it there."""
    with allure.step("Ensure SWITCH-HOST is on and console is on CPU"):
        ensure_host_on(duthost, switch_host)
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

    Scenarios: reboot (CPU + UART), panic, watchdog, reboot-bmc, fast-reboot.
    Select with --switch_host_restart all|random|reboot,panic,watchdog,reboot-bmc,fast-reboot.
    """
    with allure.step("Ensure SWITCH-HOST is on"):
        ensure_host_on(duthost, switch_host)
    restart_type, side, uart_expect = _SWITCH_HOST_RESTART_SCENARIOS[switch_host_restart]
    _assert_host_restart_leaves_console(
        switch_host, console_mux, bmc_shared_uart, restart_type, side, uart_expect)


def test_host_initiated_warm_reboot_leaves_console_unchanged(duthost, switch_host, console_mux,
                                                             bmc_shared_uart):
    """Warm reboot does not move the console.

    TODO: Not in `_SWITCH_HOST_RESTART_SCENARIOS` because some platforms do not support
    warm-reboot yet. A dedicated case is easier to skip.
    """
    with allure.step("Ensure SWITCH-HOST is on"):
        ensure_host_on(duthost, switch_host)
    _assert_host_restart_leaves_console(
        switch_host, console_mux, bmc_shared_uart, Restart.WARM_REBOOT)


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
        pytest_assert(pdu_reboot(pdu), "PDU board cycle failed")
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
        pytest_assert(pdu_reboot(pdu), "PDU board cycle failed")
        uart.expect_bmc_boot_log()
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)
        pytest_assert(wait_host_on(switch_host), "SWITCH-HOST did not come back after PDU cycle")


def test_bmc_reboot_uart_shows_bmc_boot(duthost, switch_host, console_mux, bmc_shared_uart):
    """BMC reboot shows BMC boot on the console with no software console switch."""
    with allure.step("Ensure SWITCH-HOST is on"):
        ensure_host_on(duthost, switch_host)
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
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False)
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
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False)
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)

    with allure.step("Power on SWITCH-HOST, reboot BMC, and expect console on BMC"):
        recover_switch_host_after_power_off(
            duthost, switch_host, context="serial-console power-on")
        boot_id_before = _restart(duthost, Restart.REBOOT, wait=False)
        _wait_bmc_up(duthost, boot_id_before, console_mux)
        console_mux.assert_console(CONSOLE_BMC)


def test_set_console_same_side_is_noop(duthost, switch_host, console_mux, bmc_shared_uart):
    """Setting console to the side it is already on is a no-op."""
    with allure.step("Ensure SWITCH-HOST is on"):
        ensure_host_on(duthost, switch_host)
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
    with allure.step("Ensure SWITCH-HOST is on and console is on BMC"):
        ensure_host_on(duthost, switch_host)
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
    with allure.step("Ensure SWITCH-HOST is on and console is on CPU"):
        ensure_host_on(duthost, switch_host)
        console_mux.set_console(CONSOLE_CPU)
        console_mux.assert_console(CONSOLE_CPU)

    with allure.step("Reset SWITCH-HOST and expect console stays on CPU"):
        reset_host(platform_api_conn, switch_host)
        console_mux.assert_console(CONSOLE_CPU)
