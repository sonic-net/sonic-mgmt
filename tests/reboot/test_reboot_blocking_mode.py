import logging
import pytest
import re
import json
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
]

COMMAND_TIMEOUT = 90  # seconds


def check_if_platform_reboot_enabled(duthost) -> bool:
    platform = get_command_result(duthost, "sonic-cfggen -H -v DEVICE_METADATA.localhost.platform")
    return check_if_dut_file_exist(duthost, "/usr/share/sonic/device/{}/platform_reboot".format(platform))


def mock_systemctl_reboot(duthost):
    if not check_if_dut_file_exist(duthost, "/sbin/reboot.bak"):
        # Check exist to avoid override original reboot file.
        execute_command(duthost, "sudo mv /sbin/reboot /sbin/reboot.bak")
    execute_command(duthost, "sudo echo \"\" > /sbin/reboot")
    execute_command(duthost, "sudo chmod +x /sbin/reboot")
    execute_command_ignore_error(duthost, "sudo /usr/local/bin/watchdogutil disarm")

    # Disable watch dog to avoid reboot too early.
    execute_command(
        duthost,
        "sudo sed -i 's#/usr/local/bin/watchdogutil#/usr/local/bin/disabled_watchdogutil#g' /usr/local/bin/reboot")


def restore_systemctl_reboot_and_reboot(duthost):
    if not check_if_dut_file_exist(duthost, "/sbin/reboot.bak"):
        return
    execute_command(duthost, "sudo rm /sbin/reboot")
    execute_command(duthost, "sudo mv /sbin/reboot.bak /sbin/reboot")
    execute_command(
        duthost,
        "sudo sed -i 's#/usr/local/bin/disabled_watchdogutil#/usr/local/bin/watchdogutil#g' /usr/local/bin/reboot")
    execute_command(duthost, "sudo reboot")
    wait_critical_processes(duthost)


def mock_reboot_config_file(duthost):
    if (
        check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf")
        and not check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf.bak")
    ):
        execute_command(duthost, "sudo mv /etc/sonic/reboot.conf /etc/sonic/reboot.conf.bak")
    execute_command(
        duthost,
        "echo -e \"blocking_mode=true\\nshow_timer=true\" > /etc/sonic/reboot.conf")


def mock_reboot_config_file_with_0_timeout(duthost):
    if (
        check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf")
        and not check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf.bak")
    ):
        execute_command(duthost, "sudo mv /etc/sonic/reboot.conf /etc/sonic/reboot.conf.bak")
    execute_command(
        duthost,
        "echo -e \"blocking_mode=true\\nblocking_mode_timeout=0\\nshow_timer=true\" > /etc/sonic/reboot.conf")


def restore_reboot_config_file(duthost):
    execute_command(duthost, "sudo rm /etc/sonic/reboot.conf")
    if check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf.bak"):
        execute_command(duthost, "sudo mv /etc/sonic/reboot.conf.bak /etc/sonic/reboot.conf")


def execute_command(duthost, cmd):
    result = duthost.shell(cmd)
    result_txt = json.dumps(result, indent=4, ensure_ascii=False)
    logging.info(f"COMMAND RESULT ({cmd}): {result_txt}")
    pytest_assert(result["rc"] == 0, "Unexpected rc: {}".format(result["rc"]))


def execute_command_ignore_error(duthost, cmd):
    result = duthost.shell(cmd, module_ignore_errors=True)
    result_txt = json.dumps(result, indent=4, ensure_ascii=False)
    logging.info(f"COMMAND RESULT ({cmd}): {result_txt}")


def get_command_result(duthost, cmd):
    result = duthost.shell(cmd, module_ignore_errors=True)
    result_txt = json.dumps(result, indent=4, ensure_ascii=False)
    logging.info(f"COMMAND RESULT ({cmd}): {result_txt}")
    return result["stdout"]


def check_if_dut_file_exist(duthost, filepath) -> bool:
    result = duthost.shell(f"test -f {filepath} && echo true || echo false", module_ignore_errors=True)
    return "true" in result["stdout"]


class TestRebootBlockingModeCLI:
    @pytest.fixture(autouse=True, scope="function")
    def setup_teardown(
        self,
        duthosts,
        enum_rand_one_per_hwsku_hostname
    ):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if check_if_platform_reboot_enabled(duthost):
            pytest.skip("Skip test because platform reboot is enabled.")

        mock_systemctl_reboot(duthost)
        yield
        restore_systemctl_reboot_and_reboot(duthost)

    def test_non_blocking_mode(
        self,
        duthosts,
        enum_rand_one_per_hwsku_hostname
    ):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        result = get_command_result(
            duthost,
            f"sudo timeout {COMMAND_TIMEOUT}s bash -c 'sudo reboot; echo \"ExpectedFinished\"'")
        pytest_assert("ExpectedFinished" in result, "Reboot didn't exited as expected.")

    def test_blocking_mode(
        self,
        duthosts,
        enum_rand_one_per_hwsku_hostname
    ):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        result = get_command_result(
            duthost,
            f"sudo timeout {COMMAND_TIMEOUT}s bash -c 'sudo reboot -b -v; echo \"UnexpectedFinished\"'")
        pytest_assert("UnexpectedFinished" not in result, "Reboot script didn't blocked as expected.")
        pattern = r".*\n[.]+$"
        pytest_assert(re.search(pattern, result), "Cannot find dots as expected in output: {}".format(result))


class TestRebootBlockingModeConfigFile:
    @pytest.fixture(autouse=True, scope="function")
    def setup_teardown(
        self,
        duthosts,
        enum_rand_one_per_hwsku_hostname
    ):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if check_if_platform_reboot_enabled(duthost):
            pytest.skip("Skip test because platform reboot is enabled.")

        mock_systemctl_reboot(duthost)
        yield

        restore_reboot_config_file(duthost)
        restore_systemctl_reboot_and_reboot(duthost)

    def test_timeout_for_blocking_mode(
        self,
        duthosts,
        enum_rand_one_per_hwsku_hostname
    ):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        mock_reboot_config_file_with_0_timeout(duthost)
        result = get_command_result(
            duthost,
            f"sudo timeout {COMMAND_TIMEOUT}s bash -c 'sudo reboot; echo \"ExpectedFinished\"'")
        pytest_assert("ExpectedFinished" in result, "Reboot didn't exited as expected.")
