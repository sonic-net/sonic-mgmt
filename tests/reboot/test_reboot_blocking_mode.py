import binascii
import logging
import pytest
import time
import ipaddress
import re
from socket import inet_aton
from scapy.all import Ether, UDP, Raw
from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
from ptf.dataplane import match_exp_pkt

pytestmark = [
    pytest.mark.topology('mx', 'm0'),
]

COMMAND_TIMEOUT = 600 # seconds

def check_if_platform_reboot_enabled(duthost) -> bool:
    platform = get_command_result_ignore_error(duthost, "sonic-cfggen -H -v DEVICE_METADATA.localhost.platform")
    return check_if_dut_file_exist("/usr/share/sonic/device/{}/platform_reboot".format(platform))

def mock_systemctl_reboot(duthost):
    execute_command("sudo mv /sbin/reboot /sbin/reboot.bak")
    execute_command("sudo echo \"\" > /sbin/reboot")
    execute_command("sudo chmod +x /sbin/reboot")

def restore_systemctl_reboot_and_reboot(duthost):
    if not check_if_dut_file_exist(duthost, "/sbin/reboot.bak"):
        return
    execute_command("sudo rm /sbin/reboot")
    execute_command("sudo mv /sbin/reboot.bak /sbin/reboot")

def mock_reboot_config_file(duthost):
    if check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf"):
        execute_command("sudo mv /etc/sonic/reboot.conf /etc/sonic/reboot.conf.bak")
    execute_command("echo -e \"blocking_mode=true\\nshow_timer=true\" > /etc/sonic/reboot.conf")

def restore_reboot_config_file(duthost):
    execute_command("sudo rm /etc/sonic/reboot.conf")
    if check_if_dut_file_exist(duthost, "/etc/sonic/reboot.conf.bak"):
        execute_command("sudo mv /etc/sonic/reboot.conf.bak /etc/sonic/reboot.conf")

def execute_command(duthost, cmd):
    result = duthost.shell(cmd, timeout=COMMAND_TIMEOUT)
    pytest_assert(result["rc"] == 0, "Unexpected rc: {}".format(result["rc"]))

def get_command_result(duthost, cmd):
    result = duthost.shell(cmd, timeout=COMMAND_TIMEOUT)
    pytest_assert(result["rc"] == 0, "Unexpected rc: {}".format(result["rc"]))
    return result["stdout"]

def get_command_result_ignore_error(duthost, cmd):
    result = duthost.shell(cmd, module_ignore_errors=True, timeout=COMMAND_TIMEOUT)
    return result["stdout"]

def check_if_dut_file_exist(duthost, filepath) -> bool:
    result = duthost.shell("test -f {} && echo true || echo false".format(filepath), module_ignore_errors=True)
    return "true" in result["stdout"]

class TestRebootBlockingModeCLI:
    def test_non_blocking_mode(
        self,
        duthost,
        ptfadapter,
        random_intf_pair
    ):
        if check_if_platform_reboot_enabled(duthost):
            return
        
        mock_systemctl_reboot(duthost)

        result = get_command_result(duthost, "sudo reboot; echo \"ExpectedFinished\"")
        pytest_assert("ExpectedFinished" in result, "Reboot didn't exited as expected.")

        restore_systemctl_reboot_and_reboot(duthost)

    def test_blocking_mode(
        self,
        duthost,
        ptfadapter,
        random_intf_pair
    ):
        if check_if_platform_reboot_enabled(duthost):
            return
        
        mock_systemctl_reboot(duthost)

        result = get_command_result_ignore_error(duthost, "sudo reboot -b; echo \"UnexpectedFinished\"")
        pytest_assert("UnexpectedFinished" not in result, "Reboot script didn't blocked as expected.")

        restore_systemctl_reboot_and_reboot(duthost)
    
    def test_blocking_mode_with_running_config(
        self,
        duthost,
        ptfadapter,
        random_intf_pair
    ):
        if check_if_platform_reboot_enabled(duthost):
            return
        
        mock_systemctl_reboot(duthost)

        result = get_command_result_ignore_error(duthost, "sudo reboot -b -v; echo \"UnexpectedFinished\"")
        pytest_assert("UnexpectedFinished" not in result, "Reboot script didn't blocked as expected.")
        pattern = r"Issuing OS-level reboot\s*\n[.]+"
        pytest_assert(re.search(pattern, result), "Cannot find dots as expected in output: {}".format(result))

        restore_systemctl_reboot_and_reboot(duthost)

class TestRebootBlockingModeConfigFile:
    def test_blocking_mode_with_running_config_using_config_file(
        self,
        duthost,
        ptfadapter,
        random_intf_pair
    ):
        if check_if_platform_reboot_enabled(duthost):
            return
        
        mock_systemctl_reboot(duthost)
        mock_reboot_config_file(duthost)

        result = get_command_result_ignore_error(duthost, "sudo reboot; echo \"UnexpectedFinished\"")
        pytest_assert("UnexpectedFinished" not in result, "Reboot script didn't blocked as expected.")
        pattern = r"Issuing OS-level reboot\s*\n[.]+"
        pytest_assert(re.search(pattern, result), "Cannot find dots as expected in output: {}".format(result))

        restore_reboot_config_file(duthost)
        restore_systemctl_reboot_and_reboot(duthost)
