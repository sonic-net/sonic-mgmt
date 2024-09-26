import copy
import pytest
import logging
import time
from tests.common.reboot import reboot, REBOOT_TYPE_COLD

test_report = dict()

MGFX_HWSKU = ["Arista-720DT-G48S4", "Nokia-7215", "Nokia-M0-7215", "Celestica-E1031-T48S4"]
MGFX_XCVR_INTF = ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']


def wait_until_uptime(duthost, post_reboot_delay):
    logging.info("Wait until DUT uptime reaches {}s".format(post_reboot_delay))
    while duthost.get_uptime().total_seconds() < post_reboot_delay:
        time.sleep(1)


def get_test_report():
    global test_report
    result = copy.deepcopy(test_report)
    test_report = dict()
    return result


@pytest.fixture
def add_fail_step_to_reboot(localhost, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    def add_exit_to_script(reboot_type):
        add_exit_to_script.params = tuple()
        if "warm" in reboot_type:
            reboot_script = "warm-reboot"
        elif "fast" in reboot_type:
            reboot_script = "fast-reboot"

        cmd_format = "sed -i -u 's/{}/{}/' {}"
        reboot_script_path = duthost.shell(
            'which {}'.format(reboot_script))['stdout']
        original_line = '^setup_control_plane_assistant$'
        replaced_line = 'exit -1; setup_control_plane_assistant'
        replace_cmd = cmd_format.format(
            original_line, replaced_line, reboot_script_path)
        logging.info(
            "Modify {} to exit before set +e".format(reboot_script_path))
        duthost.shell(replace_cmd)
        add_exit_to_script.params = (
            cmd_format, replaced_line, original_line, reboot_script_path, reboot_script_path)

    yield add_exit_to_script

    if add_exit_to_script.params:
        cmd_format, replaced_line, original_line, reboot_script_path, reboot_script_path = add_exit_to_script.params
        replace_cmd = cmd_format.format(
            replaced_line, "setup_control_plane_assistant", reboot_script_path)
        logging.info("Revert {} script to original".format(reboot_script_path))
        duthost.shell(replace_cmd)
    # cold reboot DUT to restore any bad state caused by negative test
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD)
