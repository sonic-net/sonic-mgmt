import logging
import pytest

logger = logging.getLogger(__name__)


REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_UNKNOWN = "unknown"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_WATCHDOG = "Watchdog"


'''
    command                : command to reboot the DUT
'''
reboot_dict = {
    REBOOT_TYPE_COLD: {
        "command": "sudo reboot"
    },
    REBOOT_TYPE_KERNEL_PANIC: {
        "command": "echo c | sudo tee /proc/sysrq-trigger"
    },
    REBOOT_TYPE_WATCHDOG: {
        "command": "sudo watchdog -t 1"
    }
}


def reboot_smartswitch(duthost, reboot_type='cold'):
    """
    reboots SmartSwitch or a DPU
    :param duthost: DUT host object
    :param reboot_type: reboot type (cold)
    """

    if reboot_type not in reboot_dict:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))

    hostname = duthost.hostname
    dut_datetime = duthost.get_now_time(utc_timezone=True)

    logging.info("Rebooting the DUT {} with type {}".format(hostname, reboot_type))

    reboot_res = duthost.command(reboot_dict[reboot_type]["command"])

    return [reboot_res, dut_datetime]



