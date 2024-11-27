import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.platform_api import module
from tests.smartswitch.common.device_utils_dpu import check_dpu_ping_status, check_dpu_reboot_cause
from tests.common.reboot import sync_reboot_history_queue_with_dut, REBOOT_TYPE_HISTOYR_QUEUE

logger = logging.getLogger(__name__)

REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_UNKNOWN = "unknown"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_WATCHDOG = "Watchdog"


'''
command : command to reboot the DUT
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


def log_and_perform_reboot(duthost, reboot_type, dpu_name):
    """
    Logs and initiates the reboot process based on the host type.
    Skips the test if the host is a DPU.

    @param duthost: DUT host object
    @param reboot_type: Type of reboot to perform
    @param dpu_name: Name of the DPU (optional)
    """
    hostname = duthost.hostname
    logger.info("Rebooting the DUT {} with type {}".format(hostname, reboot_type))

    if reboot_type == REBOOT_TYPE_COLD:
        if duthost.is_smartswitch():
            return duthost.command("sudo reboot -d {}".format(dpu_name))
        elif duthost.is_dpu():
            pytest.skip("Skipping the reboot test as the DUT is a DPU")
    else:
        return duthost.command(reboot_dict[reboot_type]["command"])


def check_dpu_reboot_status(duthost, dpu_ip, dpu_name, dut_datetime):
    """
    Checks the DPU's status post-reboot by verifying its uptime and ping status.

    @param duthost: DUT host object
    @param dpu_ip: DPU IP address
    @param dpu_name: Name of the DPU
    @param dut_datetime: Datetime of DUT when reboot initiated
    """
    pytest_assert(wait_until(120, 30, 0, check_dpu_ping_status, duthost, dpu_ip),
                  "DPU ping is not operational")

    dut_uptime = duthost.get_up_time(utc_timezone=True)
    assert float(dut_uptime.strftime("%s")) > float(dut_datetime.strftime("%s")), \
        "DPU {} did not reboot".format(dpu_name)

    logger.info("DUT {} uptime is {}".format(duthost.hostname, dut_uptime))
    check_dpu_reboot_cause(duthost, dpu_name)


def perform_and_check_reboot(duthost, platform_api_conn, reboot_type=REBOOT_TYPE_COLD,
                             dpu_id=0, dpu_name=None):
    """
    Performs a reboot and validates the DPU status after reboot.

    @param duthost: DUT host object
    @param platform_api_conn: Platform API connection
    @param reboot_type: Reboot type
    @param dpu_id: DPU ID
    @param dpu_name: DPU name
    """
    if reboot_type not in reboot_dict:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))

    logger.info("Sync reboot cause history queue with DUT reboot cause history queue")
    sync_reboot_history_queue_with_dut(duthost)

    res = log_and_perform_reboot(duthost, reboot_type, dpu_name)
    if res.is_failed or res.rc != 0:
        pytest.fail("Failed to reboot the DPU {}".format(dpu_name))

    dut_datetime = duthost.get_now_time(utc_timezone=True)

    logger.info("Appending the last reboot type to the queue")
    REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)

    dpu_ip = module.get_ip(platform_api_conn, dpu_id)
    check_dpu_reboot_status(duthost, dpu_ip, dpu_name, dut_datetime)
