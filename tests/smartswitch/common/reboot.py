import logging
import pytest
from multiprocessing.pool import ThreadPool
from tests.common.reboot import reboot_ss_ctrl_dict as reboot_dict, REBOOT_TYPE_HISTOYR_QUEUE, \
    sync_reboot_history_queue_with_dut, execute_reboot_smartswitch_command

logger = logging.getLogger(__name__)

REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_UNKNOWN = "unknown"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_WATCHDOG = "Watchdog"


def log_and_perform_reboot(duthost, reboot_type, dpu_name):
    """
    Logs and initiates the reboot process based on the host type.
    Skips the test if the host is a DPU.

    @param duthost: DUT host object
    @param reboot_type: Type of reboot to perform
    @param dpu_name: Name of the DPU (optional)
    """
    hostname = duthost.hostname

    if reboot_type == REBOOT_TYPE_COLD:
        if duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"):
            if dpu_name is None:
                logger.info("Sync reboot cause history queue with DUT reboot cause history queue")
                sync_reboot_history_queue_with_dut(duthost)

                with ThreadPool(processes=1) as pool:
                    async_result = pool.apply_async(execute_reboot_smartswitch_command,
                                                    (duthost, reboot_type, hostname))
                    pool.terminate()

                return {"failed": False,
                        "result": async_result}

            else:
                logger.info("Rebooting the DPU {} with type {}".format(dpu_name, reboot_type))
                return duthost.command("sudo reboot -d {}".format(dpu_name))
        elif duthost.facts['is_dpu']:
            pytest.skip("Skipping the reboot test as the DUT is a DPU")
    else:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))


def perform_reboot(duthost, reboot_type=REBOOT_TYPE_COLD, dpu_name=None):
    """
    Performs a reboot and validates the DPU status after reboot.

    @param duthost: DUT host object
    @param reboot_type: Reboot type
    @param dpu_name: DPU name
    """
    if reboot_type not in reboot_dict:
        pytest.skip("Skipping the reboot test as the reboot type {} is not supported".format(reboot_type))

    res = log_and_perform_reboot(duthost, reboot_type, dpu_name)
    if res and res['failed'] is True:
        if dpu_name is None:
            pytest.fail("Failed to reboot the {} with type {}".format(duthost.hostname, reboot_type))
        else:
            pytest.fail("Failed to reboot the DPU {} with type {}".format(dpu_name, reboot_type))

    if dpu_name is None:
        logger.info("Appending the last reboot type to the queue")
        REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)
