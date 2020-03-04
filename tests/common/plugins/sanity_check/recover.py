
import logging
import time

import constants

from common.utilities import wait, wait_until
from common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)


def reboot_dut(dut, localhost, cmd):
    logger.info("Reboot dut using cmd='%s'" % cmd)
    reboot_task, reboot_res = dut.command(cmd, module_async=True)

    logger.info("Wait for DUT to go down")
    try:
        localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=300)
    except RunAnsibleModuleFail as e:
        logger.error("DUT did not go down, exception: " + repr(e))
        if reboot_task.is_alive():
            logger.error("Rebooting is not completed")
            reboot_task.terminate()
        logger.error("reboot result %s" % str(reboot_res.get()))
        assert False, "Failed to reboot the DUT"

    localhost.wait_for(host=dut.hostname, port=22, state="started", delay=10, timeout=300)
    wait(30, msg="Wait 30 seconds for system to be stable.")


def recover(dut, localhost, recover_method):
    logger.info("Try to recover %s using method %s" % (dut.hostname, recover_method))
    if constants.RECOVER_METHODS[recover_method]["reboot"]:
        reboot_dut(dut, localhost, constants.RECOVER_METHODS[recover_method]["cmd"])
    else:
        dut.command(constants.RECOVER_METHODS[recover_method]["cmd"])
        wait(30, msg="Wait 30 seconds for system to be stable.")
