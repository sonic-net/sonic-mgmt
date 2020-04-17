
import logging
import time

import constants

from common.utilities import wait, wait_until
from common.errors import RunAnsibleModuleFail
from common.platform.device_utils import fanout_switch_port_lookup

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
    wait(120, msg="Wait 120 seconds for system to be stable.")


def __recover_interfaces(dut, fanouthosts, result):
    for port in result['down_ports']:
        logging.info("Restoring port {}".format(port))
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, port)
        if fanout and fanout_port:
            fanout.no_shutdown(fanout_port)
        dut.no_shutdown(port)
    wait(30, msg="Wait 30 seconds for interface(s) to restore.")


def __recover_services(dut, result):
    status   = result['services_status']
    services = [ x for x in status if not status[x] ]
    logging.info("Service(s) down: {}".format(services))
    return 'reboot' if 'database' in services else 'config_reload'


def adaptive_recover(dut, localhost, fanouthosts, check_results):
    outstanding_action = None
    for result in check_results:
        if result['failed']:
            logging.info("Restoring {}".format(result))
            if result['check_item'] == 'interfaces':
                __recover_interfaces(dut, fanouthosts, result)
            elif result['check_item'] == 'services':
                action             = __recover_services(dut, result)
                # Only allow outstanding_action be overridden when it is
                # None. In case the outstanding_action has already been
                # been set to 'reboot'.
                outstanding_action = action if not outstanding_action
            else:
                outstanding_action = 'reboot'

    if outstanding_action:
        method = constants.RECOVER_METHODS[outstanding_action]
        if method["reboot"]:
            reboot_dut(dut, localhost, constants.RECOVER_METHODS[recover_method]["cmd"])
        else:
            dut.command(method["cmd"])
            wait(60, msg="Wait 60 seconds for system to be stable.")


def recover(dut, localhost, fanouthosts, check_results, recover_method):
    logger.info("Try to recover %s using method %s" % (dut.hostname, recover_method))
    method = constants.RECOVER_METHODS[recover_method]
    if method["adaptive"]:
        adaptive_recover(dut, localhost, fanouthosts, check_results)
    elif method["reboot"]:
        reboot_dut(dut, localhost, constants.RECOVER_METHODS[recover_method]["cmd"])
    else:
        dut.command(method["cmd"])
        wait(60, msg="Wait 60 seconds for system to be stable.")
