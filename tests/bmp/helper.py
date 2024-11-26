import time
import re
import logging
import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.bmp_utils import BMPEnvironment


logger = logging.getLogger(__name__)



def bmp_container(duthost):
    env = BMPEnvironment(duthost)
    return env.bmp_container


def dump_bmp_log(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s cat /var/log/openbmpd.log" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("BMP log: " + res['stdout'])


def dump_system_status(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s ps -efwww" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("BMP process: " + res['stdout'])
    dut_command = "docker exec %s date" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("System time: " + res['stdout'] + res['stderr'])



def check_bmp_status(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s supervisorctl status %s" % (env.bmp_container, env.bmp_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']

