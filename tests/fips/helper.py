import logging
import json
import os
import pytest
import time
import sys

from tests.common import config_reload
from tests.common.reboot import reboot, REBOOT_TYPE_POWEROFF
from tests.common.helpers.assertions import pytest_assert as pyassert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until

FIPS_CHECK_SERIVCES = ['restapi', 'hostcfgd', 'procdockerstatsd']
_FIPS_YANG_SUPPORTED = None

logger = logging.getLogger(__name__)

def check_fips_yang_installed(duthost):
    global _FIPS_YANG_SUPPORTED
    if _FIPS_YANG_SUPPORTED != None:
        return _FIPS_YANG_SUPPORTED
    dut_command = "sudo ls /usr/local/yang-models/"
    output = duthost.shell(dut_command)['stdout']
    _FIPS_YANG_SUPPORTED = "sonic-fips" in output
    return _FIPS_YANG_SUPPORTED

def set_fips_by_patch(duthost, is_enable=False, is_enforce=False):
    dut_command = "show run"
    output = duthost.shell(dut_command)['stdout']
    if "FIPS" in output:
        patch = [
            {
                "op": "replace",
                "path": "/FIPS/global/enforce",
                "value": str(is_enable)
            },
            {
                "op": "replace",
                "path": "/FIPS/global/enable",
                "value": str(is_enforce)
            }
        ]
    else:
        patch = [
            {
                "op": "add",
                "path": "/FIPS",
                "value": {
                    "global": {
                        "enable": str(is_enable),
                        "enforce": str(is_enforce)
                    }
                }
            }
        ]
    dut_command = "echo '{}' > fips.patch".format(json.dumps(patch))
    duthost.shell(dut_command)

    dut_command = "sudo config apply-patch fips.patch"
    output = duthost.shell(dut_command)['stdout']
    pyassert("Patch applied successfully" in output)

def reboot_and_wait_for_fips(duthost, localhost, is_enforce=False, retry=1):
    '''
    Reboot the DUT and wait until the require service started for FIPS test
    '''

    def check_ready():
        output = duthost.shell('systemctl list-units --type service --output json --no-pager')['stdout']
        for service in json.loads(output):
            if service['unit'].replace('.service', '') in FIPS_CHECK_SERIVCES:
                if service['sub'] != 'running':
                    return False
        return True

    def reboot_helper(kwargs):
        #duthost.shell('sudo sonic-installer get-fips && sudo /sbin/reboot -f')
        duthost.shell('sudo sonic-installer get-fips && sudo shutdown -r now')

    if check_fips_yang_installed(duthost):
        set_fips_by_patch(duthost, is_enforce, is_enforce)
    option = "--enable-fips" if is_enforce else "--disable-fips"
    dut_command = "sudo sonic-installer set-fips {}".format(option)
    duthost.shell(dut_command)
    option = "1" if is_enforce else "0"
    dut_command = "[ -d /etc/fips ] && echo {} > /etc/fips/fips_enable".format(option)
    duthost.shell(dut_command)

    for i in range(retry):
        reboot(duthost, localhost, reboot_type = REBOOT_TYPE_POWEROFF, wait=10, plt_reboot_ctrl_overwrite=False, reboot_helper=reboot_helper)
        assert wait_until(300, 20, 0, check_ready), "Not all critical services are fully started"
        dut_command = "sudo openssl engine -vv"
        output = duthost.shell(dut_command)['stdout']
        enforced = 'symcrypt' in output
        if is_enforce == enforced:
            logger.info("Set FIPS state successfully, retry:{}".format(i+1))
            return

    pyassert(is_enforce == enforced, 'Failed to set the FIPS state')

def reboot_fips(duthost, localhost, is_enforce=False, retry=2):
    set_fips_by_patch(duthost, is_enforce, is_enforce)
    option = "--enable-fips" if is_enforce else "--disable-fips"
    dut_command = "sudo sonic-installer set-fips {} && echo {} > /etc/fips/fips_enable".format(option)
    duthost.shell(dut_command)
    option = "1" if is_enforce else "0"
    dut_command = "[ -d /etc/fips ] && echo {} > /etc/fips/fips_enable".format(option)
    duthost.shell(dut_command)

    for i in range(retry):
        reboot_fips(duthost, localhost)
        dut_command = "sudo openssl engine -vv"
        output = duthost.shell(dut_command)['stdout']
        enforced = 'symcrypt' in output
        if is_enforce == enforced:
            logger.info("Set FIPS state successfully, retry:{}".format(i+1))
            return
    pyassert(is_enforce == enforced, 'Failed to set the FIPS state')
