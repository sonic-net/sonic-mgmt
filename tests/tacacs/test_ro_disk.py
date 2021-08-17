import pytest
import crypt
import json
import logging
import time
from pkg_resources import parse_version

from tests.common.utilities import wait_until
from tests.common.reboot import reboot
from .test_ro_user import ssh_remote_run

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images or older. Skipping the test")


def simulate_ro(duthost):
    duthost.shell("echo u > /proc/sysrq-trigger")
    logger.info("Disk turned to RO state; pause for 30s before attempting to ssh")
    time.sleep(30)


def chk_ssh_remote_run(localhost, remote_ip, username, password, cmd):
    rc = -1
    try:
        res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
        rc = res["rc"]
    finally:
        logger.debug("ssh rc={}".format(rc))
    return rc == 0


def test_ro_disk(localhost, duthosts, enum_rand_one_per_hwsku_hostname, creds_all_duts, test_tacacs):
    """test tacacs rw user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)

    dutip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    ro_user = creds_all_duts[duthost]['tacacs_ro_user']
    ro_pass = creds_all_duts[duthost]['tacacs_ro_user_passwd']

    rw_user = creds_all_duts[duthost]['tacacs_rw_user']
    rw_pass = creds_all_duts[duthost]['tacacs_rw_user_passwd']

    res = duthost.shell("ls -l /home/{}".format(ro_user), module_ignore_errors=True)
    assert res["rc"] != 0, "ro user pre-exists"

    try:
        # Ensure rw user can get in, as we need this to be able to reboot
        ret = chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "ls")
        
        assert ret, "Failed to ssh as rw user"

        # Set disk in RO state
        simulate_ro(duthost)

        logger.debug("user={}".format(ro_user))

        assert wait_until(600, 20, chk_ssh_remote_run, localhost, dutip,
                ro_user, ro_pass, "cat /etc/passwd"), "Failed to ssh as ro user"

    finally:
        logger.debug("START: reboot {} to restore disk RW state".
                format(enum_rand_one_per_hwsku_hostname))
        chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "sudo /sbin/reboot")
        time.sleep(120)
        logger.debug("  END: reboot {} to restore disk RW state".
                format(enum_rand_one_per_hwsku_hostname))

       
