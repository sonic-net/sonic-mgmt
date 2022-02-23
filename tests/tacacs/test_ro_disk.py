import pytest
import logging

from tests.common.devices.base import RunAnsibleModuleFail
from tests.common.utilities import wait_until
from tests.common.utilities import skip_release
from tests.common.utilities import wait
from .test_ro_user import ssh_remote_run
from .utils import setup_tacacs_client

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def check_disk_ro(duthost):
    try:
        result = duthost.shell("touch ~/disk_check.tst", module_ignore_errors=True)
        return result["rc"] != 0
    finally:
        logger.info("touch file failed as expected")
        return True


def simulate_ro(duthost):
    duthost.shell("echo u > /proc/sysrq-trigger")
    logger.info("Disk turned to RO state; pause for 30s before attempting to ssh")
    assert wait_until(30, 2, 0, check_disk_ro, duthost), "disk not in ro state"


def chk_ssh_remote_run(localhost, remote_ip, username, password, cmd):
    rc = -1
    try:
        res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
        rc = res["rc"]
    finally:
        logger.debug("ssh rc={} user={} cmd={}".format(rc, username, cmd))
    return rc == 0


def do_reboot(duthost, localhost, dutip, rw_user, rw_pass):
    # occasionally reboot command fails with some kernel error messages
    # Hence retry if needed.
    #
    wait_time = 20
    retries = 3
    for i in range(retries):
        # Regular reboot command would not work, as it would try to
        # collect show tech, which will fail in RO state.
        #
        chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "sudo /sbin/reboot")
        try:
            localhost.wait_for(host=duthost.mgmt_ip, port=22, state="stopped", delay=5, timeout=60)
            break
        except RunAnsibleModuleFail as e:
            logger.error("DUT did not go down, exception: {} attempt:{}/{}".
                    format(repr(e), i, retries))

    assert i<3, "Failed to reboot"
    localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=300)
    wait(wait_time, msg="Wait {} seconds for system to be stable.".format(wait_time))
    assert wait_until(300, 20, 0, duthost.critical_services_fully_started), \
            "All critical services should fully started!"


def do_setup_tacacs(ptfhost, duthost, tacacs_creds):
    logger.info('Upon reboot: setup tacacs_creds')
    tacacs_server_ip = ptfhost.mgmt_ip
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip)

    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' in ptfhost_vars:
        tacacs_server_ip = ptfhost_vars['ansible_hostv6']
        setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip)
    logger.info('Upon reboot: complete: setup tacacs_creds')


def test_ro_disk(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname,
        tacacs_creds, check_tacacs):
    """test tacacs rw user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201911", "201811"])

    dutip = duthost.mgmt_ip

    ro_user = tacacs_creds['tacacs_ro_user']
    ro_pass = tacacs_creds['tacacs_ro_user_passwd']

    rw_user = tacacs_creds['tacacs_rw_user']
    rw_pass = tacacs_creds['tacacs_rw_user_passwd']

    res = duthost.shell("ls -l /run/mount/*", module_ignore_errors=True)
    if res["rc"] == 0:
        # System has some partial state left behind from last run.
        # reboot to clear it
        #
        logger.info("PRETEST: reboot {} to restore system state".
                format(enum_rand_one_per_hwsku_hostname))
        do_reboot(duthost, localhost, dutip, rw_user, rw_pass)

        do_setup_tacacs(ptfhost, duthost, tacacs_creds)

    res = duthost.shell("ls -l /home/{}".format(ro_user), module_ignore_errors=True)
    if  res["rc"] == 0:
        logger.debug("ro user pre-exists; deleting")
        try:
            duthost.shell("sudo deluser --remove-home {}".format(ro_user),
                    module_ignore_errors=True)
        finally:
            # If any failure, it implies user not valid, which is good enough.
            logger.info("del user {} done".format(ro_user))

    try:
        # Ensure rw user can get in, as we need this to be able to reboot
        ret = chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "ls")

        assert ret, "Failed to ssh as rw user"

        # Set disk in RO state
        simulate_ro(duthost)

        logger.debug("user={}".format(ro_user))

        assert wait_until(600, 20, 0, chk_ssh_remote_run, localhost, dutip,
                ro_user, ro_pass, "cat /etc/passwd"), "Failed to ssh as ro user"

    finally:
        logger.debug("START: reboot {} to restore disk RW state".
                format(enum_rand_one_per_hwsku_hostname))
        do_reboot(duthost, localhost, dutip, rw_user, rw_pass)
        assert wait_until(600, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started"
        logger.debug("  END: reboot {} to restore disk RW state".
                format(enum_rand_one_per_hwsku_hostname))
