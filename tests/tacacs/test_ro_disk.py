import pytest
import logging
import os
import time

from ansible.errors import AnsibleConnectionFailure
from tests.common.devices.base import RunAnsibleModuleFail
from tests.common.utilities import wait_until
from tests.common.utilities import skip_release
from tests.common.utilities import wait
from tests.common.utilities import pdu_reboot
from tests.common.reboot import reboot
from .test_ro_user import ssh_remote_run
from .utils import setup_tacacs_client, change_and_wait_aaa_config_update
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

MOUNT_DIR = "/run/mount"
LOG_DIR = os.path.join(MOUNT_DIR, "log")
DATA_DIR = "logs/tacacs"


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

    # Wait for disk remount finish
    # TODO: check remount finish by rsyslog
    time.sleep(10)


def chk_ssh_remote_run(localhost, remote_ip, username, password, cmd):
    rc = -1
    try:
        res = ssh_remote_run(localhost, remote_ip, username, password, cmd)
        rc = res["rc"]
    finally:
        logger.debug("ssh rc={} user={} cmd={}".format(rc, username, cmd))
    return rc == 0


def do_pdu_reboot(duthost, localhost, duthosts, pdu_controller):
    if not pdu_reboot(pdu_controller):
        logger.error("Failed to do PDU reboot for {}".format(duthost.hostname))
        return
    return post_reboot_healthcheck(duthost, localhost, duthosts, 20)


def do_reboot(duthost, localhost, duthosts):
    # occasionally reboot command fails with some kernel error messages
    # Hence retry if needed.
    #
    wait_time = 20
    retries = 3
    rebooted = False

    for i in range(retries):
        #
        try:
            # Reboot DUT using reboot function instead of using ssh_remote_run.
            # ssh_remote_run gets blocked due to console messages from reboot on DUT
            # Do not wait for ssh as next step checks if ssh is stopped to ensure DUT is
            # is rebooting.
            reboot(duthost, localhost, wait_for_ssh=False)
            localhost.wait_for(host=duthost.mgmt_ip, port=22, state="stopped", delay=5, timeout=60)
            rebooted = True
            break
        except AnsibleConnectionFailure as e:
            logger.error("DUT not reachable, exception: {} attempt:{}/{}".
                         format(repr(e), i, retries))
        except RunAnsibleModuleFail as e:
            logger.error("DUT did not go down, exception: {} attempt:{}/{}".
                         format(repr(e), i, retries))

        wait(wait_time, msg="Wait {} seconds before retry.".format(wait_time))

    if not rebooted:
        logger.error("Failed to reboot DUT after {} retries".format(retries))
        return False

    return post_reboot_healthcheck(duthost, localhost, duthosts, wait_time)


def post_reboot_healthcheck(duthost, localhost, duthosts, wait_time):
    localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=300)
    wait(wait_time, msg="Wait {} seconds for system to be stable.".format(wait_time))
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        return False
    # If supervisor node is rebooted in chassis, linecards also will reboot.
    # Check if all linecards are back up.
    if duthost.is_supervisor_node():
        for host in duthosts:
            if host != duthost:
                logger.info("checking if {} critical services are up".format(host.hostname))
                wait_critical_processes(host)
                if not wait_until(300, 20, 0, check_interface_status_of_up_ports, host):
                    logger.error("Not all ports that are admin up on are operationally up")
                    return False
    return True


def do_setup_tacacs(ptfhost, duthost, tacacs_creds):
    logger.info('Upon reboot: setup tacacs_creds')
    tacacs_server_ip = ptfhost.mgmt_ip
    tacacs_server_passkey = tacacs_creds[duthost.hostname]['tacacs_passkey']
    setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, tacacs_server_passkey, ptfhost)

    ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
    if 'ansible_hostv6' in ptfhost_vars:
        tacacs_server_ip = ptfhost_vars['ansible_hostv6']
        setup_tacacs_client(duthost, tacacs_creds, tacacs_server_ip, tacacs_server_passkey, ptfhost)
    logger.info('Upon reboot: complete: setup tacacs_creds')


def do_check_clean_state(duthost):
    for i in ["upper", "work", "log"]:
        res = duthost.shell("ls -l {}".format(os.path.join(MOUNT_DIR, i)), module_ignore_errors=True)
        if res["rc"] == 0:
            # Log current state in-depth
            duthost.shell("find {} -ls".format(MOUNT_DIR), module_ignore_errors=True)
            return False
    return True


def fetch_into_file(localhost, remote_ip, rwuser, rwpass, src_file, dst_file):
    chk_ssh_remote_run(localhost, remote_ip, rwuser, rwpass, "sudo chmod a+r {}".format(src_file))
    scp_cmd = "scp -o StrictHostKeyChecking=no {}@{}:{} {}".format(rwuser, remote_ip, src_file, dst_file)
    cmd = "sshpass -p {} {}".format(rwpass, scp_cmd)
    ret = os.system(cmd)
    logger.info("ret={} cmd={}".format(ret, scp_cmd))


def log_rotate(duthost):
    try:
        duthost.shell("logrotate --force /etc/logrotate.d/rsyslog")
    except RunAnsibleModuleFail as e:
        if "logrotate does not support parallel execution on the same set of logfiles" in e.message:
            # command will failed when log already in rotating
            logger.warning("logrotate command failed: {}".format(e))
        else:
            raise e


def test_ro_disk(localhost, ptfhost, duthosts, enum_rand_one_per_hwsku_hostname,
                 tacacs_creds, check_tacacs, pdu_controller):
    """test tacacs rw user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201911", "201811"])

    dutip = duthost.mgmt_ip

    ro_user = tacacs_creds['tacacs_ro_user']
    ro_pass = tacacs_creds['tacacs_ro_user_passwd']

    rw_user = tacacs_creds['tacacs_rw_user']
    rw_pass = tacacs_creds['tacacs_rw_user_passwd']

    if not do_check_clean_state(duthost):
        # System has some partial state left behind from last run.
        # reboot to clear it
        #
        logger.info("PRETEST: reboot {} to restore system state".
                    format(enum_rand_one_per_hwsku_hostname))
        assert do_reboot(duthost, localhost, duthosts), "Failed to reboot"
        assert do_check_clean_state(duthost), "state not good even after reboot"
        do_setup_tacacs(ptfhost, duthost, tacacs_creds)

    # just check it out that ro user could indeed login
    ret = chk_ssh_remote_run(localhost, dutip, ro_user, ro_pass, "ls")
    assert ret, "Failed pre-test ssh login as ro user"

    logger.debug("Delete ro user to simulate new login in RO state.")
    duthost.shell("sudo deluser --remove-home {}".format(ro_user))
    logger.info("del user {} done".format(ro_user))

    res = duthost.shell("ls -l /home/{}".format(ro_user), module_ignore_errors=True)
    assert res["rc"] != 0, "Failed to remove ro user dir"

    # Ensure rw user can get in, as we need this to be able to reboot
    ret = chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "ls")
    assert ret, "Failed to ssh as rw user"

    try:
        # Redirect logs to tmpfs
        #
        duthost.shell("sudo mkdir {}".format(LOG_DIR))

        conf_path = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "000-ro_disk.conf")
        duthost.copy(src=conf_path, dest="/etc/rsyslog.d/000-ro_disk.conf")

        # To get file in decent size. Force a rotate
        log_rotate(duthost)

        res = duthost.shell("systemctl restart rsyslog")
        assert res["rc"] == 0, "failed to restart rsyslog"

        # Pause 2 seconds to ensure the new .conf is read in by rsyslogd
        time.sleep(2)

        # Remove file, so the reboot at the end of test will revert this logs redirect.
        duthost.shell("rm /etc/rsyslog.d/000-ro_disk.conf")

        # Enable AAA failthrough authentication so that reboot function can be used
        # to reboot DUT
        change_and_wait_aaa_config_update(duthost, "config aaa authentication failthrough enable")

        # Set disk in RO state
        simulate_ro(duthost)

        logger.debug("user={}".format(ro_user))

        # Wait for 15 minutes
        # Reason:
        #   Monit does not start upon boot for 5 minutes.
        #   Note: Monit invokes disk check every 5 cycles/minutes
        #   We need to wait solid +10mins before concluding.
        #
        res = wait_until(900, 20, 0, chk_ssh_remote_run, localhost, dutip,
                         ro_user, ro_pass, "cat /etc/passwd")
        logger.info("res={}".format(res))

        chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "sudo find {} -ls".format(MOUNT_DIR))
        chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "systemctl status monit")

        chk_ssh_remote_run(localhost, dutip, rw_user, rw_pass, "sudo find /home -ls")

        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR)

        # Fetch files of interest
        #
        for f in ["/etc/passwd", os.path.join(LOG_DIR, "auth.log"),
                  os.path.join(LOG_DIR, "syslog")]:
            fetch_into_file(localhost, dutip, rw_user, rw_pass, f,
                            os.path.join(DATA_DIR, os.path.basename(f)))
        assert res, "Failed to ssh as ro user"

    finally:
        logger.debug("START: reboot {} to restore disk RW state".
                     format(enum_rand_one_per_hwsku_hostname))
        if not do_reboot(duthost, localhost, duthosts):
            logger.warning("Failed to reboot {}, try PDU reboot to restore disk RW state".
                           format(enum_rand_one_per_hwsku_hostname))
            do_pdu_reboot(duthost, localhost, duthosts, pdu_controller)
        logger.debug("  END: reboot {} to restore disk RW state".
                     format(enum_rand_one_per_hwsku_hostname))

        # log rotate during ro disk may cause syslog file contains garbled content
        # garbled content will break loganalyzer, rotate again to cleanup syslog file.
        log_rotate(duthost)
