import threading
import time
import re
import logging
import sys
import os
from multiprocessing.pool import ThreadPool
from collections import deque

from .helpers.assertions import pytest_assert
from .platform.interface_utils import check_interface_status_of_up_ports
from .platform.processes_utils import wait_critical_processes
from .utilities import wait_until, get_plt_reboot_ctrl
from tests.common.helpers.dut_utils import ignore_t2_syslog_msgs

logger = logging.getLogger(__name__)

# Create the waiting power on event
power_on_event = threading.Event()

# SSH defines
SONIC_SSH_PORT = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

REBOOT_TYPE_WARM = "warm"
REBOOT_TYPE_SAI_WARM = "sai-warm"
REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_SOFT = "soft"
REBOOT_TYPE_FAST = "fast"
REBOOT_TYPE_POWEROFF = "power off"
REBOOT_TYPE_WATCHDOG = "watchdog"
REBOOT_TYPE_UNKNOWN = "Unknown"
REBOOT_TYPE_THERMAL_OVERLOAD = "Thermal Overload"
REBOOT_TYPE_BIOS = "bios"
REBOOT_TYPE_ASIC = "asic"
REBOOT_TYPE_KERNEL_PANIC = "Kernel Panic"
REBOOT_TYPE_SUPERVISOR = "Reboot from Supervisor"
REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS = "Heartbeat with the Supervisor card lost"

# Event to signal DUT activeness
DUT_ACTIVE = threading.Event()
DUT_ACTIVE.set()

'''
    command                : command to reboot the DUT
    timeout                : timeout waiting for DUT to come back after reboot
    wait                   : time wait for switch the stablize
    cause                  : search string to determine reboot cause
    test_reboot_cause_only : indicate if the purpose of test is for reboot cause only
'''
reboot_ctrl_dict = {
    REBOOT_TYPE_POWEROFF: {
        "timeout": 300,
        "wait": 120,
        "cause": "Power Loss",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_COLD: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # We are searching two types of reboot cause.
        # This change relates to changes of PR #6130 in sonic-buildimage repository
        "cause": r"'reboot'|Non-Hardware \(reboot|^reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_SOFT: {
        "command": "soft-reboot",
        "timeout": 300,
        "wait": 120,
        "cause": "soft-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_FAST: {
        "command": "fast-reboot",
        "timeout": 180,
        "wait": 120,
        "cause": "fast-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_WARM: {
        "command": "warm-reboot",
        "timeout": 300,
        "wait": 90,
        "warmboot_finalizer_timeout": 180,
        "cause": "warm-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_WATCHDOG: {
        "command": "watchdogutil arm -s 5",
        "timeout": 300,
        "wait": 120,
        "cause": "Watchdog",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_SAI_WARM: {
        "command": "/usr/bin/sai_warmboot.sh",
        "timeout": 300,
        "wait": 90,
        "warmboot_finalizer_timeout": 30,
        "cause": "warm-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_BIOS: {
        "timeout": 300,
        "wait": 120,
        "cause": "BIOS",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_ASIC: {
        "timeout": 300,
        "wait": 120,
        "cause": "ASIC",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_KERNEL_PANIC: {
        "command": 'nohup bash -c "sleep 5 && echo c > /proc/sysrq-trigger" &',
        "timeout": 300,
        "wait": 120,
        "cause": "Kernel Panic",
        "test_reboot_cause_only": True
    },
    REBOOT_TYPE_SUPERVISOR: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # When linecards are rebooted due to supervisor cold reboot
        "cause": "reboot from Supervisor",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_SUPERVISOR_HEARTBEAT_LOSS: {
        "command": "reboot",
        "timeout": 300,
        "wait": 120,
        # When linecards are rebooted due to supervisor crash/abnormal reboot
        "cause": "Heartbeat",
        "test_reboot_cause_only": False
    }
}

MAX_NUM_REBOOT_CAUSE_HISTORY = 10
REBOOT_TYPE_HISTOYR_QUEUE = deque([], MAX_NUM_REBOOT_CAUSE_HISTORY)
REBOOT_CAUSE_HISTORY_TITLE = ["name", "cause", "time", "user", "comment"]

# Retry logic config
MAX_RETRIES = 3
RETRY_BACKOFF_TIME = 15


def check_warmboot_finalizer_inactive(duthost):
    """
    Check if warmboot finalizer service is exited
    """
    stdout = duthost.command('systemctl is-active warmboot-finalizer.service', module_ignore_errors=True)['stdout']
    return 'inactive' == stdout.strip()


def wait_for_shutdown(duthost, localhost, delay, timeout, reboot_res):
    hostname = duthost.hostname
    dut_ip = duthost.mgmt_ip
    logger.info('waiting for ssh to drop on {}'.format(hostname))
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)

    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        if reboot_res.ready():
            logger.error('reboot result: {} on {}'.format(reboot_res.get(), hostname))
        raise Exception('DUT {} did not shutdown'.format(hostname))


def wait_for_startup(duthost, localhost, delay, timeout):
    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information
    hostname = duthost.hostname
    dut_ip = duthost.mgmt_ip
    logger.info('waiting for ssh to startup on {}'.format(hostname))
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)
    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        raise Exception('DUT {} did not startup'.format(hostname))

    logger.info('ssh has started up on {}'.format(hostname))


def perform_reboot(duthost, pool, reboot_command, reboot_helper=None, reboot_kwargs=None, reboot_type='cold'):
    # pool for executing tasks asynchronously
    hostname = duthost.hostname

    def execute_reboot_command():
        logger.info('rebooting {} with command "{}"'.format(hostname, reboot_command))
        return duthost.command(reboot_command)

    def execute_reboot_helper():
        logger.info('rebooting {} with helper "{}"'.format(hostname, reboot_helper))
        return reboot_helper(reboot_kwargs, power_on_event)

    dut_datetime = duthost.get_now_time(utc_timezone=True)
    DUT_ACTIVE.clear()

    # Extend ignore fabric port msgs for T2 chassis with DNX chipset on Linecards
    ignore_t2_syslog_msgs(duthost)

    if reboot_type != REBOOT_TYPE_POWEROFF:
        reboot_res = pool.apply_async(execute_reboot_command)
    else:
        assert reboot_helper is not None, "A reboot function must be provided for power off/on reboot"
        reboot_res = pool.apply_async(execute_reboot_helper)
    return [reboot_res, dut_datetime]


def reboot(duthost, localhost, reboot_type='cold', delay=10,
           timeout=0, wait=0, wait_for_ssh=True, wait_warmboot_finalizer=False, warmboot_finalizer_timeout=0,
           reboot_helper=None, reboot_kwargs=None, plt_reboot_ctrl_overwrite=True,
           safe_reboot=False, check_intf_up_ports=False):
    """
    reboots DUT
    :param duthost: DUT host object
    :param localhost:  local host object
    :param reboot_type: reboot type (cold, fast, warm)
    :param delay: delay between ssh availability checks
    :param timeout: timeout for waiting ssh port state change
    :param wait: time to wait for DUT to initialize
    :param wait_for_ssh: Wait for SSH startup
    :param wait_warmboot_finalizer=True: Wait for WARMBOOT_FINALIZER done
    :param reboot_helper: helper function to execute the power toggling
    :param reboot_kwargs: arguments to pass to the reboot_helper
    :param safe_reboot: arguments to wait DUT ready after reboot
    :param check_intf_up_ports: arguments to check interface after reboot
    :return:
    """
    pool = ThreadPool()
    hostname = duthost.hostname
    try:
        tc_name = os.environ.get('PYTEST_CURRENT_TEST').split(' ')[0]
        plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, tc_name, reboot_type)
        reboot_ctrl = reboot_ctrl_dict[reboot_type]
        reboot_command = reboot_ctrl['command'] if reboot_type != REBOOT_TYPE_POWEROFF else None
        if timeout == 0:
            timeout = reboot_ctrl['timeout']
        if wait == 0:
            wait = reboot_ctrl['wait']
        if plt_reboot_ctrl_overwrite and plt_reboot_ctrl:
            # get 'wait' and 'timeout' from inventory if they are specified, otherwise use current values
            wait = plt_reboot_ctrl.get('wait', wait)
            timeout = plt_reboot_ctrl.get('timeout', timeout)
        if warmboot_finalizer_timeout == 0 and 'warmboot_finalizer_timeout' in reboot_ctrl:
            warmboot_finalizer_timeout = reboot_ctrl['warmboot_finalizer_timeout']
    except KeyError:
        raise ValueError('invalid reboot type: "{} for {}"'.format(reboot_type, hostname))

    # Create a temporary file in tmpfs before reboot
    logger.info('DUT {} create a file /dev/shm/test_reboot before rebooting'.format(hostname))
    duthost.command('sudo touch /dev/shm/test_reboot')

    reboot_res, dut_datetime = perform_reboot(duthost, pool, reboot_command, reboot_helper, reboot_kwargs, reboot_type)

    wait_for_shutdown(duthost, localhost, delay, timeout, reboot_res)

    # Release event to proceed poweron for PDU.
    power_on_event.set()

    # if wait_for_ssh flag is False, do not wait for dut to boot up
    if not wait_for_ssh:
        return
    wait_for_startup(duthost, localhost, delay, timeout)

    logger.info('waiting for switch {} to initialize'.format(hostname))

    if safe_reboot:
        # The wait time passed in might not be guaranteed to cover the actual
        # time it takes for containers to come back up. Therefore, add 5
        # minutes to the maximum wait time. If it's ready sooner, then the
        # function will return sooner.
        pytest_assert(wait_until(wait + 400, 20, 0, duthost.critical_services_fully_started),
                      "All critical services should be fully started!")
        wait_critical_processes(duthost)

        if check_intf_up_ports:
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
    else:
        time.sleep(wait)

    # Wait warmboot-finalizer service
    if reboot_type == REBOOT_TYPE_WARM and wait_warmboot_finalizer:
        logger.info('waiting for warmboot-finalizer service to finish on {}'.format(hostname))
        ret = wait_until(warmboot_finalizer_timeout, 5, 0, check_warmboot_finalizer_inactive, duthost)
        if not ret:
            raise Exception('warmboot-finalizer service timeout on DUT {}'.format(hostname))

    # Verify if the temporary file created in tmpfs is deleted after reboot, to determine a
    # successful reboot
    file_check = duthost.stat(path="/dev/shm/test_reboot")
    if file_check['stat']['exists']:
        raise Exception('DUT {} did not reboot'.format(hostname))

    DUT_ACTIVE.set()
    logger.info('{} reboot finished on {}'.format(reboot_type, hostname))
    pool.terminate()
    dut_uptime = duthost.get_up_time(utc_timezone=True)
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    # some device does not have onchip clock and requires obtaining system time a little later from ntp
    # or SUP to obtain the correct time so if the uptime is less than original device time, it means it
    # is most likely due to this issue which we can wait a little more until the correct time is set in place.
    if float(dut_uptime.strftime("%s")) < float(dut_datetime.strftime("%s")):
        logger.info('DUT {} timestamp went backwards'.format(hostname))
        wait_until(120, 5, 0, positive_uptime, duthost, dut_datetime)

    dut_uptime = duthost.get_up_time()

    assert float(dut_uptime.strftime("%s")) > float(dut_datetime.strftime("%s")), "Device {} did not reboot". \
        format(hostname)


def positive_uptime(duthost, dut_datetime):
    dut_uptime = duthost.get_up_time()
    if float(dut_uptime.strftime("%s")) < float(dut_datetime.strftime("%s")):
        return False

    return True


def get_reboot_cause(dut):
    """
    @summary: get the reboot cause on DUT.
    @param dut: The AnsibleHost object of DUT.
    """
    logger.info('Getting reboot cause from dut {}'.format(dut.hostname))
    output = dut.shell('show reboot-cause')
    cause = output['stdout']

    # For kvm testbed, the expected output of command `show reboot-cause`
    # is such like "User issued 'xxx' command [User: admin, Time: Sun Aug  4 06:43:19 PM UTC 2024]"
    # So, use the above pattern to get real reboot cause
    if dut.facts["asic_type"] == "vs":
        cause = re.search("User issued '(.*)' command", cause).groups()[0]

    for type, ctrl in list(reboot_ctrl_dict.items()):
        if re.search(ctrl['cause'], cause):
            return type

    return REBOOT_TYPE_UNKNOWN


def check_reboot_cause(dut, reboot_cause_expected):
    """
    @summary: Check the reboot cause on DUT. Can be used with wailt_until
    @param dut: The AnsibleHost object of DUT.
    @param reboot_cause_expected: The expected reboot cause.
    """
    reboot_cause_got = get_reboot_cause(dut)
    logger.debug("dut {} last reboot-cause {}".format(dut.hostname, reboot_cause_got))
    return reboot_cause_got == reboot_cause_expected


def sync_reboot_history_queue_with_dut(dut):
    """
    @summary: Sync DUT and internal history queues
    @param dut: The AnsibleHost object of DUT.
    """

    global REBOOT_TYPE_HISTOYR_QUEUE
    global MAX_NUM_REBOOT_CAUSE_HISTORY

    # Initialize local deque for storing DUT reboot cause history
    dut_reboot_history_queue = deque([], MAX_NUM_REBOOT_CAUSE_HISTORY)

    # Skip this function if sonic image is 201811 or 201911
    if "201811" in dut.os_version or "201911" in dut.os_version:
        logger.info("Skip sync reboot-cause history for version before 202012")
        return

    # IF control is here it means the SONiC image version is > 201911
    # Try and get the entire reboot-cause history from DUT

    # Retry logic for increased robustness
    dut_reboot_history_received = False
    for retry_count in range(MAX_RETRIES):
        try:
            # Try and get the current reboot history from DUT
            # If received, set flag and break out of for loop

            dut_reboot_history_queue = dut.show_and_parse("show reboot-cause history")
            dut_reboot_history_received = True
            break
        except Exception:
            e_type, e_value, e_traceback = sys.exc_info()
            logger.info("Exception type: %s" % e_type.__name__)
            logger.info("Exception message: %s" % e_value)
            logger.info("Backing off for %d seconds before retrying", ((retry_count + 1) * RETRY_BACKOFF_TIME))

            time.sleep(((retry_count + 1) * RETRY_BACKOFF_TIME))
            continue

    # If retry logic did not yield reboot cause history from DUT,
    # return without clearing the existing reboot history queue.
    if not dut_reboot_history_received:
        logger.warn("Unable to sync reboot history queue")
        return

    # If the reboot cause history is received from DUT,
    # we sync the two queues. TO that end,
    # Clear the current reboot history queue
    REBOOT_TYPE_HISTOYR_QUEUE.clear()

    # For each item in the DUT reboot queue,
    # iterate through every item in the reboot dict until
    # a "cause" match is found. Then add that key to the
    # reboot history queue REBOOT_TYPE_HISTOYR_QUEUE
    # If no cause is found add 'Unknown' as reboot type.

    # NB: appendleft used because queue received from DUT
    #     is in reverse-chronological order.

    for reboot_type in (dut_reboot_history_queue):
        dict_iter_found = False
        for dict_iter in (reboot_ctrl_dict):
            if re.search(reboot_ctrl_dict[dict_iter]["cause"], reboot_type["cause"]):
                logger.info("Adding {} to REBOOT_TYPE_HISTOYR_QUEUE".format(dict_iter))
                REBOOT_TYPE_HISTOYR_QUEUE.appendleft(dict_iter)
                dict_iter_found = True
                break
        if not dict_iter_found:
            logger.info("Adding {} to REBOOT_TYPE_HISTOYR_QUEUE".format(REBOOT_TYPE_UNKNOWN))
            REBOOT_TYPE_HISTOYR_QUEUE.appendleft(REBOOT_TYPE_UNKNOWN)


def check_reboot_cause_history(dut, reboot_type_history_queue):
    """
    @summary: Check the reboot cause history on DUT. Can be used with wailt_until
    @param dut: The AnsibleHost object of DUT.
    @param reboot_type_history_queue: reboot type queue.
    e.g.
    show reboot-cause  history
    Name                 Cause          Time                             User    Comment
    -------------------  -------------  -------------------------------  ------  ---------
    2021_09_09_14_15_13  Power Loss ()  N/A                              N/A     N/A
    2021_09_09_14_06_17  reboot         Thu 09 Sep 2021 02:05:17 PM UTC  admin   N/A
    2021_09_09_13_59_11  Watchdog ()    N/A                              N/A     N/A
    2021_09_09_13_52_13  Power Loss ()  N/A                              N/A     N/A
    2021_09_09_13_45_18  warm-reboot    Thu 09 Sep 2021 01:44:14 PM UTC  admin   N/A
    2021_09_09_13_37_58  fast-reboot    Thu 09 Sep 2021 01:37:09 PM UTC  admin   N/A
    2021_09_09_13_30_52  soft-reboot    Thu 09 Sep 2021 01:30:24 PM UTC  admin   N/A
    2021_09_09_13_24_17  reboot         Thu 09 Sep 2021 01:23:17 PM UTC  admin   N/A
    """
    reboot_cause_history_got = dut.show_and_parse("show reboot-cause history")
    logger.debug("dut {} reboot-cause history {}. reboot type history queue is {}".format(
        dut.hostname, reboot_cause_history_got, reboot_type_history_queue))

    # For kvm testbed, command `show reboot-cause history` will return None
    # So, return in advance if this check is running on kvm.
    if dut.facts["asic_type"] == "vs":
        return True

    logger.info("Verify reboot-cause history title")
    if reboot_cause_history_got:
        if not set(REBOOT_CAUSE_HISTORY_TITLE) == set(reboot_cause_history_got[0].keys()):
            logger.error("Expected reboot-cause history title:{} not match actual reboot-cause history title:{}".
                         format(REBOOT_CAUSE_HISTORY_TITLE, list(reboot_cause_history_got[0].keys())))
            return False

    logger.info("Verify reboot-cause output are sorted in reverse chronological order")
    reboot_type_history_len = len(reboot_type_history_queue)
    if reboot_type_history_len <= len(reboot_cause_history_got):
        for index, reboot_type in enumerate(reboot_type_history_queue):
            if reboot_type not in reboot_ctrl_dict:
                logger.warn("Reboot type: {} not in dictionary. Skipping history check for this entry.".
                            format(reboot_type))
                continue
            logger.info("index:  %d, reboot cause: %s, reboot cause from DUT: %s" %
                        (index, reboot_ctrl_dict[reboot_type]["cause"],
                         reboot_cause_history_got[reboot_type_history_len - index - 1]["cause"]))
            if not re.search(reboot_ctrl_dict[reboot_type]["cause"],
                             reboot_cause_history_got[reboot_type_history_len - index - 1]["cause"]):
                logger.error("The {} reboot-cause not match. expected_reboot type={}, actual_reboot_cause={}".format(
                    index, reboot_ctrl_dict[reboot_type]["cause"],
                    reboot_cause_history_got[reboot_type_history_len - index]["cause"]))
                return False
        return True
    logger.error("The number of expected reboot-cause:{} is more than that of actual reboot-cuase:{}".format(
        reboot_type_history_len, len(reboot_type_history_queue)))
    return False
