import threading
import time
import re
import logging
from multiprocessing.pool import ThreadPool, TimeoutError
from errors import RunAnsibleModuleFail
from collections import deque

logger = logging.getLogger(__name__)

# SSH defines
SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

REBOOT_TYPE_WARM = "warm"
REBOOT_TYPE_COLD = "cold"
REBOOT_TYPE_SOFT = "soft"
REBOOT_TYPE_FAST = "fast"
REBOOT_TYPE_POWEROFF = "power off"
REBOOT_TYPE_WATCHDOG = "watchdog"
REBOOT_TYPE_UNKNOWN  = "Unknown"

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
        "cause": "warm-reboot",
        "test_reboot_cause_only": False
    },
    REBOOT_TYPE_WATCHDOG: {
        "command": "watchdogutil arm -s 5",
        "timeout": 300,
        "wait": 120,
        "cause": "Watchdog",
        "test_reboot_cause_only": True
    }
}

MAX_NUM_REBOOT_CAUSE_HISTORY = 10
REBOOT_TYPE_HISTOYR_QUEUE = deque([], MAX_NUM_REBOOT_CAUSE_HISTORY)
REBOOT_CAUSE_HISTORY_TITLE = ["name", "cause", "time", "user", "comment"]


def get_warmboot_finalizer_state(duthost):
    try:
        res = duthost.command('systemctl is-active warmboot-finalizer.service',module_ignore_errors=True)
        finalizer_state = res['stdout'].strip() if 'stdout' in res else ""
    except RunAnsibleModuleFail as err:
        finalizer_state = err.results
    return finalizer_state

def reboot(duthost, localhost, reboot_type='cold', delay=10, \
    timeout=0, wait=0, wait_for_ssh=True, reboot_helper=None, reboot_kwargs=None):
    """
    reboots DUT
    :param duthost: DUT host object
    :param localhost:  local host object
    :param reboot_type: reboot type (cold, fast, warm)
    :param delay: delay between ssh availability checks
    :param timeout: timeout for waiting ssh port state change
    :param wait: time to wait for DUT to initialize
    :param reboot_helper: helper function to execute the power toggling
    :param reboot_kwargs: arguments to pass to the reboot_helper
    :return:
    """

    # pool for executing tasks asynchronously
    pool = ThreadPool()
    dut_ip = duthost.mgmt_ip
    hostname = duthost.hostname
    try:
        reboot_ctrl    = reboot_ctrl_dict[reboot_type]
        reboot_command = reboot_ctrl['command'] if reboot_type != REBOOT_TYPE_POWEROFF else None
        if timeout == 0:
            timeout = reboot_ctrl['timeout']
        if wait == 0:
            wait = reboot_ctrl['wait']
    except KeyError:
        raise ValueError('invalid reboot type: "{} for {}"'.format(reboot_type, hostname))

    def execute_reboot_command():
        logger.info('rebooting {} with command "{}"'.format(hostname, reboot_command))
        return duthost.command(reboot_command)

    def execute_reboot_helper():
        logger.info('rebooting {} with helper "{}"'.format(hostname, reboot_helper))
        return reboot_helper(reboot_kwargs)

    dut_datetime = duthost.get_now_time()
    DUT_ACTIVE.clear()

    if reboot_type != REBOOT_TYPE_POWEROFF:
        reboot_res = pool.apply_async(execute_reboot_command)
    else:
        assert reboot_helper is not None, "A reboot function must be provided for power off reboot"
        reboot_res = pool.apply_async(execute_reboot_helper)

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

    if not wait_for_ssh:
        return

    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information

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

    logger.info('waiting for switch {} to initialize'.format(hostname))

    if reboot_type == 'warm':
        logger.info('waiting for warmboot-finalizer service to become activating on {}'.format(hostname))
        finalizer_state = get_warmboot_finalizer_state(duthost)
        while finalizer_state != 'activating':
            dut_datetime_after_ssh = duthost.get_now_time()
            time_passed = float(dut_datetime_after_ssh.strftime("%s")) - float(dut_datetime.strftime("%s"))
            if time_passed > wait:
                raise Exception('warmboot-finalizer never reached state "activating" on {}'.format(hostname))
            time.sleep(1)
            finalizer_state = get_warmboot_finalizer_state(duthost)
        logger.info('waiting for warmboot-finalizer service to finish on {}'.format(hostname))
        finalizer_state = get_warmboot_finalizer_state(duthost)
        logger.info('warmboot finalizer service state {} on {}'.format(finalizer_state, hostname))
        count = 0
        while finalizer_state == 'activating':
            finalizer_state = get_warmboot_finalizer_state(duthost)
            logger.info('warmboot finalizer service state {} on {}'.format(finalizer_state, hostname))
            time.sleep(delay)
            if count * delay > timeout:
                raise Exception('warmboot-finalizer.service did not finish on {}'.format(hostname))
            count += 1
        logger.info('warmboot-finalizer service finished on {}'.format(hostname))
    else:
        time.sleep(wait)

    DUT_ACTIVE.set()
    logger.info('{} reboot finished on {}'.format(reboot_type, hostname))
    pool.terminate()
    dut_uptime = duthost.get_up_time()
    logger.info('DUT {} up since {}'.format(hostname, dut_uptime))
    assert float(dut_uptime.strftime("%s")) > float(dut_datetime.strftime("%s")), "Device {} did not reboot".format(hostname)


def get_reboot_cause(dut):
    """
    @summary: get the reboot cause on DUT.
    @param dut: The AnsibleHost object of DUT.
    """
    logging.info('Getting reboot cause from dut {}'.format(dut.hostname))
    output = dut.shell('show reboot-cause')
    cause  = output['stdout']

    for type, ctrl in reboot_ctrl_dict.items():
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
    logging.debug("dut {} last reboot-cause {}".format(dut.hostname, reboot_cause_got))
    return reboot_cause_got == reboot_cause_expected


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
    logging.debug("dut {} reboot-cause history {}. reboot type history queue is {}".format(
        dut.hostname, reboot_cause_history_got, reboot_type_history_queue))

    logging.info("Verify reboot-cause history title")
    if reboot_cause_history_got:
        if not set(REBOOT_CAUSE_HISTORY_TITLE) == set(reboot_cause_history_got[0].keys()):
            logging.error("Expected reboot-cause history title:{} not match actual reboot-cause history title:{}".format(
                REBOOT_CAUSE_HISTORY_TITLE, reboot_cause_history_got[0].keys()))
            return False

    logging.info("Verify reboot-cause output are sorted in reverse chronological order" )
    reboot_type_history_len = len(reboot_type_history_queue)
    if reboot_type_history_len <= len(reboot_cause_history_got):
        for index, reboot_type in enumerate(reboot_type_history_queue):
            if not re.search(reboot_ctrl_dict[reboot_type]["cause"], reboot_cause_history_got[reboot_type_history_len-index-1]["cause"]):
                logging.error("The {} reboot-cause not match. expected_reboot type={}, actual_reboot_cause={}".format(
                    index, reboot_ctrl_dict[reboot_type]["cause"], reboot_cause_history_got[reboot_type_history_len-index]["cause"]))
                return False
        return True
    logging.error("The number of expected reboot-cause:{} is more than that of actual reboot-cuase:{}".format(
        reboot_type_history_len, len(reboot_type_history_queue)))
    return False
