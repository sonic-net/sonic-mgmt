import threading
import time
import logging
from multiprocessing.pool import ThreadPool, TimeoutError
from errors import RunAnsibleModuleFail

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
        "cause": r"'reboot'|Non-Hardware \(reboot",
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
        "command": "python -c \"import sonic_platform.platform as P; P.Platform().get_chassis().get_watchdog().arm(5); exit()\"",
        "timeout": 300,
        "wait": 120,
        "cause": "Watchdog",
        "test_reboot_cause_only": True
    }
}

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
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']

    try:
        reboot_ctrl    = reboot_ctrl_dict[reboot_type]
        reboot_command = reboot_ctrl['command'] if reboot_type != REBOOT_TYPE_POWEROFF else None
        if timeout == 0:
            timeout = reboot_ctrl['timeout']
        if wait == 0:
            wait = reboot_ctrl['wait']
    except KeyError:
        raise ValueError('invalid reboot type: "{}"'.format(reboot_type))

    def execute_reboot_command():
        logger.info('rebooting with command "{}"'.format(reboot_command))
        return duthost.command(reboot_command)

    def execute_reboot_helper():
        logger.info('rebooting with helper "{}"'.format(reboot_helper))
        return reboot_helper(reboot_kwargs)

    dut_datetime = duthost.get_now_time()
    DUT_ACTIVE.clear()

    if reboot_type != REBOOT_TYPE_POWEROFF:
        reboot_res = pool.apply_async(execute_reboot_command)
    else:
        assert reboot_helper is not None, "A reboot function must be provided for power off reboot"
        reboot_res = pool.apply_async(execute_reboot_helper)

    logger.info('waiting for ssh to drop')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)

    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        if reboot_res.ready():
            logger.error('reboot result: {}'.format(reboot_res.get()))
        raise Exception('DUT did not shutdown')

    if not wait_for_ssh:
        return

    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information

    logger.info('waiting for ssh to startup')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout,
                             module_ignore_errors=True)
    if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
        raise Exception('DUT did not startup')

    logger.info('ssh has started up')

    logger.info('waiting for switch to initialize')

    if reboot_type == 'warm':
        logger.info('waiting for warmboot-finalizer service to become activating')
        finalizer_state = get_warmboot_finalizer_state(duthost)
        while finalizer_state != 'activating':
            dut_datetime_after_ssh = duthost.get_now_time()
            time_passed = float(dut_datetime_after_ssh.strftime("%s")) - float(dut_datetime.strftime("%s"))
            if time_passed > wait:
                raise Exception('warmboot-finalizer never reached state "activating"')
            time.sleep(1)
            finalizer_state = get_warmboot_finalizer_state(duthost)
        logger.info('waiting for warmboot-finalizer service to finish')
        finalizer_state = get_warmboot_finalizer_state(duthost)
        logger.info('warmboot finalizer service state {}'.format(finalizer_state))
        count = 0
        while finalizer_state == 'activating':
            finalizer_state = get_warmboot_finalizer_state(duthost)
            logger.info('warmboot finalizer service state {}'.format(finalizer_state))
            time.sleep(delay)
            if count * delay > timeout:
                raise Exception('warmboot-finalizer.service did not finish')
            count += 1
        logger.info('warmboot-finalizer service finished')
    else:
        time.sleep(wait)

    DUT_ACTIVE.set()
    logger.info('{} reboot finished'.format(reboot_type))
    pool.terminate()
    dut_uptime = duthost.get_up_time()
    logger.info('DUT up since {}'.format(dut_uptime))
    assert float(dut_uptime.strftime("%s")) - float(dut_datetime.strftime("%s")) > 10, "Device did not reboot"


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
