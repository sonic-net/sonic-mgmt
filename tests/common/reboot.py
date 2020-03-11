import time
import logging
from multiprocessing.pool import ThreadPool, TimeoutError
from ansible_host import AnsibleModuleException

logger = logging.getLogger(__name__)

# SSH defines
SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

# map reboot type -> reboot command
reboot_commands =\
{
    'cold': 'reboot',
    'fast': 'fast-reboot',
    'warm': 'warm-reboot',
}


def reboot(duthost, localhost, reboot_type='cold', delay=10, timeout=180, wait=120):
    """
    reboots DUT
    :param duthost: DUT host object
    :param localhost:  local host object
    :param reboot_type: reboot type (cold, fast, warm)
    :param delay: delay between ssh availability checks
    :param timeout: timeout for waiting ssh port state change
    :param wait: time to wait for DUT to initialize
    :return:
    """

    # pool for executing tasks asynchronously
    pool = ThreadPool()
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']

    try:
        reboot_command = reboot_commands[reboot_type]
    except KeyError:
        raise ValueError('invalid reboot type: "{}"'.format(reboot_type))

    def execute_reboot():
        logger.info('rebooting with command "{}"'.format(reboot_command))
        return duthost.command(reboot_command)

    reboot_res = pool.apply_async(execute_reboot)

    logger.info('waiting for ssh to drop')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout)

    if 'failed' in res:
        if reboot_res.ready():
            logger.error('reboot result: {}'.format(reboot_res.get()))
        raise Exception('DUT did not shutdown')

    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information

    logger.info('waiting for ssh to startup')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout
    )
    if 'failed' in res:
        raise Exception('DUT did not startup')

    logger.info('ssh has started up')

    logger.info('waiting for switch to initialize')
    time.sleep(wait)

    if reboot_type == 'warm':
        logger.info('waiting for warmboot-finalizer service to finish')
        res = duthost.command('systemctl is-active warmboot-finalizer.service',module_ignore_errors=True)
        finalizer_state = res['stdout'].strip()
        assert finalizer_state == 'activating'
        count = 0
        while finalizer_state == 'activating':
            try:
                res = duthost.command('systemctl is-active warmboot-finalizer.service')
            except AnsibleModuleException as err:
                res = err.module_result

            finalizer_state = res['stdout'].strip()
            time.sleep(delay)
            if count * delay > timeout:
                raise Exception('warmboot-finalizer.service did not finish')
            count += 1
        logger.info('warmboot-finalizer service finished')

    logger.info('{} reboot finished'.format(reboot_type))

    pool.terminate()
