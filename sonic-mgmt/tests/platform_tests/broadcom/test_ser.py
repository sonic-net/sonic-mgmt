import os
import time
import logging
import re
from datetime import datetime
import pytest

from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.asic('broadcom'),
    pytest.mark.topology('any')
]

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))

FILES_DIR = os.path.join(BASE_DIR, 'files')
SER_INJECTOR_FILE = 'ser_injector.py'
DUT_WORKING_DIR = '/tmp/'


def disable_ssh_timout(dut):
    '''
    @summary disable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Disabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak")
    dut.command("sudo sed -i -e 's/^ClientAliveInterval/#&/' -e 's/^ClientAliveCountMax/#&/' /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)


def enable_ssh_timout(dut):
    '''
    @summary: enable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Enabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)


@pytest.fixture(scope="module", autouse=True)
def test_setup_teardown(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    disable_ssh_timout(duthost)
    # There must be a better way to do this.
    # Reboot the DUT so that we guaranteed to login without ssh timeout.
    reboot(duthost, localhost, wait=120)

    yield

    enable_ssh_timout(duthost)

    # This test could leave DUT in a failed state or have syslog contaminations.
    # We should be able to cleanup with config reload, but reboot to make sure
    # we reset the connection on duthost for now.
    reboot(duthost, localhost, wait=120)


@pytest.mark.disable_loganalyzer
@pytest.mark.broadcom
def test_ser(duthosts, rand_one_dut_hostname, enum_asic_index):
    '''
    @summary: Broadcom SER injection test use Broadcom SER injection utility
              to insert SER into different memory tables. Before the SER
              injection, Broadcom mem/sram scanners are started and syslog
              file location is marked.  The test is invoked using:

              pytest platform/broadcom/test_ser.py --testbed=vms12-t0-s6000-1 \
              --inventory=../ansible/str --testbed_file=../ansible/testbed.csv \
              --host-pattern=vms12-t0-s6000-1 --module-path=../ansible/library

    @param duthost: Ansible framework testbed DUT device
    '''
    duthost = duthosts[rand_one_dut_hostname]

    logger.info('Copying SER injector to dut: %s' % duthost.hostname)
    duthost.copy(
        src=os.path.join(FILES_DIR, SER_INJECTOR_FILE),
        dest=DUT_WORKING_DIR
    )

    logger.info('Running SER injector test')
    log_filename = "/tmp/ser_injector.log"
    args = "-f {}".format(log_filename)
    args += "" if enum_asic_index is None else " -n {}".format(enum_asic_index)

    logger.info('Running SER injector test, args {}'.format(args))
    duthost.shell(
        'python {} {}'.format(
            os.path.join(DUT_WORKING_DIR, SER_INJECTOR_FILE), args
        ),
        module_ignore_errors=True,
        module_async=True,
        executable="/bin/bash"
    )

    timeout = 5400  # Timeout in seconds
    start_time = time.time()
    not_timeout = True

    while True:
        time.sleep(60)

        get_running_proc_cmd = 'ps -aux | grep {}'.format(SER_INJECTOR_FILE)
        get_running_proc_cmd_response = duthost.shell(get_running_proc_cmd, module_ignore_errors=True)
        rc = get_running_proc_cmd_response.get('rc', 1)
        stdout_lines = get_running_proc_cmd_response.get('stdout_lines', [])
        logger.debug("cmd {} rc {} stdout {}".format(get_running_proc_cmd, rc, stdout_lines))

        if rc == 0 and len(stdout_lines) == 2:   # processes_to_be_ignored = 2
            logger.debug("Function executed successfully.")
            break
        elif time.time() - start_time >= timeout:
            logger.debug("Timeout reached. Exiting.")
            not_timeout = False
            break

    get_log_cmd = 'cat {}'.format(log_filename)
    get_log_cmd_response = duthost.shell(get_log_cmd, module_ignore_errors=True)
    get_log_cmd_stdout = get_log_cmd_response.get('stdout', '')

    if not_timeout:
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*rc (\d+)"
        match = re.search(pattern, get_log_cmd_stdout)
        if match:
            timestamp_str = match.group(1)
            rc_value = int(match.group(2))

            log_timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
            current_timestamp = datetime.now()

            if rc_value == 0 and log_timestamp < current_timestamp:
                logger.info('Test complete success')
                return
            else:
                logger.info('Test complete failed with rc {}'.format(rc_value))
    else:
        logger.info('Test complete failed with timeout')

    pattern_asic = re.compile(r'SER test on ASIC :(.*)')
    match_asic = pattern_asic.search(get_log_cmd_stdout)
    result_asic = match_asic.group(0) if match_asic else None

    pattern_failed = re.compile(r'SER Test failed for memories (.*)')
    match_failed_memories = pattern_failed.search(get_log_cmd_stdout)
    result_failed_memories = match_failed_memories.group(0) if match_failed_memories else None

    pattern_timeout = re.compile(r'SER Test timed out for memories (.*)')
    match_timed_out_memories = pattern_timeout.search(get_log_cmd_stdout)
    result_timed_out_memories = match_timed_out_memories.group(0) if match_timed_out_memories else None
    logger.info('result_asic {}; \n'
                'result_failed_memories {}; \n'
                'result_timed_out_memories {}'.format(
                    result_asic, result_failed_memories, result_timed_out_memories)
                )

    logger.debug("test ser script output: \n {}".format(get_log_cmd_response['stdout_lines']))
    time.sleep(5)
    assert not_timeout, 'ser_injector scirpt timeout'
    assert False, (
        'ser_injector script failed; \n'
        'result_asic {}; \n'
        'result_failed_memories {}; \n'
        'result_timed_out_memories {}'.format(
            result_asic, result_failed_memories, result_timed_out_memories
        )
    )
