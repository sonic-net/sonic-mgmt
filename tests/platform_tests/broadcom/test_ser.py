import time
import logging
import pytest

from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.asic('broadcom'),
    pytest.mark.topology('any'),
    pytest.mark.disable_memory_utilization
]

SER_RESULTS_DIR = '/tmp/ser_result.log'


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
def test_setup_teardown(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
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
def test_ser(duthosts, enum_rand_one_per_hwsku_hostname, enum_asic_index):
    '''
    @summary: Broadcom SER capability tests will test SER injections
              into different memory tables on each ASIC of the selected DUT.

    @param duthost: Ansible framework testbed DUT device
    '''
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = duthost.asic_instance(enum_asic_index)
    bcmcmd = f"bcmcmd -n {asic.asic_index}" if duthost.is_multi_asic else "bcmcmd"
    syncd = asic.get_docker_name("syncd")

    def extract_failed_memory(output):
        failed_memory_list = []
        capture = False

        for line in output:
            if "total failed memory" in line:
                capture = True

            if "total skipped memory" in line:
                break

            if capture:
                failed_memory_list.append(line.strip())

        assert capture, "Did not find failed memory list"
        ser_passed = "total failed memory 0" in failed_memory_list[0]
        return ser_passed, failed_memory_list

    logger.info('Running SER capability test on %s ASIC %s', duthost.hostname, asic.asic_index)

    duthost.shell(f"{bcmcmd} 'SER CAPABILITY Indextype=single Errtype=single Filename={SER_RESULTS_DIR}'",
                  executable="/bin/bash")
    output = duthost.shell(f"docker exec {syncd} cat {SER_RESULTS_DIR}",
                           executable="/bin/bash")['stdout_lines']

    logger.info('SER capability test results:')
    logger.info(output)

    ser_passed, failed_memory_list = extract_failed_memory(output)
    assert ser_passed, "SER test failed! \n" + "\n".join(failed_memory_list)
