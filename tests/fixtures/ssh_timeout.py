import pytest
import logging

logger = logging.getLogger(__name__)

def disable_ssh_timout(dut):
    '''
    @summary disable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Disabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo sed -i 's/^ClientAliveInterval/#&/' /etc/ssh/sshd_config")
    dut.command("sudo sed -i 's/^ClientAliveCountMax/#&/' /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)

def enable_ssh_timout(dut):
    '''
    @summary: enable ssh session on target dut
    @param dut: Ansible host DUT
    '''
    logger.info('Enabling ssh time out on dut: %s' % dut.hostname)
    dut.command("sudo sed -i '/^#ClientAliveInterval/s/^#//' /etc/ssh/sshd_config")
    dut.command("sudo sed -i '/^#ClientAliveCountMax/s/^#//' /etc/ssh/sshd_config")

    dut.command("sudo systemctl restart ssh")
    time.sleep(5)

@pytest.fixture(scope='module')
def pause_testbed_ssh_timeout(testbed_devices):
    '''
    @summary: Test fixture for lengthy test cases. This result in ssh session timing out.
              The setup test fixture disable ssh time out during the test and restores it
              after test is complete
    @param testbed_devices: Ansible framework testbed devices
    '''
    dut = testbed_devices["dut"]

    disable_ssh_timout(dut)

    yield

    enable_ssh_timout(dut)
