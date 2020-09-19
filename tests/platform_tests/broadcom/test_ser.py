import os
import time
import logging

import pytest

from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.broadcom,
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
def test_setup_teardown(duthost, localhost):
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
def test_ser(duthost):
    '''
    @summary: Broadcom SER injection test use Broadcom SER injection utility to insert SER
              into different memory tables. Before the SER injection, Broadcom mem/sram scanners
              are started and syslog file location is marked.
              The test is invoked using:
              pytest platform/broadcom/test_ser.py --testbed=vms12-t0-s6000-1 --inventory=../ansible/str --testbed_file=../ansible/testbed.csv
                                                   --host-pattern=vms12-t0-s6000-1 --module-path=../ansible/library
    @param duthost: Ansible framework testbed DUT device
    '''
    asic_type = duthost.facts["asic_type"]
    if "broadcom" not in asic_type:
        pytest.skip('Skipping SER test for asic_type: %s' % asic_type)

    logger.info('Copying SER injector to dut: %s' % duthost.hostname)
    duthost.copy(src=os.path.join(FILES_DIR, SER_INJECTOR_FILE), dest=DUT_WORKING_DIR)

    logger.info('Running SER injector test')
    rc = duthost.shell('python {}'.format(os.path.join(DUT_WORKING_DIR, SER_INJECTOR_FILE)), executable="/bin/bash")
    logger.info('Test complete with %s: ' % rc)

