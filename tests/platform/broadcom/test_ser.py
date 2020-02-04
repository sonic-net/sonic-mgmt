import os
import time
import random
import logging
import pprint

import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.broadcom
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
def setup(testbed_devices):
    '''
    @summary: Test fixture for SER injection test. SER injection test is time consuming.
              This result in ssh session timing out. The setup test fixture disable ssh 
              time out during the test and restores it after test is complete
    @param testbed_devices: Ansible framework testbed devices
    '''
    dut = testbed_devices["dut"]

    disable_ssh_timout(dut)

    yield

    enable_ssh_timout(dut)

@pytest.mark.disable_loganalyzer
@pytest.mark.broadcom
def test_ser(testbed_devices, setup):
    '''
    @summary: Broadcom SER injection test use Broadcom SER injection utility to insert SER
              into different memory tables. Before the SER injection, Broadcom mem/sram scanners 
              are started and syslog file location is marked.
    @param testbed_devices: Ansible framework testbed devices
    @param setup: module test fixture
    '''
    dut = testbed_devices["dut"]
    asic_type = dut.facts["asic_type"]
    if "broadcom" in asic_type:

        logger.info('Copying SER injector to dut: %s' % dut.hostname)
        dut.copy(src=os.path.join(FILES_DIR, SER_INJECTOR_FILE), dest=DUT_WORKING_DIR)

        logger.info('Running SER injector test')
        rc = dut.command('python {}'.format(os.path.join(DUT_WORKING_DIR, SER_INJECTOR_FILE)))
        logger.info('Test complete with %s: ' % rc)

    else:
        logger.info('Skipping SER test for asic_type: %s' % asic_type)
