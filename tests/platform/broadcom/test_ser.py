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

@pytest.mark.disable_loganalyzer
@pytest.mark.broadcom
@pytest.mark.usefixtures("pause_testbed_ssh_timeout")
def test_ser(testbed_devices, pause_testbed_ssh_timeout):
    '''
    @summary: Broadcom SER injection test use Broadcom SER injection utility to insert SER
              into different memory tables. Before the SER injection, Broadcom mem/sram scanners 
              are started and syslog file location is marked.
              The test is invoked using:
              pytest platform/broadcom/test_ser.py --testbed=vms12-t0-s6000-1 --inventory=../ansible/str --testbed_file=../ansible/testbed.csv 
                                                   --host-pattern=vms12-t0-s6000-1 --module-path=../ansible/library
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
