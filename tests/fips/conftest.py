import logging
import os
import pytest
import time
import sys

from tests.common.reboot import reboot, REBOOT_TYPE_FAST
from tests.common.helpers.assertions import pytest_assert as pyassert
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from helper import reboot_and_wait_for_fips

@pytest.fixture(scope="module", autouse=True)
def setup_dut(duthosts, rand_one_dut_hostname, localhost):
    '''
    Step dut to diable FIPS during the test
    '''
    duthost = duthosts[rand_one_dut_hostname]

    dut_command = "sudo dpkg-query -W"
    output = duthost.shell(dut_command)['stdout']
    pyrequire('symcrypt' in output.lower(), "Test is not supported on devices which do not support symcrypt!")

    # Check FIPS state
    dut_command = "sudo cat /proc/cmdline"
    output = duthost.shell(dut_command)['stdout']
    enforced = " fips=1" in output or " sonic_fips=1" in output
    if enforced:
        reboot_and_wait_for_fips(duthost, localhost, False)

    yield

    # Check FIPS state, if changed restore the old state
    dut_command = "sudo cat /proc/cmdline"
    output = duthost.shell(dut_command)['stdout']
    enforced_new = " fips=1" in output or " sonic_fips=1" in output
    if enforced != enforced_new:
        reboot_and_wait_for_fips(duthost, localhost, enforced)

