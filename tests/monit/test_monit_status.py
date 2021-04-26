"""
Test the running status of Monit service
"""
import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

@pytest.fixture
def disable_lldp(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    duthost.command("docker exec lldp supervisorctl stop lldpmgrd")
    if duthost.is_multi_asic:
        duthost.command("docker exec lldp0 supervisorctl stop lldpmgrd")
    yield
    duthost.command("docker exec lldp supervisorctl start lldpmgrd")
    if duthost.is_multi_asic:
        duthost.command("docker exec lldp0 supervisorctl start lldpmgrd")

def check_monit_last_output(duthost):
    monit_status_result = duthost.shell("sudo monit status \'lldp|lldpmgrd\'", module_ignore_errors=True)['stdout_lines']
    indices = [i for i, s in enumerate(monit_status_result) if 'last output' in s]
    monit_last_output = monit_status_result[indices[0]]
    if duthost.is_multi_asic:
        return "/usr/bin/lldpmgrd' is not running in host and in namespace asic0" in monit_last_output
    else:
        return "/usr/bin/lldpmgrd' is not running in host" in monit_last_output

def test_monit_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    monit_status_result = duthost.shell("sudo monit status", module_ignore_errors=True)

    exit_code = monit_status_result["rc"]
    pytest_assert(exit_code == 0, "Monit is either not running or not configured correctly")

def test_monit_reporting_message(duthosts, enum_rand_one_per_hwsku_frontend_hostname, disable_lldp):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not wait_until(180, 60, check_monit_last_output, duthost):
        pytest.fail("Expected Monit reporting message not found")
