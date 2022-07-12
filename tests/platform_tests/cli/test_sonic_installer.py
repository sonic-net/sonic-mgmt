"""
Tests for the `sonic_installer` commands in SONiC
"""
import logging
import paramiko
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.config_reload import config_reload

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

DOCKER_START_WAIT_TIME = 10
CONFIG_RELOAD_WAIT_TIME = 60

@pytest.fixture(scope='function')
def stop_database_docker(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # shutdown database docker before test
    duthost.command("sudo docker stop database", module_ignore_errors=True)

    yield

    # start database docker after test
    duthost.command("sudo docker start database", module_ignore_errors=True)
    time.sleep(DOCKER_START_WAIT_TIME)

    # reload config, because some critical process not work after database docker restart
    config_reload(duthost)
    time.sleep(CONFIG_RELOAD_WAIT_TIME)
    wait_critical_processes(duthost)

def test_sonic_installer_not_depends_on_database_docker(duthosts, enum_rand_one_per_hwsku_hostname, stop_database_docker):
    """
    @summary: Test sonic-installer command can work when database docker not running
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])

    # shutdown database docker before test
    sonic_installer_result = duthost.command("sudo sonic-installer list")
    pytest_assert(sonic_installer_result["stdout_lines"][0].startswith("Current:"),
                  "sonic-installer command failed, stdout: {}, stderr: {}".format(sonic_installer_result["stdout_lines"], sonic_installer_result["stderr_lines"]))
