"""
Tests for the `show` commands in SONiC
"""
import logging
import paramiko
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from .test_sonic_installer import stop_database_docker

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

def test_show_not_depends_on_database_docker(duthosts, enum_rand_one_per_hwsku_hostname, stop_database_docker):
    """
    @summary: Test show command can work when database docker not running
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])

    # shutdown database docker before test
    show_result = duthost.command("sudo show")
    pytest_assert(show_result["stdout_lines"][0].startswith("Usage: show"),
                  "show command failed, stdout: {}, stderr: {}".format(show_result["stdout_lines"], show_result["stderr_lines"]))
