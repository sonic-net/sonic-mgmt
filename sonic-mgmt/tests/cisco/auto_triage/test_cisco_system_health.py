"""
Tests for the cisco_system_health script
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_cisco_system_health(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify the Cisco platform system health via cisco_system_health.py
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo python3 /opt/cisco/tools/bin/cisco_system_health.py")
    logging.info(result)
    assert "Platform services state check Passed" in result["stdout"], "Platform services state check Failed!"
    assert "Container check Passed" in result["stdout"], "Container check Failed!"
    assert "Platform Health Check Passed" in result["stdout"], "Platform Health Check Failed!"
