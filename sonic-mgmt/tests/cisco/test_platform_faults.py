"""
Fault insertion tests for platform.
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


def test_platform_overtemp_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an overtemp fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command("sudo docker exec pmon sh -c 'echo 150 > /tmp/SSD_Temp'")
    logging.info(result)

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep SSD_Temp", module_ignore_errors=True)['stdout_lines']
    logging.info(result)
    assert "True" in str(result), "Temperature over threshold warning not detected"

    result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")
    logging.info(result)

def test_platform_undertemp_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an undertemp fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command("sudo docker exec pmon sh -c 'echo -15 > /tmp/SSD_Temp'")
    logging.info(result)

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep SSD_Temp", module_ignore_errors=True)['stdout_lines']
    logging.info(result)
    assert "True" in str(result), "Temperature over threshold warning not detected"

    result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")
    logging.info(result)

