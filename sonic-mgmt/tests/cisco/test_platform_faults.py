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

    assert "True" in str(result), "Temperature under threshold warning not detected"

    result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")
    logging.info(result)


def test_platform_overvolt_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an overvolt fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    #Find the first voltage sensor 
    sname = duthost.shell("sed -n '/voltage_sensors/,/name/ s/.*name.*: *//p ' /opt/cisco/etc/thermal_zone.yaml")['stdout']
    logging.info(sname)

    if not sname:
        pytest.skip("Voltage sensor not found")

    cmd = "sudo docker exec pmon sh -c 'echo 100000 > /tmp/{}'".format(sname)
    result = duthost.command(cmd)
    logging.info(result)

    time.sleep(60)

    cmd = "show platform voltage | grep {}".format(sname)
    result = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    logging.info(result)

    assert "True" in str(result), "Voltage over threshold warning not detected"

    cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
    result = duthost.command(cmd)
    logging.info(result)


def test_platform_undervolt_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an undervolt fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    #Find the first voltage sensor 
    sname = duthost.shell("sed -n '/voltage_sensors/,/name/ s/.*name.*: *//p ' /opt/cisco/etc/thermal_zone.yaml")['stdout']
    logging.info(sname)

    if not sname:
        pytest.skip("Voltage sensor not found")

    cmd = "sudo docker exec pmon sh -c 'echo 0 > /tmp/{}'".format(sname)
    result = duthost.command(cmd)
    logging.info(result)

    time.sleep(60)

    cmd = "show platform voltage | grep {}".format(sname)
    result = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    logging.info(result)
    assert "True" in str(result), "Voltage under threshold warning not detected"

    cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
    result = duthost.command(cmd)
    logging.info(result)

