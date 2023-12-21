"""
Fault insertion tests for platform.
"""
import time
import logging
import pytest
import re
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        if CheckEnvironment._is_sim is None:
            result = duthost.shell("sudo dmidecode | grep QEMU")['stdout']
            if result:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


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

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon sh -c 'echo 25 > /tmp/SSD_Temp'")
    else:
        result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep SSD_Temp", module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "False" in str(result), "Temperature over threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")


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

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon sh -c 'echo 25 > /tmp/SSD_Temp'")
    else:
        result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep SSD_Temp", module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "False" in str(result), "Temperature under threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon rm /tmp/SSD_Temp")


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

    if CheckEnvironment.is_sim(duthost):
        numbers = re.findall(r'\b\d+\b', result)
        sensor_val = int(numbers[1]) - 1
        cmd = "sudo docker exec pmon sh -c 'echo {} > /tmp/{}'".format(sensor_val, sname)
        result = duthost.command(cmd)
        logging.info(result)
    else:
        cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
        result = duthost.command(cmd)

    time.sleep(60)

    cmd = "show platform voltage | grep {}".format(sname)
    result = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    logging.info(result)

    assert "False" in str(result), "Voltage over threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
        result = duthost.command(cmd)


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

    if CheckEnvironment.is_sim(duthost):
        numbers = re.findall(r'\b\d+\b', result)
        sensor_val = int(numbers[1]) - 1
        cmd = "sudo docker exec pmon sh -c 'echo {} > /tmp/{}'".format(sensor_val, sname)
        result = duthost.command(cmd)
        logging.info(result)
    else:
        cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
        result = duthost.command(cmd)

    time.sleep(60)

    cmd = "show platform voltage | grep {}".format(sname)
    result = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    logging.info(result)

    assert "False" in str(result), "Voltage under threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        cmd = "sudo docker exec pmon rm /tmp/{}".format(sname)
        result = duthost.command(cmd)

