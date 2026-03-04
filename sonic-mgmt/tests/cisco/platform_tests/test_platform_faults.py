"""
Fault insertion tests for platform.
"""
import time
import logging
import pytest
import re
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any')
]


class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        if CheckEnvironment._is_sim is None:
            result = duthost.shell("sudo dmidecode | grep QEMU", module_ignore_errors=True)['stdout']
            if result:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


def get_ssd_temp_sensor_info(duthost):
    """
    Discover the SSD temperature sensor name and derive fault injection values
    from the CLI output dynamically.

    Returns:
        tuple: (sname, fault_high, fault_low) where fault_high = Crit High TH + 10
               and fault_low = Crit Low TH - 10.
    """
    ssd_line = duthost.shell("show platform temperature | grep -i SSD | head -n 1", module_ignore_errors=True)['stdout']
    if not ssd_line:
        pytest.skip("SSD temperature sensor not found")
    fields = ssd_line.split()
    sname = fields[0]
    if fields[4].upper() == "N/A" or fields[5].upper() == "N/A":
        pytest.fail("SSD temperature sensor '{}' has N/A for Crit High TH / Crit Low TH".format(sname))
    fault_high = int(float(fields[4])) + 10
    fault_low = int(float(fields[5])) - 10
    logging.info("Using SSD temperature sensor: {}, fault_high={}, fault_low={}".format(
        sname, fault_high, fault_low))
    return sname, fault_high, fault_low


def test_platform_overtemp_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an overtemp fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    sname, fault_high, _ = get_ssd_temp_sensor_info(duthost)

    result = duthost.command("sudo docker exec pmon sh -c 'echo {} > /tmp/{}'".format(fault_high, sname))
    logging.info(result)

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep {}".format(sname), module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "True" in str(result), "Temperature over threshold warning not detected"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon sh -c 'echo 25 > /tmp/{}'" .format(sname))
    else:
        result = duthost.command("sudo docker exec pmon rm /tmp/{}".format(sname))

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep {}".format(sname), module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "False" in str(result), "Temperature over threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon rm /tmp/{}".format(sname))


def test_platform_undertemp_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an undertemp fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    sname, _, fault_low = get_ssd_temp_sensor_info(duthost)

    result = duthost.command("sudo docker exec pmon sh -c 'echo {} > /tmp/{}'".format(fault_low, sname))
    logging.info(result)

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep {}".format(sname), module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "True" in str(result), "Temperature under threshold warning not detected"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon sh -c 'echo 25 > /tmp/{}'" .format(sname))
    else:
        result = duthost.command("sudo docker exec pmon rm /tmp/{}".format(sname))

    time.sleep(60)

    result = duthost.shell("show platform temperature | grep {}".format(sname), module_ignore_errors=True)['stdout_lines']
    logging.info(result)

    assert "False" in str(result), "Temperature under threshold warning not cleared"

    if CheckEnvironment.is_sim(duthost):
        result = duthost.command("sudo docker exec pmon rm /tmp/{}".format(sname))


def test_platform_overvolt_fault(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Inject an overvolt fault and check the alarm"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    #Find the first voltage sensor 
    sname = duthost.shell("sed -n '/voltage_sensors/,/name/ s/.*name.*: *//p ' /opt/cisco/etc/thermal_zone.yaml | head -n 1")['stdout']
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
    sname = duthost.shell("sed -n '/voltage_sensors/,/name/ s/.*name.*: *//p ' /opt/cisco/etc/thermal_zone.yaml | head -n 1")['stdout']
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

