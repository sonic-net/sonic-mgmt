import logging
import operator
import pytest
import random
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import get_platform_data
from tests.common.utilities import wait_until
from tests.platform_tests.thermal_control_test_helper import *
from mellanox_thermal_control_test_helper import MockerHelper, PsuPowerThresholdMocker
from tabulate import tabulate
import re

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

mocker = None

@pytest.fixture
# We can not set it as module because mocker_factory is function scope
def mock_power_threshold(request, duthosts, rand_one_dut_hostname, mocker_factory):
    global mocker
    psudaemon_restarted = False

    duthost = duthosts[rand_one_dut_hostname]

    MockPlatform = request.config.getoption("--mock_any_testbed")
    mocker = mocker_factory(duthost, 'PsuPowerThresholdMocker')
    if MockPlatform:
        try:
            if mocker.read_psu_power_threshold(1) or mock.read_psu_power_threshold(2):
                logger.info('CLI option "--mock_any_testbed" ignored since PSU power threshold is supported')
        except Exception as e:
            pass

        logger.info('Mocking the system to support PSU power threshold')
        mocker.mock_power_threshold(2)

        # Restart PSU daemon to take the mock stuff
        logger.info('Restart PSU daemon to take mock PSU power threshold')
        duthost.shell('docker exec -ti pmon supervisorctl restart psud')
        psudaemon_restarted = True
        time.sleep(2)

    yield

    logging.info('Clean all mock files')
    mocker.deinit()

    if psudaemon_restarted:
        logger.info('Restore PSU daemon')
        duthost.shell('docker exec -ti pmon supervisorctl restart psud')
        time.sleep(2)


def init_log_analyzer(duthost, marker, expected, ignored=None):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()

    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected)
    if ignored:
        loganalyzer.ignore_regex.extend(ignored)

    return loganalyzer, marker


def check_log_analyzer(loganalyzer, marker):
    loganalyzer.analyze(marker)
    return loganalyzer


@pytest.mark.disable_loganalyzer
def test_psu_power_threshold(request, duthosts, rand_one_dut_hostname, mock_power_threshold):
    def _check_psu_info_in_db(psu_index, power, power_warning_threshold, power_critical_threshold, power_overload):
        psuname = 'PSU {}'.format(psu_index)
        command_check_psu_db = 'sonic-db-cli STATE_DB hmget "PSU_INFO|{}" power power_warning_threshold power_critical_threshold power_overload'.format(psuname)
        output = duthost.shell(command_check_psu_db)['stdout'].split()
        if int(float(output[0])) != power/1000000 \
           or int(float(output[1])) != power_warning_threshold/1000000 \
           or int(float(output[2])) != power_critical_threshold/1000000 \
           or output[3] != str(power_overload):
            return False

        command_check_system_health_db = 'sonic-db-cli STATE_DB hgetall SYSTEM_HEALTH_INFO'
        output = duthost.shell(command_check_system_health_db)['stdout']
        system_health_dict = eval(output)
        if power_overload:
            if 'Not OK' not in system_health_dict['summary'] \
               or 'exceeds threshold' not in system_health_dict[psuname]:
                return False
        else:
            if system_health_dict['summary'] != 'OK':
                return False

        return True

    def _calculate_psu_power_threshold(ambient_threshold, port_ambient, fan_ambient):
        ambient_temperature = min(port_ambient, fan_ambient)
        if ambient_temperature <= ambient_threshold:
            return power_capacity

        return power_capacity - slope * (ambient_temperature - ambient_threshold)

    global mocker

    duthost = duthosts[rand_one_dut_hostname]

    psu_index = 1
    power_capacity = mocker.read_psu_power_threshold(psu_index)
    slope = mocker.read_psu_power_slope()
    power = mocker.read_psu_power(psu_index)
    ambient_critical_threshold = mocker.read_ambient_temp_critical_threshold()
    ambient_warning_threshold = mocker.read_ambient_temp_warning_threshold()
    fan_ambient = mocker.read_fan_ambient_thermal()
    port_ambient = mocker.read_port_ambient_thermal()

    if fan_ambient > ambient_warning_threshold or port_ambient > ambient_warning_threshold:
        pytest.fail('Fan ambient temperature {} or port ambient temperature exceeds the ambient warning threshold'.format(fan_ambient, port_ambient))

    if power > power_capacity:
        pytest.fail('Current power {} exceeds maximum power capacity {}'.format(power, power_capacity))

    # Ignore some possible errors
    loganalyzer, marker = init_log_analyzer(duthost,
                                            'PSU power exceeding test',
                                            [],
                                            ['Failed to read from file {}'.format(PsuPowerThresholdMocker.PORT_AMBIENT_TEMP),
                                             'Failed to read from file {}'.format(PsuPowerThresholdMocker.FAN_AMBIENT_TEMP)])

    # Mock the power as well.
    # This is to make sure the power will be a fixed value because it can flucuate if it was read from a sensor.
    logger.info('Mock PSU power to {} which is in normal range'.format(power/1000000)) 
    mocker.mock_psu_power(psu_index, power)

    # 1. Mock power to range (warning, critical)
    # 1.2 Mock ambient temperature sensors
    port_ambient_mock = ambient_warning_threshold + (ambient_critical_threshold - ambient_warning_threshold)/2
    fan_ambient_mock = ambient_critical_threshold
    power_critical_threshold = _calculate_psu_power_threshold(ambient_critical_threshold, port_ambient_mock, fan_ambient_mock)
    power_warning_threshold = _calculate_psu_power_threshold(ambient_warning_threshold, port_ambient_mock, fan_ambient_mock)

    logger.info('Mock ambient temperature sensors (fan {} port {}) and check the thresholds'.format(
        port_ambient_mock/1000,
        fan_ambient_mock/1000))
    mocker.mock_port_ambient_thermal(port_ambient_mock)
    mocker.mock_fan_ambient_thermal(fan_ambient_mock)
    # Check whether thresholds are updated
    assert wait_until(10,
                      2,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      False)

    # 1.2 Mock the power
    power = power_warning_threshold
    logger.info('Mock PSU power to {} which is in the range between warning {} and critical {} thresholds'.format(
        power/1000000,
        power_warning_threshold/1000000,
        power_critical_threshold/1000000))
    mocker.mock_psu_power(psu_index, power)
    assert wait_until(10,
                      2,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      False)

    # 2. Mock power to range (critical, )
    # 2.1 Mock ambient temperature sensors
    port_ambient_mock = ambient_critical_threshold + 1000
    fan_ambient_mock = ambient_critical_threshold + 5000
    power_critical_threshold = _calculate_psu_power_threshold(ambient_critical_threshold, port_ambient_mock, fan_ambient_mock)
    power_warning_threshold = _calculate_psu_power_threshold(ambient_warning_threshold, port_ambient_mock, fan_ambient_mock)

    logger.info('Mock ambient temperature sensors (fan {} port {}) and check the thresholds'.format(
        port_ambient_mock/1000,
        fan_ambient_mock/1000))
    mocker.mock_port_ambient_thermal(port_ambient_mock)
    mocker.mock_fan_ambient_thermal(fan_ambient_mock)

    # Check whether thresholds are updated
    assert wait_until(10,
                      2,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      False)

    # Prepare for log analyzer
    check_log_analyzer(loganalyzer, marker)
    loganalyzer, marker = init_log_analyzer(duthost,
                                            'PSU power exceeds threshold',
                                            ['PSU power warning: .* power .* exceeds critical threshold'])

    # 2.2 Mock the power
    power = power_critical_threshold + 1000000
    logger.info('Mock PSU power to {} which is in greater than the critical threshold {}, make sure alarm is raised'.format(
        power/1000000,
        power_critical_threshold/1000000))
    mocker.mock_psu_power(psu_index, power)
    assert wait_until(80,
                      10,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      True)

    # Check whether the expected message is found
    check_log_analyzer(loganalyzer, marker)
    loganalyzer, marker = init_log_analyzer(duthost, 'PSU power exceeding threshold', [])

    # 3. Mock power to range (warning, critical)
    power = power_critical_threshold - 1000000
    logger.info('Mock PSU power to {} which is in the range the between warning {} and the critical {} thresholds, make sure alarm remains'.format(
        power/1000000,
        power_warning_threshold/1000000,
        power_critical_threshold/1000000))
    mocker.mock_psu_power(psu_index, power)
    assert wait_until(10,
                      2,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      True)

    # 4. Mock power to range (, warning)
    # 4.1 Mock ambient temperature sensors
    port_ambient_mock = ambient_critical_threshold + 1000
    fan_ambient_mock = ambient_warning_threshold + (ambient_critical_threshold - ambient_warning_threshold)/2
    power_critical_threshold = _calculate_psu_power_threshold(ambient_critical_threshold, port_ambient_mock, fan_ambient_mock)
    power_warning_threshold = _calculate_psu_power_threshold(ambient_warning_threshold, port_ambient_mock, fan_ambient_mock)

    logger.info('Mock ambient temperature sensors (fan {} port {}) and check the thresholds'.format(
        port_ambient_mock/1000,
        fan_ambient_mock/1000))
    mocker.mock_port_ambient_thermal(port_ambient_mock)
    mocker.mock_fan_ambient_thermal(fan_ambient_mock)
    # Check whether thresholds are updated
    assert wait_until(10,
                      2,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      True)

    # Prepare log analyzer
    check_log_analyzer(loganalyzer, marker)
    loganalyzer, marker = init_log_analyzer(duthost,
                                            'PSU power become back to normal',
                                            ['PSU power warning cleared: .* power .* is back to normal'])

    # 4.2 Mock power
    power = power_warning_threshold - 1000000
    logger.info('Mock PSU power to {} which is less than the warning threshold {}, make sure alarm is cleared'.format(
        power/1000000,
        power_warning_threshold/1000000))
    mocker.mock_psu_power(psu_index, power)
    assert wait_until(80,
                      10,
                      0,
                      _check_psu_info_in_db,
                      psu_index,
                      power,
                      power_warning_threshold,
                      power_critical_threshold,
                      False)

    check_log_analyzer(loganalyzer, marker)
