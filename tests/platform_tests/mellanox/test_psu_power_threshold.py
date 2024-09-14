import allure
import logging
import pytest
import time
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.assertions import pytest_assert
from tests.common.mellanox_data import get_platform_data
from tests.common.utilities import wait_until  # noqa F401
from tests.common.helpers.thermal_control_test_helper import mocker_factory  # noqa F401
from .mellanox_thermal_control_test_helper import MockerHelper, PsuPowerThresholdMocker  # noqa F401

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

mocker = None

MAX_PSUS = None


@pytest.fixture(autouse=True)
def check_feature_supported(request, duthosts, rand_one_dut_hostname, mocker_factory): # noqa F811
    global MAX_PSUS
    global mocker
    duthost = duthosts[rand_one_dut_hostname]
    platform_data = get_platform_data(duthost)
    MAX_PSUS = platform_data['psus']['number']
    all_psus_supporting_thresholds = True
    mocker = mocker_factory(duthost, 'PsuPowerThresholdMocker')
    try:
        for psu_index in range(MAX_PSUS):
            mocker.read_psu_power_threshold(psu_index + 1)
            mocker.read_psu_power_slope(psu_index + 1)
    except Exception:
        all_psus_supporting_thresholds = False

    MockPlatform = request.config.getoption("--mock_any_testbed")

    if MockPlatform and all_psus_supporting_thresholds:
        pytest.fail('CLI option "--mock_any_testbed" is provided while power thresholds are supported on both PSUs')

    if not (all_psus_supporting_thresholds or MockPlatform):
        pytest.skip('PSU power threshold is not supported')


@pytest.fixture
def mock_ambient_temp_threshold():
    ambient_temp_critical_threshold = 60000
    ambient_temp_warning_threshold = 50000
    mocker.mock_ambient_temp_critical_threshold(ambient_temp_critical_threshold)
    mocker.mock_ambient_temp_warning_threshold(ambient_temp_warning_threshold)


@pytest.fixture
def mock_power_threshold(request, duthosts, rand_one_dut_hostname, mock_ambient_temp_threshold):  # noqa F811
    psudaemon_restarted = False
    duthost = duthosts[rand_one_dut_hostname]

    MockPlatform = request.config.getoption("--mock_any_testbed")
    if MockPlatform:
        logger.info('Mocking the system to support PSU power threshold')
        mocker.mock_power_threshold(MAX_PSUS)

        # Restart PSU daemon to take the mock stuff
        logger.info('Restart PSU daemon to take mock PSU power threshold')
        duthost.shell('docker exec pmon supervisorctl restart psud')
        psudaemon_restarted = True
        time.sleep(2)
    else:
        try:
            ambient_critical_threshold = None
            ambient_warning_threshold = None
            ambient_critical_threshold = mocker.read_ambient_temp_critical_threshold()
            ambient_warning_threshold = mocker.read_ambient_temp_warning_threshold()
        except Exception:
            pytest.fail('Some required information does not exist (ambient thresholds critical {} warning {})'.format(
                ambient_critical_threshold,
                ambient_warning_threshold))

    yield

    logging.info('Clean all mock files')
    mocker.deinit()

    if psudaemon_restarted:
        logger.info('Restore PSU daemon')
        duthost.shell('docker exec pmon supervisorctl restart psud')
        time.sleep(2)


def init_log_analyzer(duthost, marker, expected, ignored=['Failed to read from file.*(fan_amb|port_amb)']):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()

    loganalyzer.load_common_config()
    loganalyzer.expect_regex = expected
    if ignored:
        loganalyzer.ignore_regex.extend(ignored)

    return loganalyzer, marker


def check_log_analyzer(loganalyzer, marker):
    loganalyzer.analyze(marker)
    return loganalyzer


@pytest.mark.disable_loganalyzer
def test_psu_power_threshold(request, duthosts, rand_one_dut_hostname, mock_power_threshold):
    def _check_psu_info_in_db(psu_index, power, power_warning_suppress_threshold, power_critical_threshold,
                              power_overload):
        psuname = 'PSU {}'.format(psu_index)
        command_check_psu_db = 'sonic-db-cli STATE_DB hmget "PSU_INFO|{}" power ' \
            'power_warning_suppress_threshold power_critical_threshold power_overload'.format(
                psuname)
        output = duthost.shell(command_check_psu_db)['stdout'].split()
        if len(output) != 4:
            pytest.fail(
                'Got wrong information ({}) from STATE_DB PSU_INFO|{}'.format(output, psuname))

        if int(float(output[1])) != power_warning_suppress_threshold/1000000 \
           or int(float(output[2])) != power_critical_threshold/1000000 \
           or output[3] != str(power_overload):
            return False

        if abs(float(output[0])*1000000 - power/MAX_PSUS) > 100:
            return False

        command_check_system_health_db = 'sonic-db-cli STATE_DB hget SYSTEM_HEALTH_INFO "{}"'
        summary = duthost.shell(command_check_system_health_db.format('summary'))[
            'stdout'].strip()
        if power_overload:
            if 'Not OK' in summary:
                detail = duthost.shell(command_check_system_health_db.format(psuname))[
                    'stdout'].strip()
                if 'exceeds threshold' in detail:
                    return True
        elif summary == 'OK':
            return True
        else:
            detail = duthost.shell(command_check_system_health_db.format(psuname))[
                'stdout'].strip()
            if not detail:
                return True
            else:
                logger.info(
                    'SYSTEM_HEALTH_INFO: {} is not OK due to {}'.format(psuname, detail))

        return False

    def _calculate_psu_power_threshold(ambient_threshold, port_ambient, fan_ambient, extra_adjustment=None):
        ambient_temperature = min(port_ambient, fan_ambient)
        if ambient_temperature <= ambient_threshold:
            power_threshold = power_capacity
        else:
            power_threshold = power_capacity - slope * (ambient_temperature - ambient_threshold)

        if extra_adjustment:
            power_threshold -= extra_adjustment

        return power_threshold

    def _update_ambient_sensors_and_check_db(psu_index, port_ambient_mock, fan_ambient_mock, power, was_power_exceeded):
        power_critical_threshold = _calculate_psu_power_threshold(ambient_critical_threshold, port_ambient_mock,
                                                                  fan_ambient_mock)
        power_warning_suppress_threshold = _calculate_psu_power_threshold(ambient_warning_threshold,
                                                                          port_ambient_mock, fan_ambient_mock,
                                                                          slope * 1000)

        logger.info('Mock ambient temperature sensors (fan {} port {}) and check the thresholds)'.format(
            port_ambient_mock/1000,
            fan_ambient_mock/1000))
        mocker.mock_port_ambient_thermal(port_ambient_mock)
        mocker.mock_fan_ambient_thermal(fan_ambient_mock)
        # Check whether thresholds are updated
        pytest_assert(wait_until(10,
                                 2,
                                 0,
                                 _check_psu_info_in_db,
                                 psu_index,
                                 power,
                                 power_warning_suppress_threshold,
                                 power_critical_threshold,
                                 was_power_exceeded))

        return power_warning_suppress_threshold, power_critical_threshold

    def _update_power_and_check_db(psu_index, power_warning_suppress_threshold, power_critical_threshold, power,
                                   was_power_exceeded):
        logger.info('Mock PSU {} power to {} (the warning threshold {}, the critical threshold {})'.format(
            psu_index,
            power/1000000,
            power_warning_suppress_threshold/1000000,
            power_critical_threshold/1000000))

        mocker.mock_psu_power(power, MAX_PSUS)
        if was_power_exceeded and power < power_warning_suppress_threshold \
           or not was_power_exceeded and power >= power_critical_threshold:
            timeout = 80
            interval = 10
            is_power_exceeded = not was_power_exceeded
        else:
            timeout = 10
            interval = 2
            is_power_exceeded = was_power_exceeded

        pytest_assert(wait_until(timeout,
                                 interval,
                                 0,
                                 _check_psu_info_in_db,
                                 psu_index,
                                 power,
                                 power_warning_suppress_threshold,
                                 power_critical_threshold,
                                 is_power_exceeded))

    global mocker

    duthost = duthosts[rand_one_dut_hostname]

    ambient_critical_threshold = mocker.read_ambient_temp_critical_threshold()
    ambient_warning_threshold = mocker.read_ambient_temp_warning_threshold()
    fan_ambient = mocker.read_fan_ambient_thermal()
    port_ambient = mocker.read_port_ambient_thermal()

    if fan_ambient > ambient_warning_threshold or port_ambient > ambient_warning_threshold:
        pytest.fail('The ambient temperature of fan {} or port {} exceeds the ambient warning threshold'.
                    format(fan_ambient, port_ambient))

    for i in range(MAX_PSUS):
        psu_index = i + 1

        logging.info('Starting mock test on PSU {}'.format(psu_index))

        power_capacity = mocker.read_psu_power_threshold(psu_index)
        power = mocker.read_psu_power(psu_index)
        slope = mocker.read_psu_power_slope(psu_index) * 1000

        if power > power_capacity:
            pytest.fail('Current power {} exceeds maximum power capacity {}'.format(
                power, power_capacity))

        # Ignore some possible errors
        loganalyzer, marker = init_log_analyzer(duthost,
                                                'PSU power exceeding test',
                                                [])

        # Mock the power as well.
        # This is to make sure the power will be a fixed value because it can flucuate if it was read from a sensor.
        logger.info(
            'Mock PSU power to {} which is in normal range'.format(power/1000000))
        mocker.mock_psu_power(power, MAX_PSUS)

        power_warning_suppress_threshold = None
        power_critical_threshold = None

        with allure.step('Mock power to range (warning, critical)'):
            with allure.step('Mock ambient temperature sensors'):
                power_warning_suppress_threshold, power_critical_threshold = \
                    _update_ambient_sensors_and_check_db(psu_index,
                                                         ambient_warning_threshold +
                                                         (ambient_critical_threshold -
                                                          ambient_warning_threshold)/2,
                                                         ambient_critical_threshold,
                                                         power,
                                                         False)

            with allure.step('Mock the power'):
                power = power_warning_suppress_threshold + 1000000
                _update_power_and_check_db(psu_index,
                                           power_warning_suppress_threshold,
                                           power_critical_threshold,
                                           power,
                                           False)

        with allure.step('Mock power to range (critical, infinity)'):
            with allure.step('Mock ambient temperature sensors'):
                power_warning_suppress_threshold, power_critical_threshold = \
                    _update_ambient_sensors_and_check_db(psu_index,
                                                         ambient_critical_threshold + 5000,
                                                         ambient_critical_threshold + 1000,
                                                         power,
                                                         False)
                # Prepare for log analyzer
                check_log_analyzer(loganalyzer, marker)
                loganalyzer, marker = init_log_analyzer(duthost,
                                                        'PSU power exceeds threshold',
                                                        ['PSU power warning: '
                                                         'system power .* exceeds the critical threshold'])

            with allure.step('Mock the power'):
                power = power_critical_threshold + 1000000
                _update_power_and_check_db(psu_index,
                                           power_warning_suppress_threshold,
                                           power_critical_threshold,
                                           power,
                                           False)

                # Check whether the expected message is found
                check_log_analyzer(loganalyzer, marker)
                loganalyzer, marker = init_log_analyzer(
                    duthost, 'PSU power exceeding threshold', [])

        with allure.step('Mock power to range (warning, critical)'):
            power = power_critical_threshold - 1000000
            _update_power_and_check_db(psu_index,
                                       power_warning_suppress_threshold,
                                       power_critical_threshold,
                                       power,
                                       True)

        with allure.step('Mock power to range (a low value, warning)'):
            with allure.step('Mock ambient temperature sensors'):
                power_warning_suppress_threshold, power_critical_threshold = \
                    _update_ambient_sensors_and_check_db(psu_index,
                                                         ambient_critical_threshold + 1000,
                                                         ambient_warning_threshold +
                                                         (ambient_critical_threshold -
                                                          ambient_warning_threshold)/2,
                                                         power,
                                                         True)

                # Prepare log analyzer
                check_log_analyzer(loganalyzer, marker)
                loganalyzer, marker = init_log_analyzer(duthost,
                                                        'PSU power become back to normal',
                                                        ['PSU power warning cleared: '
                                                         'system power .* is back to normal, '
                                                         'below the warning suppress threshold'])

            with allure.step('Mock power'):
                _update_power_and_check_db(psu_index,
                                           power_warning_suppress_threshold,
                                           power_critical_threshold,
                                           power_warning_suppress_threshold - 1000000,
                                           True)

                check_log_analyzer(loganalyzer, marker)
