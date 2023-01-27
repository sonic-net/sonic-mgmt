import logging
import operator
import pytest
import random
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import get_platform_data
from tests.common.utilities import wait_until
from tests.platform_tests.thermal_control_test_helper import *
from mellanox_thermal_control_test_helper import MockerHelper, AbnormalFanMocker
from tabulate import tabulate
from .minimum_table import get_min_table
import re

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

THERMAL_CONTROL_TEST_WAIT_TIME = 75
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5

THERMAL_PATH = '/run/hw-management/thermal/'
COOLING_CUR_STATE_PATH = '/run/hw-management/thermal/cooling_cur_state'
COOLING_CUR_STATE_THRESHOLD = 7
PSU_PRESENCE_PATH = '/run/hw-management/thermal/psu{}_status'
PSU_SPEED_PATH = '/run/hw-management/thermal/psu{}_fan1_speed_get'
PSU_MAX_SPEED_PATH = '/run/hw-management/config/psu_fan_max'
PWM_PATH = '/run/hw-management/thermal/pwm1'
MAX_PWM = 255
PSU_SPEED_TOLERANCE = 0.25

MAX_COOLING_LEVEL = 10


@pytest.mark.disable_loganalyzer
def test_dynamic_minimum_table(duthosts, rand_one_dut_hostname, mocker_factory):
    duthost = duthosts[rand_one_dut_hostname]
    minimum_table = get_min_table(duthost)
    if minimum_table:
        max_temperature = 45000 # 45 C
        cooling_cur_state = get_cooling_cur_state(duthost)
        if cooling_cur_state >= COOLING_CUR_STATE_THRESHOLD:
            pytest.skip('The cooling level {} is higher than threshold {}.'.format(cooling_cur_state, COOLING_CUR_STATE_THRESHOLD))

        mocker = mocker_factory(duthost, 'MinTableMocker')
        mocker.mock_normal_temperature()
        temperature = random.randint(0, max_temperature)
        trust_state = True if random.randint(0, 1) else False
        logger.info('Testing with temperature={}, trust_state={}'.format(temperature, trust_state))
        expect_minimum_cooling_level = mocker.get_expect_cooling_level(temperature, trust_state)
        logger.info('Expect minimum cooling level is {}'.format(expect_minimum_cooling_level))
        mocker.mock_min_table(temperature, trust_state)
        assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                        THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                        0,
                        check_cooling_level_larger_than_minimum,
                        duthost,
                        expect_minimum_cooling_level), \
                        'Cooling level is less than minimum allowed {}'.format(expect_minimum_cooling_level)

        temperature = random.randint(0, max_temperature)
        logger.info('Testing with temperature={}, trust_state={}'.format(temperature, not trust_state))
        expect_minimum_cooling_level = mocker.get_expect_cooling_level(temperature, not trust_state)
        logger.info('Expect minimum cooling level is {}'.format(expect_minimum_cooling_level))
        mocker.mock_min_table(temperature, not trust_state)
        assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                        THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                        0,
                        check_cooling_level_larger_than_minimum,
                        duthost,
                        expect_minimum_cooling_level), \
                        'Cooling level is less than minimum allowed {}'.format(expect_minimum_cooling_level)
    else:
        # minimum table is not defined yet, check that the default cooling level is 6
        assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                        THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                        0,
                        check_cooling_level_larger_than_minimum,
                        duthost,
                        6), \
                        'Cooling level is less than minimum allowed {}'.format(6)


@pytest.mark.disable_loganalyzer
def test_set_psu_fan_speed(duthosts, rand_one_dut_hostname, mocker_factory):
    duthost = duthosts[rand_one_dut_hostname]
    platform_data = get_platform_data(duthost)
    psu_num = platform_data['psus']['number']
    hot_swappable = platform_data['psus']['hot_swappable']
    if not hot_swappable:
        pytest.skip('The platform {} does not support this test case.'.format(duthost.facts["platform"]))

    psu_max_speed = get_psu_max_speed(duthost)
    logger.info('Create mocker, it may take a few seconds...')
    single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
    logger.info('Mock FAN absence...')
    single_fan_mocker.mock_absence()
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME * 2,
                      THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                      0,
                      check_psu_fan_speed,
                      duthost,
                      psu_num,
                      psu_max_speed,
                      operator.eq), 'Wait for PSU fan speed change to full speed failed'

    logger.info('Mock FAN presence...')
    single_fan_mocker.mock_presence()
    wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME * 2,
                             THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                             0,
                             check_psu_fan_speed,
                             duthost,
                             psu_num,
                             psu_max_speed,
                             operator.ne)

    if not wait_result:
        cooling_cur_state = get_cooling_cur_state(duthost)
        if cooling_cur_state == MAX_COOLING_LEVEL:
            cmd_output = str(duthost.command('show platform temperature')['stdout_lines'])
            cmd_output = cmd_output.replace("u'", "").replace(',', " ")
            cmd_output = re.split(r'  +',cmd_output)
            cmd_output.pop(0)
            j = 0
            table = []
            while j != len(cmd_output):
                entry = []
                for i in range(8):
                    entry.append(cmd_output[j + i])
                table.append(entry)
                j += 8
            pytest.skip('Cooling level is still 10, ignore the rest test.\nIt might happen because the asic temperature is still high.\nCurrent system temperature:\n{}'.format(tabulate(table)))
        else:
            assert False, 'Wait for PSU fan speed change to normal failed'


@pytest.mark.disable_loganalyzer
def test_psu_absence_policy(duthosts, rand_one_dut_hostname, mocker_factory):
    duthost = duthosts[rand_one_dut_hostname]
    platform_data = get_platform_data(duthost)
    hot_swappable = platform_data['psus']['hot_swappable']
    if not hot_swappable:
        pytest.skip('The platform {} does not support this test case.'.format(duthost.facts["platform"]))

    psu_num = platform_data['psus']['number']
    psu_mocker = mocker_factory(duthost, 'PsuMocker')
    psu_index = random.randint(1, psu_num)
    psu_mocker.mock_psu_status(psu_index, False)
    wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                             THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                             0,
                             check_pwm,
                             duthost,
                             MAX_PWM,
                             operator.eq)
    assert wait_result, 'PSU is absent, but PWM value is not turned to {}'.format(MAX_PWM)
    assert check_fan_speed(duthost, MAX_PWM), 'Fan speed is not turn to {}'.format(MAX_PWM)


@pytest.mark.disable_loganalyzer
def test_cpu_thermal_control(rand_selected_dut, mocker_factory):
    duthost = rand_selected_dut
    dut_platform = duthost.facts["platform"]
    pytest_require(dut_platform == "x86_64-nvidia_sn4800-r0", 'This test case is only for platform x86_64-nvidia_sn4800-r0, skipping...')
    mocker = mocker_factory(duthost, 'CpuThermalMocker')

    temp_step = 1000
    # Mock CPU temperature is lower than low threshold
    mocker.mock_cpu_pack_temperature(mocker.LOW_THRESHOLD - temp_step)
    wait_result = wait_until(10, 3, 0, check_cpu_cooling_state, mocker, mocker.MIN_COOLING_STATE)
    pytest_assert(wait_result, 
                  'CPU cooling state is not MIN when temperature is below low threshold')

    # Mock CPU temperature is raising
    mocker.mock_cpu_pack_temperature(mocker.LOW_THRESHOLD)
    wait_result = wait_until(10, 3, 0, check_cpu_cooling_state, mocker, mocker.MIN_COOLING_STATE + 1)
    pytest_assert(wait_result, 
                  'CPU cooling state is not increasing when temperature is rasing')

    # Mock CPU temperature is larger than high threshold
    mocker.mock_cpu_pack_temperature(mocker.HIGH_THRESHOLD + temp_step)
    wait_result = wait_until(10, 3, 0, check_cpu_cooling_state, mocker, mocker.MAX_COOLING_STATE)
    pytest_assert(wait_result, 
                  'CPU cooling state is not MAX increasing when temperature is beyond high threshold')

    # Mock CPU temperature is decreasing
    mocker.mock_cpu_pack_temperature(mocker.HIGH_THRESHOLD)
    wait_result = wait_until(10, 3, 0, check_cpu_cooling_state, mocker, mocker.MAX_COOLING_STATE - 1)
    pytest_assert(wait_result, 
                  'CPU cooling state is not decreasing when temperature is decreasing')


def _check_psu_fan_speed_in_range(actual_speed, max_speed, cooling_level):
    expect_speed = max_speed * cooling_level / 10.0
    logger.info('Expect speed: {}, actual speed: {}'.format(expect_speed, actual_speed))
    if expect_speed > actual_speed:
        return actual_speed > expect_speed * (1 - PSU_SPEED_TOLERANCE)
    elif expect_speed < actual_speed:
        return actual_speed < expect_speed * (1 + PSU_SPEED_TOLERANCE)


def get_psu_speed(dut, index):
    index = index + 1
    psu_speed_path = PSU_SPEED_PATH.format(index)
    file_stat = dut.stat(path=psu_speed_path)
    assert file_stat["stat"]["exists"], 'Failed to get PSU speed file due to {} does not exist'.format(psu_speed_path)

    cmd_output = dut.command('cat {}'.format(psu_speed_path))
    try:
        speed = int(cmd_output['stdout'])
        logger.info('Speed for PSU {} fan is {}'.format(index, speed))
        return speed
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(psu_speed_path, e)


def get_psu_max_speed(dut):
    cmd_output = dut.command('cat {}'.format(PSU_MAX_SPEED_PATH))
    try:
        psu_max_speed = int(cmd_output['stdout'])
        logger.info('Max PSU fan speed is {}'.format(psu_max_speed))
        return psu_max_speed
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(PSU_MAX_SPEED_PATH, e)


def get_cooling_cur_state(dut):
    cmd_output = dut.command('cat {}'.format(COOLING_CUR_STATE_PATH))
    try:
        cooling_cur_state = int(cmd_output['stdout'])
        logger.info('Cooling level is {}'.format(cooling_cur_state))
        return cooling_cur_state
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(COOLING_CUR_STATE_PATH, e)


def check_psu_fan_speed(duthost, psu_num, psu_max_speed, op):
    """Check if PSU fan speed is in the expect range.

    Args:
        duthost: DUT host object
        psu_num: PSU number
        psu_max_speed: PSU max fan speed
        op: operator eq or ne which is used to compare actual cooling level with MAX_COOLING_LEVEL

    Returns:
        [boolean]: True if all PSU fans speed are in a expected range
    """
    cooling_cur_state = get_cooling_cur_state(duthost)
    if not op(cooling_cur_state, MAX_COOLING_LEVEL):
        return False

    # PSU fan speed will never be less than 60%
    if cooling_cur_state < 6:
        cooling_cur_state = 6

    for index in range(psu_num):
        speed = get_psu_speed(duthost, index)
        if not _check_psu_fan_speed_in_range(speed, psu_max_speed, cooling_cur_state):
            return False

    return True


def check_cooling_level_larger_than_minimum(duthost, expect_minimum_cooling_level):
    actual_cooling_level = get_cooling_cur_state(duthost)
    return actual_cooling_level >= expect_minimum_cooling_level


def get_pwm_value(dut):
    cmd_output = dut.command('cat {}'.format(PWM_PATH))
    try:
        pwm_value = int(cmd_output['stdout'])
        logger.info('PWM is {}'.format(pwm_value))
        return pwm_value
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(PWM_PATH, e)


def check_pwm(duthost, expect_value, op):
    """Check if FAN PWM value is the expect value

    Args:
        duthost (object): DUT host object
        expect_value (int): Expect PWM value
        op (object): Operator eq or ne

    Returns:
        boolean: True if the pwm value is expected
    """
    pwm_value = get_pwm_value(duthost)
    return op(pwm_value, expect_value)


def check_fan_speed(duthost, expect_value):
    get_fan_speed_sysfs_cmd = 'ls {}fan*_speed_set'.format(THERMAL_PATH)
    file_list = duthost.shell(get_fan_speed_sysfs_cmd)['stdout'].splitlines()
    for file in file_list:
        actual_speed = int(duthost.shell('cat {}'.format(file))['stdout'].strip())
        if actual_speed != expect_value:
            logging.error('For file {}, Expect speed {}, but actual is {}'.format(file, expect_value, actual_speed))
            return False
    return True


def check_cpu_cooling_state(mocker, expect_value):
    actual_value = mocker.get_cpu_cooling_state()
    logging.debug('Expect cpu cooling value is {}, actual value is {}'.format(expect_value, actual_value))
    return actual_value == expect_value
