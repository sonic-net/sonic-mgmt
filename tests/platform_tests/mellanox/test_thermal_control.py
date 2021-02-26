import logging
import operator
import pytest
import random
from tests.common.mellanox_data import get_platform_data
from tests.common.utilities import wait_until
from tests.platform_tests.thermal_control_test_helper import *
from mellanox_thermal_control_test_helper import MockerHelper, AbnormalFanMocker
from tabulate import tabulate
import re

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

THERMAL_CONTROL_TEST_WAIT_TIME = 75
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5

COOLING_CUR_STATE_PATH = '/run/hw-management/thermal/cooling_cur_state'
COOLING_CUR_STATE_THRESHOLD = 7
PSU_PRESENCE_PATH = '/run/hw-management/thermal/psu{}_status'
PSU_SPEED_PATH = '/run/hw-management/thermal/psu{}_fan1_speed_get'
PSU_MAX_SPEED_PATH = '/run/hw-management/config/psu_fan_max'
PSU_SPEED_TOLERANCE = 0.25

MAX_COOLING_LEVEL = 10


@pytest.mark.disable_loganalyzer
def test_dynamic_minimum_table(duthosts, rand_one_dut_hostname, mocker_factory):
    duthost = duthosts[rand_one_dut_hostname]
    max_temperature = 45000 # 45 C
    cooling_cur_state = get_cooling_cur_state(duthost)
    if cooling_cur_state >= COOLING_CUR_STATE_THRESHOLD:
        pytest.skip('The cooling level {} is higher than threshold {}.'.format(cooling_cur_state, COOLING_CUR_STATE_THRESHOLD))

    mocker = mocker_factory(duthost, 'MinTableMocker')

    temperature = random.randint(0, max_temperature)
    trust_state = True if random.randint(0, 1) else False
    logger.info('Testing with temperature={}, trust_state={}'.format(temperature, trust_state))
    expect_minimum_cooling_level = mocker.get_expect_cooling_level(temperature, trust_state)
    logger.info('Expect minimum cooling level is {}'.format(expect_minimum_cooling_level))
    mocker.mock_min_table(temperature, trust_state)
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                      THERMAL_CONTROL_TEST_CHECK_INTERVAL,
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
                      check_cooling_level_larger_than_minimum, 
                      duthost,
                      expect_minimum_cooling_level), \
                      'Cooling level is less than minimum allowed {}'.format(expect_minimum_cooling_level)



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
                      check_psu_fan_speed, 
                      duthost, 
                      psu_num, 
                      psu_max_speed, 
                      operator.eq), 'Wait for PSU fan speed change to full speed failed'

    logger.info('Mock FAN presence...')
    single_fan_mocker.mock_presence()
    wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME * 2, 
                             THERMAL_CONTROL_TEST_CHECK_INTERVAL, 
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
