import logging
import operator
import pytest
import random
import time
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
    logging.info('Testing with temperature={}, trust_state={}'.format(temperature, trust_state))
    expect_minimum_cooling_level = mocker.get_expect_cooling_level(temperature, trust_state)
    mocker.mock_min_table(temperature, trust_state)
    time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)
    actual_cooling_level = get_cooling_cur_state(duthost)
    assert actual_cooling_level >= expect_minimum_cooling_level, 'Cooling level {} is less than minimum allowed {}'.format(actual_cooling_level, expect_minimum_cooling_level)

    temperature = random.randint(0, max_temperature)
    logging.info('Testing with temperature={}, trust_state={}'.format(temperature, not trust_state))
    expect_minimum_cooling_level = mocker.get_expect_cooling_level(temperature, not trust_state)
    mocker.mock_min_table(temperature, not trust_state)
    time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)
    actual_cooling_level = get_cooling_cur_state(duthost)
    assert actual_cooling_level >= expect_minimum_cooling_level, 'Cooling level {} is less than minimum allowed {}'.format(actual_cooling_level, expect_minimum_cooling_level)


@pytest.mark.disable_loganalyzer
def test_set_psu_fan_speed(duthosts, rand_one_dut_hostname, mocker_factory):
    duthost = duthosts[rand_one_dut_hostname]
    platform_data = get_platform_data(duthost)
    psu_num = platform_data['psus']['number']
    hot_swappable = platform_data['psus']['hot_swappable']
    if not hot_swappable:
        pytest.skip('The platform {} does not support this test case.'.format(duthost.facts["platform"]))

    logging.info('Create mocker, it may take a few seconds...')
    single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
    logging.info('Mock FAN absence...')
    single_fan_mocker.mock_absence()
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, check_cooling_cur_state, duthost, MAX_COOLING_LEVEL, operator.eq), \
        'Current cooling state is {}'.format(get_cooling_cur_state(duthost))

    logging.info('Wait {} seconds for the policy to take effect...'.format(THERMAL_CONTROL_TEST_WAIT_TIME))
    time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)
    psu_max_speed = get_psu_max_speed(duthost)
    logging.info('Max PSU fan speed is {}'.format(psu_max_speed))
    for index in range(psu_num):
        speed = get_psu_speed(duthost, index)
        logging.info('Speed for PSU {} fan is {}'.format(index, speed))
        _check_psu_fan_speed_in_range(speed, psu_max_speed, MAX_COOLING_LEVEL)

    logging.info('Mock FAN presence...')
    single_fan_mocker.mock_presence()
    wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, check_cooling_cur_state, duthost, MAX_COOLING_LEVEL, operator.ne)
    logging.info('Wait {} seconds for the policy to take effect...'.format(THERMAL_CONTROL_TEST_WAIT_TIME * 2))
    # We have to wait THERMAL_CONTROL_TEST_WAIT_TIME * 2 seconds long here because:
    #     Usually we only need wait THERMAL_CONTROL_TEST_WAIT_TIME seconds here to make sure thermal
    #     control daemon change the cooling level to proper value, However,
    #     there is chance that kernel might change cooling state back to MAX_COOLING_LEVEL after
    #     user space thermal control adjust it to dynamic minimum value. So we have to wait longer for the
    #     user space thermal control to set fan speed to dynamic minimum value again. It
    #     means that we might need wait up to 2 thermal loops here.
    time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME * 2)
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
    logging.info('Cooling level changed to {}'.format(cooling_cur_state))
    if cooling_cur_state < 6: # PSU fan speed will never be less than 60%
        cooling_cur_state = 6
    for index in range(psu_num):
        speed = get_psu_speed(duthost, index)
        logging.info('Speed for PSU {} fan is {}'.format(index, speed))
        _check_psu_fan_speed_in_range(speed, psu_max_speed, cooling_cur_state)


def _check_psu_fan_speed_in_range(actual_speed, max_speed, cooling_level):
    expect_speed = max_speed * cooling_level / 10.0
    if expect_speed > actual_speed:
        assert actual_speed > expect_speed * (1 - PSU_SPEED_TOLERANCE)
    elif expect_speed < actual_speed:
        assert actual_speed < expect_speed * (1 + PSU_SPEED_TOLERANCE)


def get_psu_speed(dut, index):
    index = index + 1
    psu_speed_path = PSU_SPEED_PATH.format(index)
    file_stat = dut.stat(path=psu_speed_path)
    if not file_stat["stat"]["exists"]:
        return None

    cmd_output = dut.command('cat {}'.format(psu_speed_path))
    try:
        return int(cmd_output['stdout'])
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(psu_speed_path, e)


def get_psu_max_speed(dut):
    cmd_output = dut.command('cat {}'.format(PSU_MAX_SPEED_PATH))
    try:
        return int(cmd_output['stdout'])
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(PSU_MAX_SPEED_PATH, e)


def get_cooling_cur_state(dut):
    cmd_output = dut.command('cat {}'.format(COOLING_CUR_STATE_PATH))
    try:
        return int(cmd_output['stdout'])
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(COOLING_CUR_STATE_PATH, e)


def check_cooling_cur_state(dut, expect_value, op):
    actual_value = get_cooling_cur_state(dut)
    return op(actual_value, expect_value)
