import logging
import operator
import pytest
import random
import time
from tests.common.mellanox_data import get_platform_data
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until
from tests.platform_tests.thermal_control_test_helper import *
from mellanox_thermal_control_test_helper import MockerHelper, AbnormalFanMocker

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any')
]

THERMAL_CONTROL_TEST_WAIT_TIME = 65
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5

COOLING_CUR_STATE_PATH = '/run/hw-management/thermal/cooling_cur_state'
COOLING_CUR_STATE_THRESHOLD = 7
PSU_PRESENCE_PATH = '/run/hw-management/thermal/psu{}_status'
PSU_SPEED_PATH = '/run/hw-management/thermal/psu{}_fan1_speed_get'
PSU_SPEED_TOLERANCE = 0.25

LOG_EXPECT_CHANGE_MIN_COOLING_LEVEL_RE = '.*Changed minimum cooling level to {}.*'


@pytest.mark.disable_loganalyzer
def test_dynamic_minimum_table(duthost, mocker_factory):
    air_flow_dirs = ['p2c', 'c2p', 'unk']
    max_temperature = 45000 # 45 C
    cooling_cur_state = get_cooling_cur_state(duthost)
    if cooling_cur_state >= COOLING_CUR_STATE_THRESHOLD:
        pytest.skip('The cooling level {} is higher than threshold {}.'.format(cooling_cur_state, COOLING_CUR_STATE_THRESHOLD))

    mocker = mocker_factory(duthost, 'MinTableMocker')
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    loganalyzer.load_common_config()

    for index in range(len(air_flow_dirs)):
        air_flow_index = random.randint(0, len(air_flow_dirs) - 1)
        air_flow_dir = air_flow_dirs[air_flow_index]
        air_flow_dirs.remove(air_flow_dir)
        temperature = random.randint(0, max_temperature)
        trust_state = True if random.randint(0, 1) else False
        logging.info('Testing with air_flow_dir={}, temperature={}, trust_state={}'.format(air_flow_dir, temperature, trust_state))
        expect_minimum_cooling_level = mocker.get_expect_cooling_level(air_flow_dir, temperature, trust_state)
        loganalyzer.expect_regex = [LOG_EXPECT_CHANGE_MIN_COOLING_LEVEL_RE.format(expect_minimum_cooling_level)]
        with loganalyzer:
            mocker.mock_min_table(air_flow_dir, temperature, trust_state)
            time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)

        temperature = random.randint(0, max_temperature)
        logging.info('Testing with air_flow_dir={}, temperature={}, trust_state={}'.format(air_flow_dir, temperature, not trust_state))
        expect_minimum_cooling_level = mocker.get_expect_cooling_level(air_flow_dir, temperature, not trust_state)
        loganalyzer.expect_regex = [LOG_EXPECT_CHANGE_MIN_COOLING_LEVEL_RE.format(expect_minimum_cooling_level)]
        with loganalyzer:
            mocker.mock_min_table(air_flow_dir, temperature, not trust_state)
            time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)


@pytest.mark.disable_loganalyzer
def test_set_psu_fan_speed(duthost, mocker_factory):
    platform_data = get_platform_data(duthost)
    psu_num = platform_data['psus']['number']
    hot_swappable = platform_data['psus']['hot_swappable']
    if not hot_swappable:
        pytest.skip('The platform {} does not support this test case.'.format(duthost.facts["platform"]))

    logging.info('Create mocker, it may take a few seconds...')
    single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
    logging.info('Mock FAN absence...')
    single_fan_mocker.mock_absence()
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, check_cooling_cur_state, duthost, 10, operator.eq), \
        'Current cooling state is {}'.format(get_cooling_cur_state(duthost))

    logging.info('Wait {} seconds for the policy to take effect...'.format(THERMAL_CONTROL_TEST_CHECK_INTERVAL))
    time.sleep(THERMAL_CONTROL_TEST_CHECK_INTERVAL)
    full_speeds = []
    for index in range(psu_num):
        speed = get_psu_speed(duthost, index)
        full_speeds.append(speed)

    logging.info('Full speed={}'.format(full_speeds))
    logging.info('Mock FAN presence...')
    single_fan_mocker.mock_presence()
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, check_cooling_cur_state, duthost, 10, operator.ne), \
        'Current cooling state is {}'.format(get_cooling_cur_state(duthost))
    logging.info('Wait {} seconds for the policy to take effect...'.format(THERMAL_CONTROL_TEST_CHECK_INTERVAL))
    time.sleep(THERMAL_CONTROL_TEST_CHECK_INTERVAL)
    cooling_cur_state = get_cooling_cur_state(duthost)
    logging.info('Cooling level changed to {}'.format(cooling_cur_state))
    current_speeds = []
    for index in range(psu_num):
        speed = get_psu_speed(duthost, index)
        current_speeds.append(speed)

    logging.info('Current speed={}'.format(current_speeds))
    index = 0
    if cooling_cur_state < 6:
        cooling_cur_state = 6
    expect_multiple = float(10) / cooling_cur_state
    while index < psu_num:
        full_speed = full_speeds[index]
        current_speed = current_speeds[index]
        index += 1
        if not full_speed or not current_speed:
            continue

        actual_multiple = float(full_speed) / current_speed
        if expect_multiple > actual_multiple:
            assert actual_multiple > expect_multiple * (1 - PSU_SPEED_TOLERANCE)
        elif expect_multiple < actual_multiple:
            assert actual_multiple < expect_multiple * (1 + PSU_SPEED_TOLERANCE)


def get_psu_speed(dut, index):
    index = index + 1
    psu_speed_path = PSU_SPEED_PATH.format(index)
    file_exists = dut.stat(path=psu_speed_path)
    if not file_exists:
        return None

    cmd_output = dut.command('cat {}'.format(psu_speed_path))
    try:
        return int(cmd_output['stdout'])
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(psu_speed_path, e)


def get_cooling_cur_state(dut):
    cmd_output = dut.command('cat {}'.format(COOLING_CUR_STATE_PATH))
    try:
        return int(cmd_output['stdout'])
    except Exception as e:
        assert False, 'Bad content in {} - {}'.format(COOLING_CUR_STATE_PATH, e)


def check_cooling_cur_state(dut, expect_value, op):
    actual_value = get_cooling_cur_state(dut)
    return op(actual_value, expect_value)
