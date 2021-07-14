import pytest
import random
import time
import logging

# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_component_expecetd_data_dict, get_expecetd_data,\
    verify_response_is_valid, get_expected_hwsku_data, time_taken_by_api

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

class TestFanTray(object):
    """Test Fan Tray"""
    expected_data = None
    LED_COLOR = {0: 'LED_COLOR_INVALID', 1: 'LED_COLOR_NONE', 2: 'LED_COLOR_GREEN', 3: 'LED_COLOR_AMBER',
                 4: 'LED_COLOR_YELLOW', 5: 'LED_COLOR_RED'}
    LED_STATE = {0: 'LED_STATE_INVALID', 1: 'LED_STATE_OFF', 2: 'LED_STATE_ON', 3: 'LED_STATE_BLINK',
                 4: 'LED_STATE_FAST_BLINK'}
    FAN_DIRECTION = {0: 'invalid', 1: 'exhaust', 2: 'intake'}
    if expected_data is None:
        expected_data = get_expecetd_data()

    # Fan Trays helper functions
    @classmethod
    @time_taken_by_api
    def get_fan_tray_nums(cls, stub):
        """Gets number of fan tray on a chassis"""
        req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=0)
        response = stub.GetFanNum(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
        fan_msg = response.fan_nums
        return fan_msg.num_fantrays

    @staticmethod
    def validate_fantray_on_dut(fantray_num, dut):
        """validate dut has fantray"""
        expected_fantray_num = get_expected_hwsku_data(dut, TestFanTray.expected_data, 'num_fantray')
        if fantray_num == 0 and expected_fantray_num == 0:
            logging.info('Dut {} does not have fan trays'.format(dut))
            return False
        if fantray_num != expected_fantray_num:
            pytest.fail('Number of fantray present on dut {} are {}, Expected was {}'
                        .format(dut, fantray_num, expected_fantray_num))

        logging.info('Number of fan tray present on dut {} are {}'.format(dut, fantray_num))
        return True

    @staticmethod
    def get_fantray_grpc_info(dut):
        """Get fan tray platform_ndk info"""
        channel = generate_grpc_channel(dut)
        fan_stub = platform_ndk_pb2_grpc.FanPlatformNdkServiceStub(channel)
        fantrays_info = {
            'channel': channel,
            'fan_stub': fan_stub,
        }
        return fantrays_info

    @staticmethod
    @time_taken_by_api
    def get_fan_tray_status(stub, index):
        """Get Fan Tray status"""

        req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
        response = stub.GetFanStatus(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
        fantray_status = response.fan_status.fantray_status

        logging.info('For Fan tray index {} status is {}'.format(index, fantray_status))
        return fantray_status


def get_numfans_in_tray(stub, index):
    """Gets number of fans in a tray"""
    logging.info('To be done')
    pytest.skip()
    return


@time_taken_by_api
def get_fan_tray_presence(stub, index):
    """Get fan tray presence """
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanPresence(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    presence_msg = response.fan_presence
    presence = presence_msg.fantray_presence
    logging.info('For Fan tray index {} presence status is {}'.format(index, presence))
    return presence


@time_taken_by_api
def get_fan_tray_serial_number(stub, index):
    """Get fan tray presence """
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanTraySerialNo(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    serial_number = response.fan_eeprom.fantray_edata

    logging.info('For Fan tray index {} serial number is {}'.format(index, serial_number))
    return serial_number


@time_taken_by_api
def get_fan_tray_part_number(stub, index):
    """Get fan tray part number"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanTrayPartNo(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    part_number = response.fan_eeprom.fantray_edata

    logging.info('For Fan tray index {} part number is {}'.format(index, part_number))
    return part_number


@time_taken_by_api
def set_fantray_algorithm(stub, disable=0):
    """Set fan tray algorithem to true/false"""
    logging.info('Setting fantray algorithm to {}'.format(disable))
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb()
    req_fan_algo = platform_ndk_pb2.SetFanTrayAlgorithmPb(fantray_algo_disable=disable)
    stub.DisableFanAlgorithm(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx, fan_algo=req_fan_algo))


@time_taken_by_api
def set_fantray_led_color_state(stub, index, color=None, state=None):
    """set fan tray LED color or state"""

    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    if color is not None:
        logging.info('Setting led color of fan tray at index {} to {}'.format(index, color))
        led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color)

    if state is not None:
        logging.info('Setting led state of fan tray at index {} to {}'.format(index, state))
        led_info = platform_ndk_pb2.LedSetInfoPb(led_state=state)

    response = stub.SetFanLedStatus(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx, led_info=led_info))
    return response


@time_taken_by_api
def set_fantray_led_info(stub, index, color, state):
    """Sets fan tray led info"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)

    logging.info('Setting led color {} and led state {} on fan tray at index {}'.format(color, state, index))
    led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color, led_state=state)
    response = stub.SetFanLedStatus(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx, led_info=led_info))

    return response


@time_taken_by_api
def get_fantray_led_color_state(stub, index, info='color'):
    """Get fan tray led color or state"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanLedStatus(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    if info == 'color':
        color_key = response.led_info.led_color
        color = TestFanTray.LED_COLOR.get(color_key)
        return color
    if info == 'state':
        state_key = response.led_info.led_state
        state = TestFanTray.LED_STATE.get(state_key)
        return state


@time_taken_by_api
def get_fantray_led_info(stub, index):
    """Get fan tray led info"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanLedStatus(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))

    color_key = response.led_info.led_color
    logging.info('The color key is {}'.format(color_key))
    color = TestFanTray.LED_COLOR.get(color_key)

    state_key = response.led_info.led_state
    logging.info('The state key is {}'.format(state_key))

    state = TestFanTray.LED_STATE.get(state_key)
    return color, state


@time_taken_by_api
def get_fantray_target_speed(stub, index=None):
    """Get fantray speed"""
    if index:
        req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
        response = stub.GetFanTargetSpeed(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    else:
        response = stub.GetFanTargetSpeed(platform_ndk_pb2.ReqFanTrayOpsPb())

    fantray_speed = response.fan_speed_target.fantray_speed
    return fantray_speed


@time_taken_by_api
def get_fantray_actual_speed(stub, index):
    """Get fantray speed rpm"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanActualSpeed(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    fantray_speed_rpm = response.fan_speed_actual.fantray_speed
    return fantray_speed_rpm


@time_taken_by_api
def get_fantray_tolerance(stub, index):
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanTolerance(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    return response.fan_tolerance


@time_taken_by_api
def get_fan_direction(stub, index):
    """Get fan direction"""
    req_idx = platform_ndk_pb2.ReqFanTrayIndexPb(fantray_idx=index)
    response = stub.GetFanDirection(platform_ndk_pb2.ReqFanTrayOpsPb(idx=req_idx))
    return response.fan_direction


@time_taken_by_api
def set_fantray_speed(stub, speed):
    """Sets fantray speed"""
    logging.info('Setting fan tray speed to {}'.format(speed))
    stub.SetFanTargetSpeed(platform_ndk_pb2.ReqFanTrayOpsPb(fantray_speed=speed))


def compare_actual_and_expected_data(actual_data, expected_data, index, dut, field):
    """Compare actual and expected data"""
    failed = False
    msg = ''
    if actual_data != expected_data:
        msg = 'The Fan tray {} data returned by Api {}, Expected data was {} at {} on dut {}'\
            .format(field, actual_data, expected_data, index, dut)
        failed = True

    logging.info('The Actual fan tray {} is {}, expected: {} at index {} on dut {}'
                 .format(field, actual_data, expected_data, index, dut))
    return failed, msg


# Fan Trays Test Cases
def test_get_fantray_presence(duthosts):
    """Tests the presence of fan tray on chassis"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                expected_fan_presence_data = get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'presence')
                actual_fan_presence_data = get_fan_tray_presence(grpc_info.get('fan_stub'), index)
                failed, msg = compare_actual_and_expected_data(actual_fan_presence_data,
                                                               expected_fan_presence_data, index, dut, 'presence')
                if failed:
                    msg_list.append(msg)

        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_fantray_serial_number(duthosts):
    """ Tests the fantray serial number """
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                expected_fan_data = get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'serial_number')
                if expected_fan_data is None:
                    expected_fan_data = ''
                actual_fan_data = get_fan_tray_serial_number(grpc_info.get('fan_stub'), index)
                failed, msg = compare_actual_and_expected_data(actual_fan_data,
                                                               expected_fan_data, index, dut, 'serial')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_fantray_part_number(duthosts):
    """Tests the fantray serial number """
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                expected_fan_data = get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'part_number')
                if expected_fan_data is None:
                    expected_fan_data = ''
                actual_fan_data = get_fan_tray_part_number(grpc_info.get('fan_stub'), index)
                failed, msg = compare_actual_and_expected_data(actual_fan_data, expected_fan_data,
                                                               index, dut, 'part number')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()

    if len(msg_list):
        pytest.fail(msg_list)


def test_get_fantray_status(duthosts):
    """Tests fantray status"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                expected_fan_data = get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'status')
                if expected_fan_data is None:
                    expected_fan_data = 'Empty'
                actual_fan_data = TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index)
                failed, msg = compare_actual_and_expected_data(actual_fan_data, expected_fan_data, index, dut, 'status')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_get_numfans_in_fantray(duthosts):
    """Test get number os fans in a fantray"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                actual_num_fans = get_numfans_in_tray(grpc_info.get('fan_stub'), index)
                expected_fan_nums = len(get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'fans'))
                failed, msg = compare_actual_and_expected_data(actual_num_fans,
                                                               expected_fan_nums, index, dut, 'num of fans in fantray')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)


def test_initial_fantray_led_color(duthosts):
    """ Test fan led status while fantray is running """
    # fan led status could be off/red/amber/green
    # testhandle = duthosts
    for duthost in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(duthost)
        dut = duthost.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                led_color = None
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    cmd = 'show platform fan'
                    output = duthost.shell(cmd)
                    logging.info('Show platform Fan shows color {} at index {}'.format(output['stdout'], index))
                    led_color = get_fantray_led_color_state(grpc_info.get('fan_stub'), index)
                    if led_color != 'LED_COLOR_GREEN':
                        pytest.fail('Fantray at index {}, LED color is {}, Expected was green'
                                    .format(index, led_color))
                    else:
                        logging.info('Fantray at index {}, LED color is {}'
                                     .format(index, led_color))

        finally:
            grpc_info.get('channel').close()

def test_fantray_led_color(duthosts):
    """ Test fan led status can be set and get"""
    # fan led status could be off/red/amber/green
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                pre_change_led_color = None
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    try:
                        pre_change_led_color = get_fantray_led_color_state(grpc_info.get('fan_stub'), index)
                        set_color = random.choice(list(TestFanTray.LED_COLOR.values()))
                        response = set_fantray_led_color_state(grpc_info.get('fan_stub'), index, color=set_color)
                        if response.response_status.status_code != 0:
                            logging.info('Color is not being set as expected, response is {} at index {}'
                                         .format(response.response_status.status_code, index))
                        else:
                            pytest.fail('Color is being set response is {} at index {}, expected was not set'
                                        .format(response.response_status.status_code, index))

                    finally:
                        set_fantray_led_color_state(grpc_info.get('fan_stub'), index, color=pre_change_led_color)
        finally:
            grpc_info.get('channel').close()


def test_fantray_led_state(duthosts):
    """ Test fantray led state can be set and get"""
    # fan led state invalid/off/on/blink/fast_blink/one_shot/one_shot_retrigger/program
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    pre_change_led_state = None
                    try:
                        pre_change_led_state = get_fantray_led_color_state(
                            grpc_info.get('fan_stub'), index, info='state')
                        set_state = random.choice(list(TestFanTray.LED_STATE.values()))
                        response = set_fantray_led_color_state(grpc_info.get('fan_stub'),
                                                    index, state=set_state)
                        if response.response_status.status_code != 0:
                            logging.info('State is not being set as expected, response is {} at index {}'
                                         .format(response.response_status.status_code, index))
                        else:
                            pytest.fail('State is being set response is {} at index {}, Expected was should not be set'
                                        .format(response.response_status.status_code, index))
                    finally:
                        set_fantray_led_color_state(grpc_info.get('fan_stub'), index,
                                                    state=pre_change_led_state)
        finally:
            grpc_info.get('channel').close()


def test_set_get_fantray_speed(duthosts):
    """ Test set/get fantray speed"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        pre_test_fantray_speed = get_fantray_target_speed(grpc_info.get('fan_stub'))
        set_fantray_algorithm(grpc_info.get('fan_stub'), disable=1)
        min_fan_speed = get_expected_hwsku_data(dut, TestFanTray.expected_data, 'min_fan_speed')
        max_fan_speed = get_expected_hwsku_data(dut, TestFanTray.expected_data, 'max_fan_speed')
        if max_fan_speed == 0:
            pytest.fail('Min/max fan speed is not defined for dut {} in expected_data.json'.format(dut))
        set_speed = random.choice(range(min_fan_speed, max_fan_speed))
        set_fantray_speed(grpc_info.get('fan_stub'), set_speed)
        time.sleep(10)
        try:
            for index in range(fantray_num):
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    fantray_tolerance = get_fantray_tolerance(grpc_info.get('fan_stub'), index)
                    logging.info('Fantray toleranse is {}%'.format(fantray_tolerance))
                    target_speed = get_fantray_target_speed(grpc_info.get('fan_stub'), index)
                    # it should be +- tolerance value
                    if (target_speed < (set_speed - 1)) or (target_speed > (set_speed + 1)):
                        pytest.fail('Target speed {} is not in range of set speed {}'
                                    .format(target_speed, set_speed))

                    logging.info('Target speed {} is in range of set speed {}'
                                 .format(target_speed, set_speed))
                    actual_speed = get_fantray_actual_speed(grpc_info.get('fan_stub'), index)
                    tolerance_range = (set_speed * fantray_tolerance)/100
                    max_actual_speed_with_tolerance = set_speed + tolerance_range
                    min_actual_speed_with_tolerance = set_speed - tolerance_range

                    if not(min_actual_speed_with_tolerance <= actual_speed <= max_actual_speed_with_tolerance):
                        pytest.fail('Fantray speed {} is not within the tolerance range {} {}'
                                    .format(actual_speed, min_actual_speed_with_tolerance,
                                            max_actual_speed_with_tolerance))
                    logging.info('Fan tray speed {} is within the tolerance range {} {}'
                                 .format(actual_speed, min_actual_speed_with_tolerance,
                                         max_actual_speed_with_tolerance))

        finally:
            set_fantray_speed(grpc_info.get('fan_stub'), pre_test_fantray_speed)
            set_fantray_algorithm(grpc_info.get('fan_stub'))
            grpc_info.get('channel').close()


def test_get_fan_direction(duthosts):
    """Tests get fan direction"""
    # testhandle = duthosts
    msg_list = list()
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                actual_fan_direction = get_fan_direction(grpc_info.get('fan_stub'), index)
                expected_fan_direction = get_component_expecetd_data_dict(
                    TestFanTray.expected_data.get(dut), 'fan_trays', index, 'direction')
                failed, msg = compare_actual_and_expected_data(TestFanTray.FAN_DIRECTION.get(actual_fan_direction),
                                                               expected_fan_direction, index, dut, 'fan direction')
                if failed:
                    msg_list.append(msg)
        finally:
            grpc_info.get('channel').close()
    if len(msg_list):
        pytest.fail(msg_list)

def test_fantray_led_info(duthosts):
    """Test set fan tray led color and state combinations"""
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        try:
            for index in range(fantray_num):
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    pre_change_led_info = None
                    try:
                        pre_change_led_info = get_fantray_led_info(grpc_info.get('fan_stub'), index)
                        set_color = random.choice(list(TestFanTray.LED_COLOR.values()))
                        set_state = random.choice(list(TestFanTray.LED_STATE.values()))
                        response = set_fantray_led_info(grpc_info.get('fan_stub'),
                                                        index, color=set_color, state=set_state)
                        verify_response_is_valid(response, set_color, set_state)
                        if response.response_status.status_code == 0:
                            if set_state == 'LED_STATE_OFF':
                                expected_led_info = 'LED_COLOR_NONE', set_state
                            else:
                                expected_led_info = set_color, set_state
                        else:
                            expected_led_info = pre_change_led_info
                        actual_led_info = get_fantray_led_info(grpc_info.get('fan_stub'), index)
                        compare_actual_and_expected_data(actual_led_info, expected_led_info,
                                                         index, dut, 'led color')

                    finally:
                        set_fantray_led_color_state(grpc_info.get('fan_stub'), index,
                                                    color=pre_change_led_info[0], state=pre_change_led_info[1])
        finally:
            grpc_info.get('channel').close()

def test_fantray_speed_is_in_range(duthosts):
    """ Test fantray speed is in range when chassis is running"""
    # testhandle = duthosts
    for dut in duthosts.nodes:
        grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        dut = dut.hostname
        fantray_num = TestFanTray.get_fan_tray_nums(grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut):
            grpc_info.get('channel').close()
            continue
        pre_test_fantray_speed = get_fantray_target_speed(grpc_info.get('fan_stub'))
        try:
            for index in range(fantray_num):
                if TestFanTray.get_fan_tray_status(grpc_info.get('fan_stub'), index) == 'Online':
                    fantray_tolerance = get_fantray_tolerance(grpc_info.get('fan_stub'), index)
                    logging.info('Fantray toleransceis {}%'.format(fantray_tolerance))
                    target_speed = get_fantray_target_speed(grpc_info.get('fan_stub'), index)
                    actual_speed = get_fantray_actual_speed(grpc_info.get('fan_stub'), index)
                    tolerance_range = (target_speed * fantray_tolerance)/100
                    max_actual_speed_with_tolerance = target_speed + tolerance_range
                    min_actual_speed_with_tolerance = target_speed - tolerance_range

                    if not(min_actual_speed_with_tolerance <= actual_speed <= max_actual_speed_with_tolerance):
                        pytest.fail('Fantray speed {} is not within the tolerance range {} {}'
                                    .format(actual_speed, min_actual_speed_with_tolerance,
                                            max_actual_speed_with_tolerance))
                    logging.info('Fan tray speed {} is within the tolerance range {} {}'
                                 .format(actual_speed, min_actual_speed_with_tolerance,
                                         max_actual_speed_with_tolerance))

        finally:
            grpc_info.get('channel').close()
