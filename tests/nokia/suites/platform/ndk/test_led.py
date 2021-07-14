import pytest
import random
import time
import logging
from collections import defaultdict

# from srltest.library import logging

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

import platform_ndk.platform_ndk_pb2 as platform_ndk_pb2
import platform_ndk.platform_ndk_pb2_grpc as platform_ndk_pb2_grpc
from ndk_common import generate_grpc_channel, get_expecetd_data, verify_response_is_valid, time_taken_by_api
from test_fantray import TestFanTray
from test_psu import TestPsu
from test_chassis import TestChassis
from test_sfp import TestSfp

PROTO_LED_COLOR = {0: platform_ndk_pb2.LedColorType.LED_COLOR_INVALID,
                   1: platform_ndk_pb2.LedColorType.LED_COLOR_NONE,
                   2: platform_ndk_pb2.LedColorType.LED_COLOR_GREEN,
                   3: platform_ndk_pb2.LedColorType.LED_COLOR_AMBER,
                   4: platform_ndk_pb2.LedColorType.LED_COLOR_YELLOW,
                   5: platform_ndk_pb2.LedColorType.LED_COLOR_RED}
PROTO_LED_STATE = {0: platform_ndk_pb2.LedStateType.LED_STATE_INVALID,
                   1: platform_ndk_pb2.LedStateType.LED_STATE_OFF,
                   2: platform_ndk_pb2.LedStateType.LED_STATE_ON,
                   3: platform_ndk_pb2.LedStateType.LED_STATE_BLINK,
                   4: platform_ndk_pb2.LedStateType.LED_STATE_FAST_BLINK}


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]

class TestLed(object):
    """Psu service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()


def get_led_grpc_info(dut):
    """Get led platform_ndk info"""
    channel = generate_grpc_channel(dut)
    led_stub = platform_ndk_pb2_grpc.LedPlatformNdkServiceStub(channel)
    led_info = {
        'channel': channel,
        'led_stub': led_stub,
    }
    return led_info


# PSU Helper functions

@time_taken_by_api
def get_fan_led_type_info(stub, start_idx=None, end_idx=None):
    """Get led fantray led color/state"""
    led_info = defaultdict(list)
    fan_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_FANTRAY
    fan_index = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=fan_led_type, led_idx=fan_index))
    if start_idx == end_idx:
        led_info[start_idx].append(TestFanTray.LED_COLOR.get(response.led_get.led_info[0].led_color))
        led_info[start_idx].append(TestFanTray.LED_STATE.get(response.led_get.led_info[0].led_state))
        return led_info

    led_color_state_info = response.led_get.led_info
    for info in led_color_state_info:
        led_info[info.led_idx].append(TestFanTray.LED_COLOR.get(info.led_color))
        led_info[info.led_idx].append(TestFanTray.LED_STATE.get(info.led_state))
    return led_info


def set_fan_led_type_info(stub, color, state, start_idx, end_idx):
    """Set fan led type color and state"""
    fan_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_FANTRAY
    logging.info('Setting FAN LED color to {} and state to {} at index from {} to {}'
                 .format(color, state, start_idx, end_idx))

    led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color, led_state=state)
    led_idx = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.SetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=fan_led_type, led_info=led_info, led_idx=led_idx))
    return response

def get_response_info(response):
    """Get response info"""
    led_color = response.led_get.led_info[0].led_color
    led_state = response.led_get.led_info[0].led_state
    return TestFanTray.LED_COLOR.get(led_color), TestFanTray.LED_STATE.get(led_state)


@time_taken_by_api
def set_led_info(stub, led_type, color, state):
    """Sets led type"""
    led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color, led_state=state)
    response = stub.SetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=led_type, led_info=led_info))
    return response


@time_taken_by_api
def set_fan_master_led_info(stub, color, state):
    """Sets master fan led color and status"""
    fan_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_FAN_STATUS
    logging.info('Setting FAN master LED color to {} and state to {}'
                 .format(color, state))
    return set_led_info(stub, fan_led_type, color, state)


@time_taken_by_api
def get_fan_master_led_info(stub):
    """Gets fan master led info"""
    fan_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_FAN_STATUS
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=fan_led_type))
    return get_response_info(response)


def compare_actual_and_expected_data(actual_data, expected_data, field, dut, index, key=None):
    """Compare actual and expected data"""
    if actual_data != expected_data:
        pytest.fail('Actual data returned by {} API for {} on {} is {}, Expected was {}'
                    .format(field, index, dut, actual_data, expected_data))

    logging.info('Actual data returned by {} API for {} on {} is {} same as Expected {}'
                 .format(field, index, dut, actual_data, expected_data))


def get_random_color_state():
    """Get random color and state"""
    set_color = random.choice(list(PROTO_LED_COLOR.values()))
    set_state = random.choice(list(PROTO_LED_STATE.values()))
    return TestFanTray.LED_COLOR.get(set_color), TestFanTray.LED_STATE.get(set_state)


@time_taken_by_api
def set_psu_master_led_info(stub, color, state):
    """Sets master psu led color and status"""
    psu_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_PSU_STATUS
    logging.info('Setting PSU master LED color to {} and state to {}'
                 .format(color, state))
    return set_led_info(stub, psu_led_type, color, state)


@time_taken_by_api
def get_psu_master_led_info(stub):
    """Gets fan master led info"""
    psu_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_PSU_STATUS
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=psu_led_type))
    return get_response_info(response)


@time_taken_by_api
def set_board_led_info(stub, color, state):
    """Sets board led info"""
    board_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_BOARD_STATUS
    logging.info('Setting board LED color to {} and state to {}'
                 .format(color, state))
    return set_led_info(stub, board_led_type, color, state)


@time_taken_by_api
def get_board_led_info(stub):
    """Get board led info"""
    board_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_BOARD_STATUS
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=board_led_type))
    return get_response_info(response)


@time_taken_by_api
def set_master_sfm_led_info(stub, color, state):
    """Sets sfm master led info"""
    sfm_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_SFM_STATUS
    logging.info('Setting sfm master LED color to {} and state to {}'
                 .format(color, state))
    return set_led_info(stub, sfm_led_type, color, state)


@time_taken_by_api
def get_master_sfm_led_info(stub):
    """Get sfm master led info"""
    sfm_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_MASTER_SFM_STATUS
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=sfm_led_type))
    return get_response_info(response)


@time_taken_by_api
def get_sfm_led_info(stub, start_idx, end_idx):
    """Get led fantray led color/state"""
    led_info = defaultdict(list)
    sfm_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_SFM
    sfm_index = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=sfm_led_type, led_idx=sfm_index))
    if start_idx == end_idx:
        led_info[start_idx].append(TestFanTray.LED_COLOR.get(response.led_get.led_info[0].led_color))
        led_info[start_idx].append(TestFanTray.LED_STATE.get(response.led_get.led_info[0].led_state))
        return led_info

    info = response.led_get.led_info
    for i in range(start_idx, end_idx+1):
        led_info[i].append(TestFanTray.LED_COLOR.get(info[i].led_color))
        led_info[i].append(TestFanTray.LED_STATE.get(info[i].led_state))
    return led_info


@time_taken_by_api
def set_sfm_led_info(stub, color, state, start_idx, end_idx):
    """Set sfm led type color and state"""
    sfm_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_SFM
    logging.info('Setting SFM LED color to {} and state to {} at index from {} to {}'
                 .format(color, state, start_idx, end_idx))

    led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color, led_state=state)
    led_idx = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.SetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=sfm_led_type, led_info=led_info, led_idx=led_idx))
    return response


def set_port_led_info(stub, color, state, start_idx, end_idx):
    """Set port led type color and state"""
    port_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_PORT
    logging.info('Setting PORT LED color to {} and state to {} at index from {} to {}'
                 .format(color, state, start_idx, end_idx))

    led_info = platform_ndk_pb2.LedSetInfoPb(led_color=color, led_state=state)
    led_idx = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.SetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=port_led_type, led_info=led_info, led_idx=led_idx))
    return response


@time_taken_by_api
def get_port_led_info(stub, start_idx, end_idx):
    """Get port led color/state"""
    led_info = defaultdict(list)
    port_led_type = platform_ndk_pb2.ReqLedType.LED_TYPE_PORT
    port_index = platform_ndk_pb2.ReqLedIndexPb(start_idx=start_idx, end_idx=end_idx)
    response = stub.GetLed(platform_ndk_pb2.ReqLedInfoPb(led_type=port_led_type, led_idx=port_index))
    if start_idx == end_idx:
        led_info[start_idx].append(TestFanTray.LED_COLOR.get(response.led_get.led_info[0].led_color))
        led_info[start_idx].append(TestFanTray.LED_STATE.get(response.led_get.led_info[0].led_state))
        return led_info

    info = response.led_get.led_info
    for i in range(start_idx, end_idx+1):
        led_info[i].append(TestFanTray.LED_COLOR.get(info[i].led_color))
        led_info[i].append(TestFanTray.LED_STATE.get(info[i].led_state))
    return led_info


def get_expected_led_info_list(response, color, state, pretest_info, index):
    """Get expected led info"""
    expected_led_type_info = list()
    if response.response_status.status_code == 0:
        if state == 'LED_STATE_OFF':
            expected_led_type_info.append('LED_COLOR_NONE')
            expected_led_type_info.append(state)
        else:
            expected_led_type_info.append(color)
            expected_led_type_info.append(state)
    else:
        expected_led_type_info = pretest_info[index]

    return expected_led_type_info


def get_expected_led_info(response, color, state, pretest_info):
    if response.response_status.status_code == 0:
        if state == 'LED_STATE_OFF':
            expected_led_type_info = 'LED_COLOR_NONE', state
        else:
            expected_led_type_info = color, state
    else:
        expected_led_type_info = pretest_info

    return expected_led_type_info


def test_set_get_fantray_led_type_info(duthosts):
    """Test set/get fantray led color info"""
    for dut in duthosts.nodes:
        fan_grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        fantray_num = TestFanTray.get_fan_tray_nums(fan_grpc_info.get('fan_stub'))
        led_grpc_info = get_led_grpc_info(dut)
        try:
            for index in range(fantray_num):
                if TestFanTray.get_fan_tray_status(fan_grpc_info.get('fan_stub'), index) == 'Online':
                    pretest_fan_led_info = None
                    try:
                        pretest_fan_led_info = get_fan_led_type_info(led_grpc_info.get('led_stub'),
                                                                     start_idx=index, end_idx=index)
                        logging.info('pre test fan led info {}'.format(pretest_fan_led_info[index]))

                        set_color, set_state = get_random_color_state()
                        response = set_fan_led_type_info(led_grpc_info.get('led_stub'),
                                                         set_color, set_state, index, index)
                        actual_fan_led_type_info = get_fan_led_type_info(led_grpc_info.get('led_stub'),
                                                                     start_idx=index, end_idx=index)
                        verify_response_is_valid(response, set_color, set_state)
                        expected_fan_led_type_info = get_expected_led_info_list(response, set_color, set_state,
                                                                           pretest_fan_led_info, index)
                        compare_actual_and_expected_data(actual_fan_led_type_info[index], expected_fan_led_type_info,
                                                         'FAN LED TYPE', dut.hostname, index)

                    finally:
                        set_fan_led_type_info(led_grpc_info.get('led_stub'),
                                              pretest_fan_led_info[index][0],
                                              pretest_fan_led_info[index][1], index, index)

        finally:
            fan_grpc_info.get('channel').close()
            led_grpc_info.get('channel').close()


def test_set_get_fantray_led_multi_index_info(duthosts):
    """Test set/get fantray info on multi index in one request """
    for dut in duthosts.nodes:
        fan_grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        fantray_num = TestFanTray.get_fan_tray_nums(fan_grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut.hostname):
            fan_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_fan_led_info = None
        try:
            pretest_fan_led_info = get_fan_led_type_info(led_grpc_info.get('led_stub'),
                                                         start_idx=0, end_idx=fantray_num-1)
            logging.info('pre test fan led info {}'.format(pretest_fan_led_info))
            set_color, set_state = get_random_color_state()
            response = set_fan_led_type_info(led_grpc_info.get('led_stub'),set_color,
                                             set_state, 0, fantray_num-1)
            verify_response_is_valid(response, set_color, set_state)
            actual_fan_led_type_info = get_fan_led_type_info(led_grpc_info.get('led_stub'),
                                                             start_idx=0, end_idx=fantray_num-1)
            for index in range(fantray_num):
                expected_fan_led_type_info = get_expected_led_info_list(response, set_color,
                                                                        set_state, pretest_fan_led_info, index)
                compare_actual_and_expected_data(actual_fan_led_type_info[index], expected_fan_led_type_info,
                                                 'FAN LED TYPE', dut.hostname, index)
        finally:
            for index, info in pretest_fan_led_info.items():
                if info is not None:
                    set_fan_led_type_info(led_grpc_info.get('led_stub'),
                                          info[0], info[1], index, index)
            fan_grpc_info.get('channel').close()
            led_grpc_info.get('channel').close()


def test_master_fan_led_status(duthosts):
    """Test master fan led status"""
    for dut in duthosts.nodes:
        fan_grpc_info = TestFanTray.get_fantray_grpc_info(dut)
        fantray_num = TestFanTray.get_fan_tray_nums(fan_grpc_info.get('fan_stub'))
        if not TestFanTray.validate_fantray_on_dut(fantray_num, dut.hostname):
            fan_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_fan_master_led_info = None
        try:
            pretest_fan_master_led_info = get_fan_master_led_info(led_grpc_info.get('led_stub'))
            logging.info('Pre test fan master led info {}'.format(pretest_fan_master_led_info))
            set_color, set_state = get_random_color_state()
            response = set_fan_master_led_info(led_grpc_info.get('led_stub'), set_color, set_state)
            verify_response_is_valid(response, set_color, set_state)
            actual_fan_master_led_info = get_fan_master_led_info(led_grpc_info.get('led_stub'))
            expected_fan_led_type_info = get_expected_led_info(response, set_color,
                                                               set_state, pretest_fan_master_led_info)
            compare_actual_and_expected_data(actual_fan_master_led_info, expected_fan_led_type_info,
                                             'FAN MASTER LED TYPE', dut.hostname, 0)
        finally:
            set_fan_master_led_info(led_grpc_info.get('led_stub'), pretest_fan_master_led_info[0],
                                    pretest_fan_master_led_info[1])
            fan_grpc_info.get('channel').close()
            led_grpc_info.get('channel').close()


def test_master_psu_led_status(duthosts):
    """Test master psu led status"""
    for dut in duthosts.nodes:
        psu_grpc_info = TestPsu.get_psu_grpc_info(dut)
        psu_num = TestPsu.get_psu_num(psu_grpc_info.get('psu_stub'))
        if not TestPsu.validate_psu_on_dut(psu_num, dut.hostname):
            psu_grpc_info.get('channel').close()
            continue
        psu_grpc_info.get('channel').close()
        led_grpc_info = get_led_grpc_info(dut)
        pretest_psu_master_led_info = None
        try:
            pretest_psu_master_led_info = get_psu_master_led_info(led_grpc_info.get('led_stub'))
            logging.info('Pre test psu master led info {}'.format(pretest_psu_master_led_info))
            set_color, set_state = get_random_color_state()
            response = set_psu_master_led_info(led_grpc_info.get('led_stub'), set_color, set_state)
            verify_response_is_valid(response, set_color, set_state)
            actual_psu_master_led_info = get_psu_master_led_info(led_grpc_info.get('led_stub'))
            expected_psu_led_type_info = get_expected_led_info(response, set_color,
                                                               set_state, pretest_psu_master_led_info)

            compare_actual_and_expected_data(actual_psu_master_led_info, expected_psu_led_type_info,
                                             'PSU MASTER LED TYPE', dut.hostname, 0)
        finally:
            set_psu_master_led_info(led_grpc_info.get('led_stub'), pretest_psu_master_led_info[0],
                                    pretest_psu_master_led_info[1])
            led_grpc_info.get('channel').close()


def test_board_led_status(duthosts):
    """Test board led status"""
    for dut in duthosts.nodes:
        led_grpc_info = get_led_grpc_info(dut)
        pretest_board_led_info = None
        try:
            pretest_board_led_info = get_board_led_info(led_grpc_info.get('led_stub'))
            logging.info('Pre test board led info {}'.format(pretest_board_led_info))
            set_color, set_state = get_random_color_state()

            response = set_board_led_info(led_grpc_info.get('led_stub'), set_color, set_state)
            verify_response_is_valid(response, set_color, set_state)
            actual_board_led_info = get_board_led_info(led_grpc_info.get('led_stub'))
            expected_board_led_info = get_expected_led_info(response, set_color, set_state, pretest_board_led_info)
            compare_actual_and_expected_data(actual_board_led_info, expected_board_led_info,
                                             'BOARD LED TYPE', dut.hostname, 0)
        finally:
            set_board_led_info(led_grpc_info.get('led_stub'), pretest_board_led_info[0], pretest_board_led_info[1])
            led_grpc_info.get('channel').close()


def test_sfm_master_led_status(duthosts):
    """Tests SFM led status"""
    for dut in duthosts.nodes:
        logging.info('Running test case on dut {}'.format(dut.hostname))
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        sfm_num = TestChassis.get_num_of_sfm(chassis_grpc_info.get('chassis_stub'))
        if sfm_num is None:
            chassis_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_sfm_master_led_info = None
        try:
            pretest_sfm_master_led_info = get_master_sfm_led_info(led_grpc_info.get('led_stub'))
            logging.info('Pre test board sfm master led info {}'.format(pretest_sfm_master_led_info))
            set_color, set_state = get_random_color_state()

            response = set_master_sfm_led_info(led_grpc_info.get('led_stub'), set_color, set_state)
            verify_response_is_valid(response, set_color, set_state)
            actual_sfm_master_led_info = get_master_sfm_led_info(led_grpc_info.get('led_stub'))
            expected_sfm_master_led_info = get_expected_led_info(response, set_color,
                                                                 set_state, pretest_sfm_master_led_info)
            compare_actual_and_expected_data(actual_sfm_master_led_info, expected_sfm_master_led_info,
                                             'SFM MASTER LED TYPE', dut.hostname, 0)
        finally:
            set_master_sfm_led_info(led_grpc_info.get('led_stub'), pretest_sfm_master_led_info[0],
                                    pretest_sfm_master_led_info[1])
            led_grpc_info.get('channel').close()
            chassis_grpc_info.get('channel').close()


def test_sfm_led_info(duthosts):
    """Test set/get sfm led info"""
    for dut in duthosts.nodes:
        logging.info('Running test case on dut {}'.format(dut.hostname))
        chassis_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        sfm_num = TestChassis.get_num_of_sfm(chassis_grpc_info.get('chassis_stub'))
        if sfm_num is None:
            chassis_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        try:
            for index in range(sfm_num):
                pretest_sfm_led_info = None
                try:
                    pretest_sfm_led_info = get_sfm_led_info(led_grpc_info.get('led_stub'),
                                                                 index, index)
                    logging.info('pre test sfm led info {}'.format(pretest_sfm_led_info[index]))

                    set_color, set_state = get_random_color_state()
                    response = set_sfm_led_info(led_grpc_info.get('led_stub'), set_color, set_state, index, index)
                    actual_sfm_led_type_info = get_sfm_led_info(led_grpc_info.get('led_stub'), index, index)
                    verify_response_is_valid(response, set_color, set_state)
                    expected_sfm_led_type_info = get_expected_led_info_list(response, set_color,
                                                                       set_state, pretest_sfm_led_info, index)
                    compare_actual_and_expected_data(actual_sfm_led_type_info[index], expected_sfm_led_type_info,
                                                     'SFM LED TYPE', dut.hostname, index)

                finally:
                    set_sfm_led_info(led_grpc_info.get('led_stub'), pretest_sfm_led_info[index][0],
                                     pretest_sfm_led_info[index][1], index, index)

        finally:
            chassis_grpc_info.get('channel').close()
            led_grpc_info.get('channel').close()


def test_multi_index_sfm_led_info(duthosts):
    """Test set/get sfm info on multi index in one request """
    for dut in duthosts.nodes:
        logging.info('Running test case on dut {}'.format(dut.hostname))
        sfm_grpc_info = TestChassis.get_chassis_grpc_info(dut)
        sfm_num = TestChassis.get_num_of_sfm(sfm_grpc_info.get('chassis_stub'))
        if sfm_num is None:
            sfm_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_sfm_led_info = None
        try:
            pretest_sfm_led_info = get_sfm_led_info(led_grpc_info.get('led_stub'),
                                                    start_idx=0, end_idx=sfm_num-1)
            logging.info('pre test sfm led info {}'.format(pretest_sfm_led_info))

            set_color, set_state = get_random_color_state()

            response = set_sfm_led_info(led_grpc_info.get('led_stub'), set_color,
                                        set_state, 0, sfm_num-1)
            verify_response_is_valid(response, set_color, set_state)
            actual_sfm_led_type_info = get_sfm_led_info(led_grpc_info.get('led_stub'),
                                                        start_idx=0, end_idx=sfm_num-1)

            for index in range(sfm_num):
                expected_sfm_led_type_info = get_expected_led_info_list(response, set_color, set_state, pretest_sfm_led_info, index)
                compare_actual_and_expected_data(actual_sfm_led_type_info[index], expected_sfm_led_type_info,
                                                 'SFM LED TYPE', dut.hostname, index)
        finally:
            for index in range(sfm_num):
                set_sfm_led_info(led_grpc_info.get('led_stub'), pretest_sfm_led_info[index][0],
                                 pretest_sfm_led_info[index][1], index, index)
            led_grpc_info.get('channel').close()
            sfm_grpc_info.get('channel').close()


def test_port_led_info(duthosts):
    """Test set/get port led info"""
    for dut in duthosts.nodes:
        logging.info('Running test case on dut {}'.format(dut.hostname))
        port_grpc_info = TestSfp.get_sfp_grpc_info(dut)
        port_num = TestSfp.get_num_of_sfp(port_grpc_info.get('sfp_stub'))
        if port_num == 0:
            port_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_port_led_info = None
        try:
            for index in range(port_num):
                try:
                    pretest_port_led_info = get_port_led_info(led_grpc_info.get('led_stub'),
                                                              start_idx=index, end_idx=index)
                    logging.info('pre test port led info {}'.format(pretest_port_led_info[index]))

                    set_color, set_state = get_random_color_state()
                    response = set_port_led_info(led_grpc_info.get('led_stub'), set_color, set_state, index, index)
                    actual_port_led_type_info = get_port_led_info(led_grpc_info.get('led_stub'), index, index)
                    verify_response_is_valid(response, set_color, set_state)
                    expected_port_led_type_info = get_expected_led_info_list(response, set_color, set_state,
                                                                             pretest_port_led_info, index)
                    compare_actual_and_expected_data(actual_port_led_type_info[index], expected_port_led_type_info,
                                                     'SFM LED TYPE', dut.hostname, index)

                finally:
                    set_port_led_info(led_grpc_info.get('led_stub'), pretest_port_led_info[index][0],
                                      pretest_port_led_info[index][1], index, index)

        finally:
            port_grpc_info.get('channel').close()
            led_grpc_info.get('channel').close()


def test_multi_index_port_led_info(duthosts):
    """Test set/get port info on multi index in one request """
    for dut in duthosts.nodes:
        logging.info('Running test case on dut {}'.format(dut.hostname))
        port_grpc_info = TestSfp.get_sfp_grpc_info(dut)
        port_num = TestSfp.get_num_of_sfp(port_grpc_info.get('sfp_stub'))
        if port_num == 0:
            port_grpc_info.get('channel').close()
            continue
        led_grpc_info = get_led_grpc_info(dut)
        pretest_port_led_info = None
        try:
            pretest_port_led_info = get_port_led_info(led_grpc_info.get('led_stub'),
                                                         start_idx=0, end_idx=port_num-1)
            logging.info('pre test port led info {}'.format(pretest_port_led_info))
            set_color, set_state = get_random_color_state()
            response = set_port_led_info(led_grpc_info.get('led_stub'), set_color,
                                             set_state, 0, port_num-1)
            verify_response_is_valid(response, set_color, set_state)
            actual_port_led_type_info = get_port_led_info(led_grpc_info.get('led_stub'),
                                                         start_idx=0, end_idx=port_num-1)
            for index in range(port_num):
                expected_port_led_type_info = get_expected_led_info_list(response, set_color, set_state,
                                                                    pretest_port_led_info, index)

                compare_actual_and_expected_data(actual_port_led_type_info[index], expected_port_led_type_info,
                                                 'PORT LED TYPE', dut.hostname, index)

        finally:
            for index in range(port_num):
                set_port_led_info(led_grpc_info.get('led_stub'), pretest_port_led_info[index][0],
                                 pretest_port_led_info[index][1], index, index)
            led_grpc_info.get('channel').close()
            port_grpc_info.get('channel').close()
