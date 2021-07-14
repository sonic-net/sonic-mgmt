import pytest
import grpc
import os
import json
import logging
import time

pytestmark_config_check = pytest.mark.srl_skip_config_check
pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
pytestmark = pytest.mark.register(level='regular', owner='falodiya')

GRPC_PORT = '50065'
# EXPECTED_DATA = 'expected_data.json'
# FOLDER = 'test/srltest/suites/platform/ndk/'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
EXPECTED_DATA_FILE = os.path.join(BASE_DIR, 'expected_data.json')
NDK_RESPONSE = {0: "NDK_SUCCESS", 1:"NDK_ERR_FAILURE", 2: "NDK_ERR_INVALID_REQ", 3:"NDK_ERR_RESOURCE_NOT_FOUND"}

def get_dut_ip(dut):
    """Get dut ip"""
    return dut.mgmt_ip


def generate_grpc_channel(dut):
    """Generates GRPC Channel"""
    dut_ip = get_dut_ip(dut)
    server_path = '{}:{}'.format(dut_ip, GRPC_PORT)
    channel = grpc.insecure_channel(server_path)
    channel_ready = grpc.channel_ready_future(channel)
    try:
        channel_ready.result(timeout=1.5)
    except grpc.FutureTimeoutError:
        pytest.fail('GRPC channel could not be established')

    return channel


def get_component_expecetd_data_dict(dut_vars, component, index, field):
    component_expected_data = None
    if dut_vars.get(component) is not None:
        for dut_idx, data in dut_vars.get(component).items():
            if int(dut_idx) == index:
                component_expected_data = data.get(field)
                return component_expected_data
    return component_expected_data


def get_expecetd_data():
    with open(EXPECTED_DATA_FILE, 'r') as f:
        data = f.read()
    expected_data = json.loads(data)
    return expected_data


def verify_response_is_valid(response, color, state):
    """Verify response with expected response"""
    if color == 'LED_COLOR_INVALID' or state == 'LED_STATE_INVALID':
        verify_response_code(response, 2)
    elif color == 'LED_COLOR_INVALID' and state == 'LED_STATE_OFF':
        verify_response_code(response, 2)
    elif color == 'LED_COLOR_NONE':
        verify_response_code(response, 2)
    else:
        verify_response_code(response, 0)


def verify_response_code(response, expected_response_code):
    """Verify response code"""
    if response.response_status.status_code != expected_response_code:
        pytest.fail('The response {} is not same as, Expected {}'
                     .format(NDK_RESPONSE.get(response.response_status.status_code),
                             NDK_RESPONSE.get(expected_response_code)))


def get_ndk_cli_response(dut, cmd, key='entry'):
    """Get response from NDK cli command"""
    response = dut.shell("cat /tmp/pass | /opt/srlinux/bin/sr_platform_ndk_cli -w -c '{}'"
                         .format(cmd))
    if response['stdout'] != "":
        return json.loads(response['stdout']).get(key)

    return ""


def get_expected_hwsku_data(dut, expected_data, component, key=None, default=0):
    """Gets expected thermal data"""
    expected_dut_data = expected_data.get(dut)
    chassis_type = expected_dut_data.get('chassis_type')
    card_hwsku = expected_dut_data.get('card_hwsku')
    expected_componenet_data = expected_data.get(chassis_type).get(card_hwsku)
    if key is None:
        return expected_componenet_data.get(component, default)
    return expected_componenet_data.get(key).get(component, default)

def time_taken_by_api(func):
    def _time_taken(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logging.info('Time taken to run {} {}s'.format(func.__name__, end_time - start_time))
        return result
    return _time_taken