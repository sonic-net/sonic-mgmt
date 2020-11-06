""" This module provides interface to interact with the fan of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def psu_fan_api(conn, psu_idx, fan_idx, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/psu/{}/fan/{}/{}'.format(psu_idx, fan_idx, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing psu fan API: "{}", psu index: {}, fan_index {} , arguments: "{}", result: "{}"'.format(name, psu_idx, fan_idx, args, res))
    return res

#
# Methods inherited from DeviceBase class
#


def get_name(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_name')


def get_presence(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_presence')


def get_model(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_model')


def get_serial(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_serial')


def get_status(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_status')


def get_position_in_parent(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_position_in_parent')


def is_replaceable(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'is_replaceable')

#
# Methods defined in fanBase class
#


def get_direction(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_direction')


def get_speed(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_speed')


def get_target_speed(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_target_speed')


def get_speed_tolerance(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_speed_tolerance')


def set_speed(conn, psu_idx, fan_idx, speed):
    return psu_fan_api(conn, psu_idx, fan_idx, 'set_speed', [speed])


def set_status_led(conn, psu_idx, fan_idx, color):
    return psu_fan_api(conn, psu_idx, fan_idx, 'set_status_led', [color])


def get_status_led(conn, psu_idx, fan_idx):
    return psu_fan_api(conn, psu_idx, fan_idx, 'get_status_led')
