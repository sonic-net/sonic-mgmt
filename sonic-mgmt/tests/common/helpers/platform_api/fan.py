""" This module provides interface to interact with the fan of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def fan_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/fan/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing fan API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res

#
# Methods inherited from DeviceBase class
#


def get_name(conn, index):
    return fan_api(conn, index, 'get_name')


def get_presence(conn, index):
    return fan_api(conn, index, 'get_presence')


def get_model(conn, index):
    return fan_api(conn, index, 'get_model')


def get_serial(conn, index):
    return fan_api(conn, index, 'get_serial')


def get_status(conn, index):
    return fan_api(conn, index, 'get_status')


def get_position_in_parent(conn, index):
    return fan_api(conn, index, 'get_position_in_parent')


def is_replaceable(conn, index):
    return fan_api(conn, index, 'is_replaceable')

#
# Methods defined in fanBase class
#


def get_direction(conn, index):
    return fan_api(conn, index, 'get_direction')


def get_speed(conn, index):
    return fan_api(conn, index, 'get_speed')


def get_target_speed(conn, index):
    return fan_api(conn, index, 'get_target_speed')


def get_speed_tolerance(conn, index):
    return fan_api(conn, index, 'get_speed_tolerance')


def set_speed(conn, index, speed):
    return fan_api(conn, index, 'set_speed', [speed])


def set_status_led(conn, index, color):
    return fan_api(conn, index, 'set_status_led', [color])


def get_status_led(conn, index):
    return fan_api(conn, index, 'get_status_led')
