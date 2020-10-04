""" This module provides interface to interact with the fan of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/fan_drawer/{}/fan/{}/{}'.format(fan_drawer_idx, fan_idx, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing fan drawer fan API: "{}", fan_drawer index: {}, fan_index {} , arguments: "{}", result: "{}"'.format(name, fan_drawer_idx, fan_idx, args, res))
    return res

#
# Methods inherited from DeviceBase class
#


def get_name(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_name')


def get_presence(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_presence')


def get_model(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_model')


def get_serial(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_serial')


def get_status(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_status')

#
# Methods defined in fanBase class
#


def get_direction(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_direction')


def get_speed(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_speed')


def get_target_speed(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_target_speed')


def get_speed_tolerance(conn, fan_drawer_idx, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_speed_tolerance')


def set_speed(conn, fan_drawer_idx, fan_idx, speed):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'set_speed', [speed])


def set_status_led(conn, fan_drawer_idx, fan_idx, color):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'set_status_led', [color])


def get_status_led(conn, fan_idx):
    return fan_drawer_fan_api(conn, fan_drawer_idx, fan_idx, 'get_status_led')
