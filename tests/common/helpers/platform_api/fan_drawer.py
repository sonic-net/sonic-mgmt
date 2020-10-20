""" This module provides interface to interact with the fan_drawer of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def fan_drawer_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/fan_drawer/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing fan_drawer API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res

#
# Methods inherited from DeviceBase class
#


def get_name(conn, index):
    return fan_drawer_api(conn, index, 'get_name')


def get_presence(conn, index):
    return fan_drawer_api(conn, index, 'get_presence')


def get_model(conn, index):
    return fan_drawer_api(conn, index, 'get_model')


def get_serial(conn, index):
    return fan_drawer_api(conn, index, 'get_serial')


def get_status(conn, index):
    return fan_drawer_api(conn, index, 'get_status')

#
# Methods defined in fan_drawerBase class
#


def get_num_fans(conn, index):
    return fan_drawer_api(conn, index, 'get_num_fans')


def get_all_fans(conn, index):
    return fan_drawer_api(conn, index, 'get_all_fans')


def set_status_led(conn, index, color):
    return fan_drawer_api(conn, index, 'set_status_led', [color])


def get_status_led(conn, index):
    return fan_drawer_api(conn, index, 'get_status_led')


def get_position_in_parent(conn, index):
    return fan_drawer_api(conn, index, 'get_position_in_parent')


def is_replaceable(conn, index):
    return fan_drawer_api(conn, index, 'is_replaceable')
