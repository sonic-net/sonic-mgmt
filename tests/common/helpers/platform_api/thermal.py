""" This module provides interface to interact with the thermal of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def thermal_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/thermal/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing thermal API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res

#
# Methods inherited from DeviceBase class
#


def get_name(conn, index):
    return thermal_api(conn, index, 'get_name')


def get_presence(conn, index):
    return thermal_api(conn, index, 'get_presence')


def get_model(conn, index):
    return thermal_api(conn, index, 'get_model')


def get_serial(conn, index):
    return thermal_api(conn, index, 'get_serial')


def get_status(conn, index):
    return thermal_api(conn, index, 'get_status')


def get_position_in_parent(conn, index):
    return thermal_api(conn, index, 'get_position_in_parent')


def is_replaceable(conn, index):
    return thermal_api(conn, index, 'is_replaceable')

#
# Methods defined in thermalBase class
#


def get_temperature(conn, index):
    return thermal_api(conn, index, 'get_temperature')


def get_high_threshold(conn, index):
    return thermal_api(conn, index, 'get_high_threshold')


def get_low_threshold(conn, index):
    return thermal_api(conn, index, 'get_low_threshold')


def set_high_threshold(conn, index, temperature):
    return thermal_api(conn, index, 'set_high_threshold', [temperature])


def set_low_threshold(conn, index, temperature):
    return thermal_api(conn, index, 'set_low_threshold', [temperature])


def get_high_critical_threshold(conn, index):
    return thermal_api(conn, index, 'get_high_critical_threshold')


def get_low_critical_threshold(conn, index):
    return thermal_api(conn, index, 'get_low_critical_threshold')


def get_minimum_recorded(conn, index):
    return thermal_api(conn, index, 'get_minimum_recorded')


def get_maximum_recorded(conn, index):
    return thermal_api(conn, index, 'get_maximum_recorded')
