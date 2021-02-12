"""
This module provides an interface to remotely interact with the power
supply units of the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def psu_api(conn, psu_id, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/psu/{}/{}'.format(psu_id, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing PSU API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn, index):
    return psu_api(conn, index, 'get_name')


def get_presence(conn, index):
    return psu_api(conn, index, 'get_presence')


def get_model(conn, index):
    return psu_api(conn, index, 'get_model')


def get_serial(conn, index):
    return psu_api(conn, index, 'get_serial')


def get_status(conn, index):
    return psu_api(conn, index, 'get_status')


def get_position_in_parent(conn, psu_id):
    return psu_api(conn, psu_id, 'get_position_in_parent')


def is_replaceable(conn, psu_id):
    return psu_api(conn, psu_id, 'is_replaceable')

#
# Methods defined in PsuBase class
#


def get_num_fans(conn, psu_id):
    return psu_api(conn, psu_id, 'get_num_fans')


def get_all_fans(conn, psu_id):
    return psu_api(conn, psu_id, 'get_all_fans')


def get_fan(conn, psu_id, index):
    return psu_api(conn, psu_id, 'get_fan', [index])


def get_voltage(conn, psu_id):
    return psu_api(conn, psu_id, 'get_voltage')


def get_current(conn, psu_id):
    return psu_api(conn, psu_id, 'get_current')


def get_power(conn, psu_id):
    return psu_api(conn, psu_id, 'get_power')


def get_maximum_supplied_power(conn, psu_id):
    return psu_api(conn, psu_id, 'get_maximum_supplied_power')


def get_powergood_status(conn, psu_id):
    return psu_api(conn, psu_id, 'get_powergood_status')


def set_status_led(conn, psu_id, color):
    return psu_api(conn, psu_id, 'set_status_led', [color])


def get_status_led(conn, psu_id):
    return psu_api(conn, psu_id, 'get_status_led')


def get_temperature(conn, psu_id):
    return psu_api(conn, psu_id, 'get_temperature')


def get_temperature_high_threshold(conn, psu_id):
    return psu_api(conn, psu_id, 'get_temperature_high_threshold')


def get_voltage_high_threshold(conn, psu_id):
    return psu_api(conn, psu_id, 'get_voltage_high_threshold')


def get_voltage_low_threshold(conn, psu_id):
    return psu_api(conn, psu_id, 'get_voltage_low_threshold')


def get_num_thermals(conn, psu_id):
    return psu_api(conn, psu_id, 'get_num_thermals')


def get_all_thermals(conn, psu_id):
    return psu_api(conn, psu_id, 'get_all_thermals')


def get_thermal(conn, psu_id, index):
    return psu_api(conn, psu_id, 'get_thermal', [index])


def set_status_master_led(conn, psu_id, color):
    return psu_api(conn, psu_id, 'set_status_master_led', [color])


def get_status_master_led(conn, psu_id):
    return psu_api(conn, psu_id, 'get_status_master_led')
