""" This module provides interface to interact with the psu of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def psu_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/psu/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing psu API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


def get_num_fans(conn):
    return psu_api(conn, 'get_num_fans')


def get_all_fans(conn):
    return psu_api(conn, 'get_all_fans')


def get_fan(conn):
    return psu_api(conn, 'get_fan', [index])


def get_voltage(conn):
    return psu_api(conn, 'get_voltage')


def get_current(conn):
    return psu_api(conn, 'get_current')


def get_power(conn):
    return psu_api(conn, 'get_power')


def get_powergood_status(conn):
    return psu_api(conn, 'get_powergood_status')


def set_status_led(conn):
    return psu_api(conn, 'set_status_led')


def get_status_led(conn):
    return psu_api(conn, 'get_status_led')


def get_temperature(conn):
    return psu_api(conn, 'get_temperature')


def get_temperature_high_threshold(conn):
    return psu_api(conn, 'get_temperature_high_threshold')


def get_voltage_high_threshold(conn):
    return psu_api(conn, 'get_voltage_high_threshold')


def get_voltage_low_threshold(conn):
    return psu_api(conn, 'get_voltage_low_threshold')

