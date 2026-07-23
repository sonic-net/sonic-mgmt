""" This module provides interface to interact with the LiquidCoolingBase of the DUT
    via platform API remotely.

    Routes to: /platform/chassis/liquid_cooling/{name}
    which resolves to: chassis.get_liquid_cooling().{name}()
"""

import json
import logging

logger = logging.getLogger(__name__)


def liquid_cooling_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/liquid_cooling/{}'.format(name),
                 json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing liquid_cooling API: "{}", arguments: "{}", result: "{}"'.format(
        name, args, res))
    return res


def get_num_leak_sensors(conn):
    return liquid_cooling_api(conn, 'get_num_leak_sensors')


def get_all_leak_sensors(conn):
    return liquid_cooling_api(conn, 'get_all_leak_sensors')


def get_leak_sensor_status(conn):
    return liquid_cooling_api(conn, 'get_leak_sensor_status')


def get_all_profiles(conn):
    """Returns list of LeakSensorProfileBase objects (serialized)"""
    return liquid_cooling_api(conn, 'get_all_profiles')


def get_profile(conn, sensor_type):
    """Returns LeakSensorProfileBase for the given sensor type (e.g., 'rope', 'spot')"""
    return liquid_cooling_api(conn, 'get_profile', [sensor_type])
