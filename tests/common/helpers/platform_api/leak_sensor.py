""" This module provides interface to interact with individual LeakageSensorBase objects
    on the DUT via platform API remotely.

    Routes to: /platform/chassis/liquid_cooling/leak_sensor/{index}/{name}
    which resolves to: chassis.get_liquid_cooling().get_leak_sensor(index).{name}()

    Profile methods route to:
    /platform/chassis/liquid_cooling/leak_sensor/{index}/leak_profile/{name}
    which resolves to: ...get_leak_sensor(index).get_leak_profile().{name}()

    Method names match LeakageSensorBase / LeakSensorProfileBase in liquid_cooling_base.py.
"""

import json
import logging

logger = logging.getLogger(__name__)


def leak_sensor_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/liquid_cooling/leak_sensor/{}/{}'.format(index, name),
                 json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing leak_sensor API: "{}", index: {}, arguments: "{}", result: "{}"'.format(
        name, index, args, res))
    return res


def leak_sensor_profile_api(conn, index, name, args=None):
    """Route to LeakSensorProfileBase methods via sensor.get_leak_profile()"""
    if args is None:
        args = []
    conn.request('POST',
                 '/platform/chassis/liquid_cooling/leak_sensor/{}/leak_profile/{}'.format(index, name),
                 json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing leak_sensor_profile API: "{}", sensor_index: {}, result: "{}"'.format(
        name, index, res))
    return res


# ===== LeakageSensorBase methods =====

def get_name(conn, index):
    """LeakageSensorBase.get_name() — name of the leak sensor"""
    return leak_sensor_api(conn, index, 'get_name')


def is_leak(conn, index):
    """LeakageSensorBase.is_leak() — True if leak detected"""
    return leak_sensor_api(conn, index, 'is_leak')


def is_leak_sensor_ok(conn, index):
    """LeakageSensorBase.is_leak_sensor_ok() — True if sensor is healthy (not faulty)"""
    return leak_sensor_api(conn, index, 'is_leak_sensor_ok')


def get_leak_sensor_type(conn, index):
    """LeakageSensorBase.get_leak_sensor_type() — sensor type string (e.g. 'rope', 'spot')"""
    return leak_sensor_api(conn, index, 'get_leak_sensor_type')


def get_leak_sensor_location(conn, index):
    """LeakageSensorBase.get_leak_sensor_location() — location string or None"""
    return leak_sensor_api(conn, index, 'get_leak_sensor_location')


def get_leak_severity(conn, index):
    """LeakageSensorBase.get_leak_severity() — LeakSeverity ('MINOR' or 'CRITICAL')"""
    return leak_sensor_api(conn, index, 'get_leak_severity')


# ===== LeakSensorProfileBase methods (via sensor.get_leak_profile()) =====

def get_profile_type(conn, index):
    """LeakSensorProfileBase.get_type() — profile type string (e.g. 'rope', 'spot', 'flex_pcb')"""
    return leak_sensor_profile_api(conn, index, 'get_type')


def get_leak_max_minor_duration_sec(conn, index):
    """LeakSensorProfileBase.get_leak_max_minor_duration_sec() — seconds before minor→critical"""
    return leak_sensor_profile_api(conn, index, 'get_leak_max_minor_duration_sec')
