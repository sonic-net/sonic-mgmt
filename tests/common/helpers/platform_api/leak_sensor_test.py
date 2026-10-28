""" This module provides interface to interact with the LeakageSensorTestBase of the DUT
    via platform API remotely. It is used to inject simulated leaks without wetting hardware.

    Routes to: /platform/chassis/liquid_cooling/leak_sensor_test/{name}
    which resolves to: chassis.get_liquid_cooling().get_leak_sensor_test().{name}()

    Method names match LeakageSensorTestBase in sonic_platform_base/leakage_sensor_test_base.py.
"""

import json
import logging

logger = logging.getLogger(__name__)


def leak_sensor_test_api(conn, name, args=None, kwargs=None):
    if args is None:
        args = []
    body = {'args': args}
    if kwargs:
        body['kwargs'] = kwargs
    conn.request('POST', '/platform/chassis/liquid_cooling/leak_sensor_test/{}'.format(name),
                 json.dumps(body))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing leak_sensor_test API: "{}", arguments: "{}", keyword arguments: "{}", result: "{}"'.format(
        name, args, kwargs, res))
    return res


def is_leak_test_supported(conn):
    """LeakageSensorTestBase.is_leak_test_supported()"""
    return leak_sensor_test_api(conn, 'is_leak_test_supported')


def set_test_leak(conn, sensor_name, enable, severity=None):
    """LeakageSensorTestBase.set_test_leak(). severity is 'MINOR' or 'CRITICAL'; the platform default
    (MINOR) is used when omitted."""
    kwargs = {'severity': severity} if severity else None
    return leak_sensor_test_api(conn, 'set_test_leak', [sensor_name, enable], kwargs)


def is_test_leak_enabled(conn, sensor_name):
    """LeakageSensorTestBase.is_test_leak_enabled()"""
    return leak_sensor_test_api(conn, 'is_test_leak_enabled', [sensor_name])


def clear_test_leaks(conn):
    """LeakageSensorTestBase.clear_test_leaks()"""
    return leak_sensor_test_api(conn, 'clear_test_leaks')
