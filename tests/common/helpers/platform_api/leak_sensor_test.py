""" This module provides interface to interact with the LeakageSensorTestBase of the DUT
    via platform API remotely. It is used to inject simulated leaks without wetting hardware.

    Routes to: /platform/chassis/liquid_cooling/leak_sensor_test/{name}
    which resolves to: chassis.get_liquid_cooling().get_leak_sensor_test().{name}()

    Method names match LeakageSensorTestBase in sonic_platform_base/leakage_sensor_test_base.py.
"""

import json
import logging

logger = logging.getLogger(__name__)

# DUT management address -> whether the platform supports leak test injection
_leak_test_supported_cache = {}


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


def is_real_leak_present(conn):
    """True if any leak sensor reports a leak that is not a test leak."""
    from tests.common.helpers.platform_api import leak_sensor, liquid_cooling
    return any(leak_sensor.is_leak(conn, i) and not leak_sensor.is_test_leak(conn, i)
               for i in range(liquid_cooling.get_num_leak_sensors(conn)))


def is_leak_test_available(conn):
    """True if LiquidCoolingBase.get_leak_sensor_test() returns a test object rather than None.

    A platform returns None when injection is unavailable, for example when it cannot
    guarantee that leak mitigation is disabled.
    """
    from tests.common.helpers.platform_api import liquid_cooling
    return liquid_cooling.liquid_cooling_api(conn, 'get_leak_sensor_test') is not None


def is_leak_test_supported(conn):
    """LiquidCoolingBase.get_leak_sensor_test() is not None and LeakageSensorTestBase.is_leak_test_supported()

    Platform support is static, so the answer is looked up once per DUT and cached for the session.
    A failed lookup raises and is not cached.
    """
    key = conn.host
    if key not in _leak_test_supported_cache:
        supported = False
        if is_leak_test_available(conn):
            supported = bool(leak_sensor_test_api(conn, 'is_leak_test_supported'))
        _leak_test_supported_cache[key] = supported
    return _leak_test_supported_cache[key]


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
