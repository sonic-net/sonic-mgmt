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
# (DUT management address, sensor name) -> {severity or None for the platform default: accepted}
_supported_severities_cache = {}

TEST_LEAK_SEVERITIES = ('MINOR', 'CRITICAL')


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


def _probe_test_leak_severities(conn, sensor_name):
    """Return {severity: accepted} for the platform default (None) and each explicit severity.

    LeakageSensorTestBase has no query for this, so each one is probed by injecting and then withdrawing
    a test leak. The default is probed on its own because it is platform defined and may differ from
    the explicit severities. The result is cached per DUT and sensor. This is the single place to change
    if the platform API gains a way to report the supported severities.
    """
    key = (conn.host, sensor_name)
    if key not in _supported_severities_cache:
        result = {}
        for severity in (None,) + TEST_LEAK_SEVERITIES:
            # A sensor that does not respond or rejects the severity is treated as unsupported
            try:
                result[severity] = set_test_leak(conn, sensor_name, True, severity=severity) is True
            except Exception as e:
                logger.warning("set_test_leak({}, severity={}) failed: {!r}".format(sensor_name, severity, e))
                result[severity] = False
            _withdraw_probe(conn, sensor_name)
        _supported_severities_cache[key] = result
    return _supported_severities_cache[key]


def _withdraw_probe(conn, sensor_name):
    """Withdraw a probe injection. Fall back to a bulk clear, and raise if the test leak cannot be removed,
    so that capability discovery never leaves a test leak active or caches a result for it."""
    try:
        if set_test_leak(conn, sensor_name, False) is True:
            return
        logger.warning("Withdrawing the probe on {} did not return True, clearing all test leaks".format(sensor_name))
    except Exception as e:
        logger.warning("Withdrawing the probe on {} failed: {!r}, clearing all test leaks".format(sensor_name, e))
    if clear_test_leaks(conn) is not True or is_test_leak_enabled(conn, sensor_name) is not False:
        raise RuntimeError("Failed to withdraw the probe test leak on {}".format(sensor_name))


def get_supported_test_leak_severities(conn, sensor_name):
    """Return the explicit test leak severities the sensor accepts, for example ['MINOR'] or ['CRITICAL']."""
    probed = _probe_test_leak_severities(conn, sensor_name)
    return [severity for severity in TEST_LEAK_SEVERITIES if probed[severity]]


def supports_test_leak_severity(conn, sensor_name, severity=None):
    """True if the sensor accepts the severity. None checks the platform default severity itself."""
    return _probe_test_leak_severities(conn, sensor_name)[severity]


def is_test_leak_enabled(conn, sensor_name):
    """LeakageSensorTestBase.is_test_leak_enabled()"""
    return leak_sensor_test_api(conn, 'is_test_leak_enabled', [sensor_name])


def clear_test_leaks(conn):
    """LeakageSensorTestBase.clear_test_leaks()"""
    return leak_sensor_test_api(conn, 'clear_test_leaks')
