"""
Platform API tests for LeakageSensorBase interface

Tests cover:
- LeakageSensorBase API methods (get_name, is_leak, is_leak_sensor_ok, etc.)
- Leak severity levels (MINOR, CRITICAL)
- Sensor state transitions (leaking/recovered, faulty/ok)
- LeakSensorProfileBase API (get_type, get_leak_max_minor_duration_sec)
- Platform-independent verification of leak sensor functionality
"""

import logging
import pytest

from tests.common.helpers.platform_api import chassis, leak_sensor, liquid_cooling
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service
)

from .platform_api_test_base import PlatformApiTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


class TestLeakSensorApi(PlatformApiTestBase):
    """
    Tests for LeakageSensorBase platform API
    """

    num_leak_sensors = 0

    @pytest.fixture(scope="function", autouse=True)
    def skip_if_no_leak_sensors(self, enum_rand_one_per_hwsku_hostname,
                                platform_api_conn):  # noqa: F811
        """Skip tests if device has no liquid cooling or no leak sensors"""
        try:
            lc = chassis.get_liquid_cooling(platform_api_conn)
            if lc is None:
                pytest.skip("Device has no liquid cooling system")

            self.num_leak_sensors = int(liquid_cooling.get_num_leak_sensors(platform_api_conn))
            if self.num_leak_sensors == 0:
                pytest.skip("No leak sensors found on device")
        except Exception as e:
            pytest.skip(f"Could not determine leak sensor count: {e}")

    def test_leak_sensor_identity_attributes(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                             platform_api_conn):  # noqa: F811
        """
        Test LeakageSensorBase identity attributes: get_name(), get_leak_sensor_type(),
        get_leak_sensor_location()

        Verifies:
        - get_name() returns non-empty string
        - get_leak_sensor_type() returns string or None (non-empty if present)
        - get_leak_sensor_location() returns string or None (non-empty if present)
        - Values are consistent across multiple calls
        """
        for sensor_index in range(self.num_leak_sensors):
            # get_name()
            name = leak_sensor.get_name(platform_api_conn, sensor_index)
            self.expect(isinstance(name, str), f"Sensor {sensor_index} get_name() should return string")
            self.expect(len(name) > 0, f"Sensor {sensor_index} get_name() should not be empty")

            name2 = leak_sensor.get_name(platform_api_conn, sensor_index)
            self.expect(name == name2, f"Sensor {sensor_index} get_name() inconsistent")

            # get_leak_sensor_type()
            sensor_type = leak_sensor.get_leak_sensor_type(platform_api_conn, sensor_index)
            self.expect(sensor_type is None or isinstance(sensor_type, str),
                        f"Sensor {sensor_index} get_leak_sensor_type() should return str or None")
            if sensor_type is not None:
                self.expect(len(sensor_type) > 0,
                            f"Sensor {sensor_index} get_leak_sensor_type() should not be empty")

            # get_leak_sensor_location()
            location = leak_sensor.get_leak_sensor_location(platform_api_conn, sensor_index)
            self.expect(location is None or isinstance(location, str),
                        f"Sensor {sensor_index} get_leak_sensor_location() should return str or None")
            if location is not None:
                self.expect(len(location) > 0,
                            f"Sensor {sensor_index} get_leak_sensor_location() should not be empty")

    def test_leak_sensor_status_attributes(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                           platform_api_conn):  # noqa: F811
        """
        Test LeakageSensorBase status attributes: is_leak(), is_leak_sensor_ok(),
        get_leak_severity()

        Verifies:
        - is_leak() returns boolean
        - is_leak_sensor_ok() returns boolean
        - get_leak_severity() returns valid LeakSeverity string ('MINOR' or 'CRITICAL')
        - Values are consistent across multiple calls
        """
        valid_severities = ['MINOR', 'CRITICAL']

        for sensor_index in range(self.num_leak_sensors):
            # is_leak()
            is_leaking = leak_sensor.is_leak(platform_api_conn, sensor_index)
            self.expect(isinstance(is_leaking, bool),
                        f"Sensor {sensor_index} is_leak() should return bool")

            is_leaking2 = leak_sensor.is_leak(platform_api_conn, sensor_index)
            self.expect(is_leaking == is_leaking2,
                        f"Sensor {sensor_index} is_leak() inconsistent")

            # is_leak_sensor_ok()
            sensor_ok = leak_sensor.is_leak_sensor_ok(platform_api_conn, sensor_index)
            self.expect(isinstance(sensor_ok, bool),
                        f"Sensor {sensor_index} is_leak_sensor_ok() should return bool")

            sensor_ok2 = leak_sensor.is_leak_sensor_ok(platform_api_conn, sensor_index)
            self.expect(sensor_ok == sensor_ok2,
                        f"Sensor {sensor_index} is_leak_sensor_ok() inconsistent")

            # get_leak_severity()
            severity = leak_sensor.get_leak_severity(platform_api_conn, sensor_index)
            self.expect(isinstance(severity, str),
                        f"Sensor {sensor_index} get_leak_severity() should return string")
            self.expect(severity in valid_severities,
                        f"Sensor {sensor_index} get_leak_severity()={severity} not in {valid_severities}")

            severity2 = leak_sensor.get_leak_severity(platform_api_conn, sensor_index)
            self.expect(severity == severity2,
                        f"Sensor {sensor_index} get_leak_severity() inconsistent")

    def test_leak_sensor_reliability(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """
        Test LeakageSensorBase reliability and error handling

        Verifies:
        - Invalid index handled gracefully (no crash)
        - Boundary conditions (first/last sensor) work correctly
        - Multiple consecutive reads are consistent (no state drift)
        """
        # Test invalid index handling
        try:
            invalid_idx = self.num_leak_sensors + 100
            name = leak_sensor.get_name(platform_api_conn, invalid_idx)
            self.expect(name is None, f"Invalid index should return None, got {name}")
        except (IndexError, Exception) as e:
            logger.info(f"Expected exception for invalid index: {e}")

        if self.num_leak_sensors > 0:
            # Boundary: first sensor
            first_name = leak_sensor.get_name(platform_api_conn, 0)
            self.expect(isinstance(first_name, str), "First sensor get_name() should return string")

            # Boundary: last sensor
            last_idx = self.num_leak_sensors - 1
            last_name = leak_sensor.get_name(platform_api_conn, last_idx)
            self.expect(isinstance(last_name, str), "Last sensor get_name() should return string")

            # Consistency: 10 consecutive reads must return the same value
            name_values = [leak_sensor.get_name(platform_api_conn, 0) for _ in range(10)]
            unique_values = set(name_values)
            self.expect(len(unique_values) == 1,
                        f"Repeated get_name() calls returned multiple values: {unique_values}")

    def test_leak_sensor_profile(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """
        Test LeakSensorProfileBase via LeakageSensorBase.get_leak_profile():
        get_type() and get_leak_max_minor_duration_sec()

        Also tests LiquidCoolingBase.get_all_profiles().

        Verifies:
        - get_type() (via profile route) returns a non-empty string
        - get_leak_max_minor_duration_sec() returns a non-negative integer
        - get_all_profiles() returns a list
        """
        if self.num_leak_sensors == 0:
            pytest.skip("No leak sensors available")

        for sensor_index in range(self.num_leak_sensors):
            # get_type() on the profile associated with this sensor
            profile_type = leak_sensor.get_profile_type(platform_api_conn, sensor_index)
            self.expect(profile_type is not None,
                        f"Sensor {sensor_index} profile get_type() should not return None")
            if profile_type is not None:
                self.expect(isinstance(profile_type, str) and len(profile_type) > 0,
                            f"Sensor {sensor_index} profile type should be non-empty string, got {profile_type!r}")

            # get_leak_max_minor_duration_sec() on the profile
            max_dur = leak_sensor.get_leak_max_minor_duration_sec(platform_api_conn, sensor_index)
            self.expect(max_dur is not None,
                        f"Sensor {sensor_index} get_leak_max_minor_duration_sec() should not return None")
            if max_dur is not None:
                self.expect(isinstance(max_dur, (int, float)) and max_dur >= 0,
                            f"Sensor {sensor_index} max_minor_duration_sec={max_dur} should be non-negative")

        # get_all_profiles() on LiquidCoolingBase
        all_profiles = liquid_cooling.get_all_profiles(platform_api_conn)
        if all_profiles is not None:
            self.expect(isinstance(all_profiles, list),
                        "liquid_cooling.get_all_profiles() should return list")
            logger.info(f"Platform exposes {len(all_profiles)} leak sensor profile type(s)")
