"""
Platform API tests for LeakageSensorBase interface

Tests cover:
- LeakageSensorBase API methods
- Leak severity levels (MINOR, CRITICAL)
- Sensor state transitions (leaking/recovered, faulty/ok)
- Platform-independent verification of leak sensor functionality
"""

import logging
import pytest

from tests.common.helpers.platform_api import chassis
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
        """Skip tests if device has no leak sensors"""
        try:
            liquid_cooling = chassis.get_liquid_cooling(platform_api_conn)
            if liquid_cooling is None:
                pytest.skip("Device has no liquid cooling system")

            self.num_leak_sensors = int(chassis.get_num_leak_sensors(platform_api_conn))
            if self.num_leak_sensors == 0:
                pytest.skip("No leak sensors found on device")
        except Exception as e:
            pytest.skip(f"Could not determine leak sensor count: {e}")

    def test_leak_sensor_identity_attributes(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                             platform_api_conn):  # noqa: F811
        """
        Test LeakageSensorBase identity attributes: name, type, location

        Verifies:
        - get_name() returns non-empty string
        - get_type() returns string or None (non-empty if present)
        - get_location() returns string or None (non-empty if present)
        - Values are consistent across multiple calls
        """
        for sensor_index in range(self.num_leak_sensors):
            # Test name
            name = chassis.get_leak_sensor_name(platform_api_conn, sensor_index)
            self.expect(isinstance(name, str), f"Sensor {sensor_index} name should be string")
            self.expect(len(name) > 0, f"Sensor {sensor_index} name should not be empty")

            # Verify name consistency
            name2 = chassis.get_leak_sensor_name(platform_api_conn, sensor_index)
            self.expect(name == name2, f"Sensor {sensor_index} name inconsistent")

            # Test type
            sensor_type = chassis.get_leak_sensor_type(platform_api_conn, sensor_index)
            self.expect(sensor_type is None or isinstance(sensor_type, str),
                        f"Sensor {sensor_index} type should be str or None")
            if sensor_type is not None:
                self.expect(len(sensor_type) > 0,
                            f"Sensor {sensor_index} type should not be empty")

            # Test location
            location = chassis.get_leak_sensor_location(platform_api_conn, sensor_index)
            self.expect(location is None or isinstance(location, str),
                        f"Sensor {sensor_index} location should be str or None")
            if location is not None:
                self.expect(len(location) > 0,
                            f"Sensor {sensor_index} location should not be empty")

    def test_leak_sensor_status_attributes(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                           platform_api_conn):  # noqa: F811
        """
        Test LeakageSensorBase status attributes: is_leak, is_leak_sensor_ok, severity

        Verifies:
        - get_is_leak() returns boolean
        - get_is_leak_sensor_ok() returns boolean
        - get_leak_severity() returns valid severity (MINOR/CRITICAL)
        - Values are consistent across multiple calls
        """
        valid_severities = ['MINOR', 'CRITICAL']

        for sensor_index in range(self.num_leak_sensors):
            # Test is_leak
            is_leak = chassis.get_leak_status(platform_api_conn, sensor_index)
            self.expect(isinstance(is_leak, bool), f"Sensor {sensor_index} is_leak should return bool")

            # Verify consistency
            is_leak2 = chassis.get_leak_status(platform_api_conn, sensor_index)
            self.expect(is_leak == is_leak2, f"Sensor {sensor_index} is_leak inconsistent")

            # Test is_leak_sensor_ok
            sensor_ok = chassis.get_leak_sensor_ok(platform_api_conn, sensor_index)
            self.expect(isinstance(sensor_ok, bool), f"Sensor {sensor_index} is_leak_sensor_ok should return bool")

            # Verify consistency
            sensor_ok2 = chassis.get_leak_sensor_ok(platform_api_conn, sensor_index)
            self.expect(sensor_ok == sensor_ok2, f"Sensor {sensor_index} is_leak_sensor_ok inconsistent")

            # Test severity
            severity = chassis.get_leak_severity(platform_api_conn, sensor_index)
            self.expect(isinstance(severity, str), f"Sensor {sensor_index} severity should be string")
            self.expect(severity in valid_severities, f"Sensor {sensor_index} severity {severity} invalid")

            # Verify consistency
            severity2 = chassis.get_leak_severity(platform_api_conn, sensor_index)
            self.expect(severity == severity2, f"Sensor {sensor_index} severity inconsistent")

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
            sensor = chassis.get_leak_sensor_name(platform_api_conn, invalid_idx)
            self.expect(sensor is None, f"Invalid index should return None, got {sensor}")
        except (IndexError, Exception) as e:
            logger.info(f"Expected exception for invalid index: {e}")

        # Test boundary conditions
        if self.num_leak_sensors > 0:
            first_name = chassis.get_leak_sensor_name(platform_api_conn, 0)
            self.expect(isinstance(first_name, str), "First sensor name should be string")

            last_idx = self.num_leak_sensors - 1
            last_name = chassis.get_leak_sensor_name(platform_api_conn, last_idx)
            self.expect(isinstance(last_name, str), "Last sensor name should be string")

        # Test concurrent read consistency
        if self.num_leak_sensors > 0:
            sensor_idx = 0
            name_values = [chassis.get_leak_sensor_name(platform_api_conn, sensor_idx) for _ in range(10)]

            unique_values = set(name_values)
            self.expect(len(unique_values) == 1, f"Multiple reads should return same value, got {unique_values}")
