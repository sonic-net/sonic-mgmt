"""Platform API tests for LeakageSensorBase."""

import logging
import pytest

from tests.common.helpers.platform_api import leak_sensor, liquid_cooling
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service
)

from .platform_api_test_base import PlatformApiTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


@pytest.fixture(scope="module", autouse=True)
def skip_if_not_liquid_cooled(duthosts, enum_rand_one_per_hwsku_hostname):
    """Skip the module if Chassis.is_liquid_cooled() is False."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    out = duthost.shell(
        "python3 -c 'from sonic_platform.chassis import Chassis; "
        "print(Chassis().is_liquid_cooled())'",
        module_ignore_errors=True)
    if out.get('stdout', '').strip() != 'True':
        pytest.skip("Chassis is not liquid-cooled")


class TestLeakSensorApi(PlatformApiTestBase):
    """Tests for LeakageSensorBase platform API."""

    num_leak_sensors = 0

    @pytest.fixture(scope="function", autouse=True)
    def resolve_num_leak_sensors(self, platform_api_conn):  # noqa: F811
        try:
            self.num_leak_sensors = int(liquid_cooling.get_num_leak_sensors(platform_api_conn))
        except Exception as e:
            pytest.skip(f"Platform API get_num_leak_sensors not available: {e}")
        if self.num_leak_sensors == 0:
            pytest.skip("No leak sensors found on device")

    def test_leak_sensor_identity_attributes(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                             platform_api_conn):  # noqa: F811
        """Verify get_name(), get_leak_sensor_type(), get_leak_sensor_location()."""
        for sensor_index in range(self.num_leak_sensors):
            # get_name()
            name = leak_sensor.get_name(platform_api_conn, sensor_index)
            self.expect(isinstance(name, str), f"Sensor {sensor_index} get_name() should return string")
            self.expect(len(name) > 0, f"Sensor {sensor_index} get_name() should not be empty")

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
        """Verify is_leak(), is_leak_sensor_ok(), get_leak_severity()."""
        valid_severities = ['MINOR', 'CRITICAL', None]

        for sensor_index in range(self.num_leak_sensors):
            # is_leak()
            is_leaking = leak_sensor.is_leak(platform_api_conn, sensor_index)
            self.expect(isinstance(is_leaking, bool),
                        f"Sensor {sensor_index} is_leak() should return bool")

            # is_leak_sensor_ok()
            sensor_ok = leak_sensor.is_leak_sensor_ok(platform_api_conn, sensor_index)
            self.expect(isinstance(sensor_ok, bool),
                        f"Sensor {sensor_index} is_leak_sensor_ok() should return bool")

            # get_leak_severity() — None is allowed (e.g. when not currently leaking)
            severity = leak_sensor.get_leak_severity(platform_api_conn, sensor_index)
            self.expect(severity in valid_severities,
                        f"Sensor {sensor_index} get_leak_severity()={severity!r} not in {valid_severities}")

    def test_leak_sensor_profile(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """Verify per-sensor profile (get_type, get_leak_max_minor_duration_sec) and get_all_profiles()."""
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
            if max_dur is None:
                logger.info(f"Sensor {sensor_index} get_leak_max_minor_duration_sec() returned None "
                            f"- platform does not support this attribute")
            else:
                self.expect(isinstance(max_dur, (int, float)) and max_dur > 0,
                            f"Sensor {sensor_index} max_minor_duration_sec={max_dur} should be non-zero")

        # get_all_profiles() on LiquidCoolingBase
        all_profiles = liquid_cooling.get_all_profiles(platform_api_conn)
        if all_profiles is not None:
            self.expect(isinstance(all_profiles, list),
                        "liquid_cooling.get_all_profiles() should return list")
            logger.info(f"Platform exposes {len(all_profiles)} leak sensor profile type(s)")
