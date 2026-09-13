"""
Test base sensor APIs for sensor types that implement SensorBase
"""

import logging

import pytest
from tests.common.helpers.platform_api import chassis
from tests.common.helpers.platform_api.sensor import Sensor
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from .platform_api_test_base import PlatformApiTestBase


class SensorApiTestBase(PlatformApiTestBase):
    """
    Test base sensor APIs
    Must be inherited by sensor types that conform to SensorBase
    """

    daemon_name = "sensormond"
    num_sensors = None
    chassis_facts = None
    sensor_class = Sensor
    sensor_unit_suffix = "INVALID"
    logger = logging.getLogger(__name__)

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.
    @pytest.fixture(scope="function", autouse=True)
    def setup(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            platform_api_conn):
        """
        Setup up requirements for voltage sensor test cases

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        daemon_en_status = check_pmon_daemon_enable_status(duthost, self.daemon_name)
        if daemon_en_status is False:
            pytest.skip(f"{self.daemon_name} is not enabled in {duthost.facts['platform']} {duthost.os_version}")
        if self.num_sensors is None:
            try:
                self.num_sensors = int(getattr(chassis,
                                               f"get_num_{self.sensor_class.sensor_type}_sensors")(platform_api_conn))
            except Exception as exc:
                pytest.fail(f"Failed to get number of sensors: {exc}")
        if self.num_sensors == 0:
            pytest.skip("No sensors found on device")

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(
            self,
            duthost,
            key,
            value):
        """
        Compare a specified key and value again DUT defined facts

        Args:
            duthost: DUT host specification
            key: Key for lookup in DUT facts
            value: Value to compare against within key in DUT facts
        """
        expected_values = {
            s[key] for s in duthost.facts.get(
                "chassis", {}).get(
                    f"{self.sensor_class.sensor_type}_sensors", [])
            if key in s}

        if self.expect(len(expected_values) > 0,
                       f"Unable to get sensor name list containing sensor '{value}' from platform.json file"):
            self.expect(value in expected_values,
                        f"Sensor name '{value}' is not included in {expected_values}")

    def get_sensor_facts(
            self,
            duthost,
            sensor_idx,
            def_value,
            key):
        """
        Retrieve expected value for specified key from DUT facts for a given sensor

        Args:
            duthost: DUT host specification
            sensor_idx: Sensor index
            def_value: Default value if no value in facts
            key: Key to search in DUT facts

        Returns:
            Value of specified key from DUT facts, def_value if no value found in DUT facts
        """
        try:
            return duthost.facts.get(
                "chassis", {}).get(
                    f"{self.sensor_class.sensor_type}_sensors", [])[sensor_idx].get(key, def_value)
        except IndexError:
            return def_value

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_name API to verify it returns data of the expected type and value

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for i in range(self.num_sensors):
            name = self.sensor_class.get_name(platform_api_conn, i)

            if not self.expect(isinstance(name, str), f"Sensor {i} name '{name}' appears incorrect"):
                continue

            self.compare_value_with_platform_facts(duthost, "name", name)

        self.assert_expectations()

    def test_get_presence(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_presence API to verify all sensors report presence as True

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            presence = self.sensor_class.get_presence(platform_api_conn, i)

            if not self.expect(isinstance(presence, bool), f"Sensor {i} presence '{presence}' appears incorrect"):
                continue

            self.expect(presence is True, f"Sensor {i} is not present")

        self.assert_expectations()

    def test_get_model(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_model API to verify all sensors report models as str type

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            model = self.sensor_class.get_model(platform_api_conn, i)

            self.expect(isinstance(model, str), f"Sensor {i} model '{model}' appears incorrect")

        self.assert_expectations()

    def test_get_serial(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_serial API to verify all sensors report serial numbers as str type

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            serial = self.sensor_class.get_serial(platform_api_conn, i)

            self.expect(isinstance(serial, str), f"Sensor {i} serial number '{serial}' appears incorrect")

        self.assert_expectations()

    def test_get_status(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_status API to verify all sensors report status as bool type

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            status = self.sensor_class.get_status(platform_api_conn, i)

            self.expect(isinstance(status, bool), f"Sensor {i} status '{status}' appears incorrect")

        self.assert_expectations()

    def test_get_position_in_parent(
            self,
            platform_api_conn):
        """
        Test get_position_in_parent API to verify all sensors report position in parent as int type

        Args:
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            position = self.sensor_class.get_position_in_parent(platform_api_conn, i)

            self.expect(isinstance(position, int), f"Sensor {i} position '{position}' appears incorrect")

        self.assert_expectations()

    def test_is_replaceable(
            self,
            platform_api_conn):
        """
        Test is_replaceable API to verify all sensors report replaceability state as bool type

        Args:
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            replaceable = self.sensor_class.is_replaceable(platform_api_conn, i)

            self.expect(isinstance(replaceable, bool), f"Sensor {i} replaceability '{replaceable}' appears incorrect")

        self.assert_expectations()

    #
    # Functions to test methods defined in SensorBase class
    #

    def test_get_type(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Specifies the type of the sensor such as current/voltage etc.

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        sensor_type = "SENSOR_TYPE_" + self.sensor_class.sensor_type.upper()
        for i in range(self.num_sensors):
            s_type = self.sensor_class.get_type(platform_api_conn, i)

            self.expect(s_type == sensor_type, f"Sensor {i} type {s_type} does not match expected type {sensor_type}")

        self.assert_expectations()

    def test_get_value(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_value API to verify all sensors report values as float or int type

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            value = self.sensor_class.get_value(platform_api_conn, i)

            self.expect(isinstance(value, (float, int)), f"Sensor {i} value '{value}' appears incorrect")

        self.assert_expectations()

    def test_get_unit(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Retrieves unit of measurement reported by sensor

        Args:
            duthosts: Unused
            enum_rand_one_per_hwsku_hostname: Unused
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        for i in range(self.num_sensors):
            unit = self.sensor_class.get_unit(platform_api_conn, i)

            if not self.expect(isinstance(unit, str), f"Sensor {i} unit '{unit}' appears incorrect"):
                continue

            self.expect(unit.endswith(self.sensor_unit_suffix),
                        f"Sensor {i} unit '{unit}' does not match base unit '{self.sensor_unit_suffix}'")
        self.assert_expectations()

    def test_get_minimum_recorded(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_minimum_recorded API to verify all sensors report minimum recorded
        value as float or int and within range

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            record_supported = self.get_sensor_facts(duthost, i, True, "minimum-recorded")
            if not record_supported:
                self.logger.info("test_get_minimum_recorded: Skipping sensor %s (not supported)", i)
                sensors_skipped += 1
                continue

            min_value = self.get_sensor_facts(duthost, i, None, "minimum")
            max_value = self.get_sensor_facts(duthost, i, None, "maximum")

            value = self.sensor_class.get_minimum_recorded(platform_api_conn, i)

            if not self.expect(isinstance(value, (float, int)), f"Sensor {i} minimum '{value}' appears incorrect"):
                continue

            if isinstance(min_value, (float, int)) and isinstance(max_value, (float, int)):
                self.expect(min_value < value <= max_value,
                            f"Sensor {i} value {value} reading is not within range")
            else:
                self.logger.info("Range for sensor %s is not specified", i)

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' minimum-recorded is not supported")

        self.assert_expectations()

    def test_get_maximum_recorded(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_maximum_recorded API to verify all sensors report maximum recorded
        value as float or int and within range

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            record_supported = self.get_sensor_facts(duthost, i, True, "maximum-recorded")
            if not record_supported:
                self.logger.info("test_get_maximum_recorded: Skipping sensor %s (not supported)", i)
                sensors_skipped += 1
                continue

            min_value = self.get_sensor_facts(duthost, i, None, "minimum")
            max_value = self.get_sensor_facts(duthost, i, None, "maximum")

            value = self.sensor_class.get_maximum_recorded(platform_api_conn, i)

            if not self.expect(isinstance(value, (float, int)), f"Sensor {i} maximum '{value}' appears incorrect"):
                continue

            if isinstance(min_value, (float, int)) and isinstance(max_value, (float, int)):
                self.expect(min_value < value <= max_value,
                            f"Sensor {i} value {value} reading is not within range")
            else:
                self.logger.info("Range for sensor %s is not specified", i)

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' maximum-recorded is not supported")

        self.assert_expectations()

    def test_get_low_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_low_threshold API to verify all sensors report low thresholds as float or int type

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "low-threshold"):
                self.logger.info("test_get_low_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue

            low_threshold = self.sensor_class.get_low_threshold(platform_api_conn, i)

            self.expect(isinstance(low_threshold, (float, int)),
                        f"Sensor {i} low threshold '{low_threshold}' appears incorrect")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' low-threshold is not supported")

        self.assert_expectations()

    def test_get_high_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_high_threshold API to verify all sensors report high thresholds as float or int type

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "high-threshold"):
                self.logger.info("test_get_high_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue

            high_threshold = self.sensor_class.get_high_threshold(platform_api_conn, i)

            self.expect(isinstance(high_threshold, (float, int)),
                        f"Sensor {i} high threshold '{high_threshold}' appears incorrect")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' high-threshold is not supported")

        self.assert_expectations()

    def test_get_low_critical_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_low_critical_threshold API to verify all sensors report low critical thresholds as float or int type

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "low-critical-threshold"):
                self.logger.info("test_get_low_critical_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue

            low_critical_threshold = self.sensor_class.get_low_critical_threshold(platform_api_conn, i)

            self.expect(isinstance(low_critical_threshold, (float, int)),
                        f"Sensor {i} low critical threshold '{low_critical_threshold}' appears incorrect")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' low-critical-threshold is not supported")

        self.assert_expectations()

    def test_get_high_critical_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test get_high_critical_threshold API to verify all sensors report high critical thresholds as float or int type

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "high-critical-threshold"):
                self.logger.info("test_get_high_critical_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue

            high_critical_threshold = self.sensor_class.get_high_critical_threshold(platform_api_conn, i)

            self.expect(isinstance(high_critical_threshold, (float, int)),
                        f"Sensor {i} high critical threshold '{high_critical_threshold}' appears incorrect")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' high-critical-threshold is not supported")

        self.assert_expectations()

    def test_set_low_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test set_low_threshold API to verify all sensors can have their low threshold
        set to a specified value successfully

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        # Ensure the sensor value is sane
        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "low-threshold"):
                self.logger.info("test_set_low_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue
            if not self.get_sensor_facts(duthost, i, True, "controllable"):
                self.logger.info("test_set_low_threshold: Skipping sensor %s (threshold not controllable)", i)
                sensors_skipped += 1
                continue

            low_value = self.sensor_class.get_low_threshold(platform_api_conn, i)
            if not self.expect(isinstance(low_value, (float, int)),
                               f"Sensor {i} low threshold '{low_value}' appears incorrect"):
                continue
            low_value += 1

            result = self.sensor_class.set_low_threshold(platform_api_conn, i, low_value)
            if not self.expect(result is True, f"Failed to set set_low_threshold for sensor {i} to {low_value}"):
                continue

            value = self.sensor_class.get_low_threshold(platform_api_conn, i)
            if not self.expect(isinstance(value, (float, int)),
                               f"Sensor {i} low threshold '{value}' appears incorrect"):
                continue

            self.expect(value == low_value,
                        f"Sensor {i} low threshold {value} is not matching the set value {low_value}")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' low-threshold is not controllable")

        self.assert_expectations()

    def test_set_high_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test set_high_threshold API to verify all sensors can have their high threshold
        set to a specified value successfully

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        # Ensure the sensor value is sane
        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "high-threshold"):
                self.logger.info("test_set_high_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue
            if not self.get_sensor_facts(duthost, i, True, "controllable"):
                self.logger.info("test_set_high_threshold: Skipping sensor %s (threshold not controllable)", i)
                sensors_skipped += 1
                continue

            high_value = self.sensor_class.get_high_threshold(platform_api_conn, i)
            if not self.expect(isinstance(high_value, (float, int)),
                               f"Sensor {i} high threshold '{high_value}' appears incorrect"):
                continue
            high_value -= 1

            result = self.sensor_class.set_high_threshold(platform_api_conn, i, high_value)
            if not self.expect(result is True, f"Failed to set set_high_threshold for sensor {i} to {high_value}"):
                continue

            value = self.sensor_class.get_high_threshold(platform_api_conn, i)
            if self.expect(isinstance(value, (float, int)), f"Sensor {i} high threshold '{value}' appears incorrect"):
                continue

            self.expect(value == high_value,
                        f"Sensor {i} high threshold {value} is not matching the set value {high_value}")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' high-threshold is not controllable")

        self.assert_expectations()

    def test_set_low_critical_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test set_low_critical_threshold API to verify all sensors can have their low critical
        threshold set to a specified value successfully

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        # Ensure the sensor value is sane
        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "low-critical-threshold"):
                self.logger.info("test_set_low_critical_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue
            if not self.get_sensor_facts(duthost, i, True, "controllable"):
                self.logger.info("test_set_low_critical_threshold: Skipping sensor %s (threshold not controllable)", i)
                sensors_skipped += 1
                continue

            low_value = self.sensor_class.get_low_critical_threshold(platform_api_conn, i)
            if not self.expect(isinstance(low_value, (float, int)),
                               f"Sensor {i} low critical threshold '{low_value}' appears incorrect"):
                continue
            low_value += 1

            result = self.sensor_class.set_low_critical_threshold(platform_api_conn, i, low_value)
            if not self.expect(result is True,
                               f"Failed to set set_low_critical_threshold for sensor {i} to {low_value}"):
                continue

            value = self.sensor_class.get_low_critical_threshold(platform_api_conn, i)
            if not self.expect(isinstance(value, (float, int)),
                               f"Sensor {i} low critical threshold '{value}' appears incorrect"):
                continue

            self.expect(value == low_value,
                        f"Sensor {i} low critical threshold {value} is not matching the set value {low_value}")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' low-critical-threshold is not controllable")

        self.assert_expectations()

    def test_set_high_critical_threshold(
            self,
            duthosts,
            enum_rand_one_per_hwsku_hostname,
            localhost,
            platform_api_conn):
        """
        Test set_high_critical_threshold API to verify all sensors can have their high critical
        threshold set to a specified value successfully

        Args:
            duthosts: DUT hosts where test can operate
            enum_rand_one_per_hwsku_hostname: Randomly selected DUT hostname
            localhost: Unused
            platform_api_conn: Platform API connector
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        sensors_skipped = 0

        # Ensure the sensor value is sane
        for i in range(self.num_sensors):
            if not self.get_sensor_facts(duthost, i, True, "high-critical-threshold"):
                self.logger.info("test_set_high_critical_threshold: Skipping sensor %s (threshold not supported)", i)
                sensors_skipped += 1
                continue
            if not self.get_sensor_facts(duthost, i, True, "controllable"):
                self.logger.info(
                    "test_set_high_critical_threshold: Skipping sensor %s (threshold not controllable)",
                    i)
                sensors_skipped += 1
                continue

            high_value = self.sensor_class.get_high_critical_threshold(platform_api_conn, i)
            if not self.expect(isinstance(high_value, (float, int)),
                               f"Sensor {i} high critical threshold '{high_value}' appears incorrect"):
                continue
            high_value -= 1

            result = self.sensor_class.set_high_critical_threshold(platform_api_conn, i, high_value)
            if not self.expect(result is True,
                               f"Failed to set set_high_critical_threshold for sensor {i} to {high_value}"):
                continue

            value = self.sensor_class.get_high_critical_threshold(platform_api_conn, i)
            if self.expect(isinstance(value, (float, int)),
                           f"Sensor {i} high critical threshold '{value}' appears incorrect"):
                continue

            self.expect(value == high_value,
                        f"Sensor {i} high critical threshold {value} is not matching the set value {high_value}")

        if sensors_skipped == self.num_sensors:
            pytest.skip("skipped as all chassis sensors' high-critical-threshold is not controllable")

        self.assert_expectations()
