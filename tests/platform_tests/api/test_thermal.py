import logging
import pytest

from tests.common.helpers.platform_api import chassis, thermal
from tests.common.utilities import skip_release_for_platform
from tests.common.platform.device_utils import platform_api_conn    # noqa F401

from .platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major >= 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring    # noqa: F821
# END Remove this after we transition to Python 3
###################################################

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]


class TestThermalApi(PlatformApiTestBase):

    num_thermals = None
    chassis_facts = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):     # noqa F811
        if self.num_thermals is None:
            try:
                self.num_thermals = int(chassis.get_num_thermals(platform_api_conn))
            except Exception:
                pytest.fail("num_thermals is not an integer")
            else:
                if self.num_thermals == 0:
                    pytest.skip("No thermals found on device")

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, duthost, key, value):
        expected_values = []
        if duthost.facts.get("chassis").get("thermals"):
            expected_thermals = duthost.facts.get("chassis").get("thermals")
            if expected_thermals:
                for exp_thermal in expected_thermals:
                    thermal_name = exp_thermal.get(key)
                    if thermal_name:
                        expected_values.append(thermal_name)

        if self.expect(len(expected_values) > 0,
                       "Unable to get thermal name list containing thermal '{}' from platform.json file"
                       .format(value)):
            self.expect(value in expected_values,
                        "Thermal name '{}' is not included in {}".format(value, expected_values))

    def get_thermal_facts(self, duthost, thermal_idx, def_value, *keys):
        if duthost.facts.get("chassis"):
            thermals = duthost.facts.get("chassis").get("thermals")
            if thermals:
                value = thermals[thermal_idx]
                for key in keys:
                    value = value.get(key)
                    if value is None:
                        return def_value

                return value

        return def_value

    def get_thermal_temperature(self, duthost, def_value, key):
        if duthost.facts.get("chassis"):
            thermals_temperature = duthost.facts.get("chassis").get("thermal_temperature")
            if thermals_temperature:
                value = thermals_temperature.get(key)
                if value is None:
                    return def_value
                return value
        return def_value

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for i in range(self.num_thermals):
            name = thermal.get_name(platform_api_conn, i)

            if self.expect(name is not None, "Unable to retrieve Thermal {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Thermal {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts(duthost, 'name', name)

        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        for i in range(self.num_thermals):
            presence = thermal.get_presence(platform_api_conn, i)

            if self.expect(presence is not None, "Unable to retrieve thermal {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Thermal {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Thermal {} is not present".format(i))

        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):     # noqa F811
        for i in range(self.num_thermals):
            model = thermal.get_model(platform_api_conn, i)

            if self.expect(model is not None, "Unable to retrieve thermal {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Thermal {} model appears incorrect".format(i))

        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        for i in range(self.num_thermals):
            serial = thermal.get_serial(platform_api_conn, i)

            if self.expect(serial is not None, "Unable to retrieve thermal {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Thermal {} serial number appears incorrect".format(i))

        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        for i in range(self.num_thermals):
            status = thermal.get_status(platform_api_conn, i)

            if self.expect(status is not None, "Unable to retrieve thermal {} status".format(i)):
                self.expect(isinstance(status, bool), "Thermal {} status appears incorrect".format(i))

        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):       # noqa F811
        for i in range(self.num_thermals):
            position = thermal.get_position_in_parent(platform_api_conn, i)
            if self.expect(position is not None, "Failed to perform get_position_in_parent for thermal {}".format(i)):
                self.expect(isinstance(position, int),
                            "Position value must be an integer value for thermal {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):       # noqa F811
        for i in range(self.num_thermals):
            replaceable = thermal.is_replaceable(platform_api_conn, i)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for thermal {}".format(i)):
                self.expect(isinstance(replaceable, bool),
                            "Replaceable value must be a bool value for thermal {}".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in ThermalBase class
    #

    def test_get_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                             platform_api_conn):   # noqa F811
        for i in range(self.num_thermals):
            temperature = thermal.get_temperature(platform_api_conn, i)

            if self.expect(temperature is not None, "Unable to retrieve Thermal {} temperature".format(i)):
                self.expect(isinstance(temperature, float), "Thermal {} temperature appears incorrect".format(i))
        self.assert_expectations()

    def test_get_minimum_recorded(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                  platform_api_conn):       # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            record_supported = self.get_thermal_facts(duthost, i, True, "minimum-recorded")
            if not record_supported:
                logger.info("test_get_minimum_recorded: Skipping thermal {} (not supported)".format(i))
                thermals_skipped += 1
                continue

            min_temperature = self.get_thermal_temperature(duthost, 0, "minimum")
            max_temperature = self.get_thermal_temperature(duthost, 100, "maximum")

            temperature = thermal.get_minimum_recorded(platform_api_conn, i)

            if self.expect(temperature is not None, "Unable to retrieve Thermal {} temperature".format(i)):
                if self.expect(isinstance(temperature, float), "Thermal {} temperature appears incorrect".format(i)):
                    self.expect(temperature > min_temperature and temperature <= max_temperature,
                                "Thermal {} temperature {} reading is not within range".format(i, temperature))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' minimum-recorded is not supported")

        self.assert_expectations()

    def test_get_maximum_recorded(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                  platform_api_conn):       # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            record_supported = self.get_thermal_facts(duthost, i, True, "maximum-recorded")
            if not record_supported:
                logger.info("test_get_maximum_recorded: Skipping thermal {} (not supported)".format(i))
                thermals_skipped += 1
                continue

            min_temperature = self.get_thermal_temperature(duthost, 0, "minimum")
            max_temperature = self.get_thermal_temperature(duthost, 100, "maximum")

            temperature = thermal.get_maximum_recorded(platform_api_conn, i)

            if self.expect(temperature is not None, "Unable to retrieve Thermal {} temperature".format(i)):
                if self.expect(isinstance(temperature, float), "Thermal {} temperature appears incorrect".format(i)):
                    self.expect(temperature > min_temperature and temperature <= max_temperature,
                                "Thermal {} temperature {} reading is not within range".format(i, temperature))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' maximum-recorded is not supported")

        self.assert_expectations()

    def test_get_low_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                               platform_api_conn):      # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "low-threshold")
            logger.info("threshold_supported: {}".format(threshold_supported))
            if not threshold_supported:
                logger.info("test_get_low_threshold: Skipping thermal {} (threshold not supported)".format(i))
                thermals_skipped += 1
                continue

            low_threshold = thermal.get_low_threshold(platform_api_conn, i)

            # Ensure the thermal low threshold temperature is sane
            if self.expect(low_threshold is not None, "Unable to retrieve Thermal {} low threshold".format(i)):
                self.expect(isinstance(low_threshold, float), "Thermal {} low threshold appears incorrect".format(i))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' low-threshold is not supported")

        self.assert_expectations()

    def test_get_high_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                platform_api_conn):     # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "high-threshold")
            if not threshold_supported:
                logger.info("test_get_high_threshold: Skipping thermal {} (threshold not supported)".format(i))
                thermals_skipped += 1
                continue

            high_threshold = thermal.get_high_threshold(platform_api_conn, i)

            # Ensure the thermal high threshold temperature is sane
            if self.expect(high_threshold is not None, "Unable to retrieve Thermal {} high threshold".format(i)):
                self.expect(isinstance(high_threshold, float),
                            "Thermal {} high threshold appears incorrect".format(i))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' high-threshold is not supported")

        self.assert_expectations()

    def test_get_low_critical_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        localhost, platform_api_conn):      # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "low-crit-threshold")
            if not threshold_supported:
                logger.info("test_get_low_critical_threshold: Skipping thermal {} (threshold not supported)".format(i))
                thermals_skipped += 1
                continue

            low_critical_threshold = thermal.get_low_critical_threshold(platform_api_conn, i)

            # Ensure the thermal low critical threshold temperature is sane
            if self.expect(low_critical_threshold is not None,
                           "Unable to retrieve Thermal {} low critical threshold".format(i)):
                self.expect(isinstance(low_critical_threshold, float),
                            "Thermal {} low threshold appears incorrect".format(i))
        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' low-critical-threshold is not supported")

        self.assert_expectations()

    def test_get_high_critical_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                         localhost, platform_api_conn):     # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0

        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "high-crit-threshold")
            if not threshold_supported:
                logger.info("test_get_high_critical_threshold: Skipping thermal {} (threshold not supported)"
                            .format(i))
                thermals_skipped += 1
                continue

            high_critical_threshold = thermal.get_high_critical_threshold(platform_api_conn, i)

            # Ensure the thermal high threshold temperature is sane
            if self.expect(high_critical_threshold is not None,
                           "Unable to retrieve Thermal {} high critical threshold".format(i)):
                self.expect(isinstance(high_critical_threshold, float),
                            "Thermal {} high threshold appears incorrect".format(i))
        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' high-critical-threshold is not supported")

        self.assert_expectations()

    def test_set_low_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                               platform_api_conn):      # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])

        # Ensure the thermal temperature is sane
        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "low-threshold")
            threshold_controllable = self.get_thermal_facts(duthost, i, True, "controllable")
            if not threshold_supported or not threshold_controllable:
                logger.info("test_set_low_threshold: Skipping thermal {} (threshold not supported or controllable)"
                            .format(i))
                thermals_skipped += 1
                continue

            low_temperature = 20
            result = thermal.set_low_threshold(platform_api_conn, i, low_temperature)
            if self.expect(result is not None, "Failed to perform set_low_threshold"):
                self.expect(result is True, "Failed to set set_low_threshold for thermal {} to {}"
                            .format(i, low_temperature))

            temperature = thermal.get_low_threshold(platform_api_conn, i)
            if self.expect(temperature is not None, "Unable to retrieve Thermal {} low threshold".format(i)):
                if self.expect(isinstance(temperature, float), "Thermal {} low threshold appears incorrect".format(i)):
                    self.expect(temperature == 20,
                                "Thermal {} low threshold {} is not matching the set value {}"
                                .format(i, temperature, low_temperature))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' low-threshold is not controllable")

        self.assert_expectations()

    def test_set_high_threshold(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                platform_api_conn):     # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        thermals_skipped = 0
        skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])

        # Ensure the thermal temperature is sane
        for i in range(self.num_thermals):
            threshold_supported = self.get_thermal_facts(duthost, i, True, "high-threshold")
            threshold_controllable = self.get_thermal_facts(duthost, i, True, "controllable")
            if not threshold_supported or not threshold_controllable:
                logger.info("test_set_high_threshold: Skipping thermal {} (threshold not controllable)".format(i))
                thermals_skipped += 1
                continue

            high_temperature = 80
            result = thermal.set_high_threshold(platform_api_conn, i, high_temperature)
            if self.expect(result is not None, "Failed to perform set_high_threshold"):
                self.expect(result is True, "Failed to set set_high_threshold for thermal {} to {}"
                            .format(i, high_temperature))

            temperature = thermal.get_high_threshold(platform_api_conn, i)
            if self.expect(temperature is not None, "Unable to retrieve Thermal {} high threshold".format(i)):
                if self.expect(isinstance(temperature, float),
                               "Thermal {} high threshold appears incorrect".format(i)):
                    self.expect(temperature == 80,
                                "Thermal {} high threshold {} is not matching the set value {}"
                                .format(i, temperature, high_temperature))

        if thermals_skipped == self.num_thermals:
            pytest.skip("skipped as all chassis thermals' high-threshold is not controllable")

        self.assert_expectations()
