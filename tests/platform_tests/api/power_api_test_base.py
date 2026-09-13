import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis
from tests.platform_tests.cli.util import get_skip_mod_list
from tests.common.utilities import skip_release

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


class TestPowerApi(PlatformApiTestBase):
    """Shared platform API tests for PSU/PDB-like power units."""

    num_power_units = None

    power_unit_api = None
    power_unit_label = ""
    facts_key = ""

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn, duthosts, enum_rand_one_per_hwsku_hostname):  # noqa: F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if self.num_power_units is None:
            try:
                self.num_power_units = int(self._get_num_power_units(platform_api_conn))
            except Exception:
                self._handle_num_power_units_exception(duthost)
            else:
                if self.num_power_units == 0:
                    self._handle_no_power_units(duthost)

        self.power_unit_skip_list = get_skip_mod_list(duthost, [self.facts_key])

    def _get_num_power_units(self, conn):
        return chassis.get_num_psus(conn)

    def _handle_num_power_units_exception(self, duthost):
        pytest.fail(f"num_{self.facts_key} is not an integer")

    def _handle_no_power_units(self, duthost):
        pytest.skip(f"No {self.facts_key} found on device")

    def _skip_absent_power_unit(self, pu_id, platform_api_conn):
        name = self.power_unit_api.get_name(platform_api_conn, pu_id)
        if name in self.power_unit_skip_list:
            logger.info("Skipping %s %s since it is in skip list", self.power_unit_label, name)
            return True
        return False

    def compare_value_with_platform_facts(self, duthost, key, value, pu_idx):
        expected_value = None
        chassis_facts = duthost.facts.get("chassis")
        if chassis_facts:
            expected_units = chassis_facts.get(self.facts_key)
            if expected_units:
                expected_value = expected_units[pu_idx].get(key)
            else:
                logger.warning("duthost.facts['chassis'] has no '%s' key. Available keys: %s",
                               self.facts_key, list(chassis_facts.keys()))
        else:
            logger.warning("duthost.facts has no 'chassis' key. Available keys: %s",
                           list(duthost.facts.keys()))

        if self.expect(expected_value is not None,
                       f"Unable to get expected value for '{key}' from platform.json file for "
                       f"{self.power_unit_label} {pu_idx}"):
            self.expect(value == expected_value,
                        f"'{key}' value is incorrect. Got '{value}', expected '{expected_value}' "
                        f"for {self.power_unit_label} {pu_idx}")

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa: F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        for i in range(self.num_power_units):
            if self._skip_absent_power_unit(i, platform_api_conn):
                continue
            name = self.power_unit_api.get_name(platform_api_conn, i)
            if self.expect(name is not None, f"Unable to retrieve {self.power_unit_label} {i} name"):
                self.expect(isinstance(name, STRING_TYPE),
                            f"{self.power_unit_label} {i} name appears incorrect")
                self.compare_value_with_platform_facts(duthost, 'name', name, i)
        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        for i in range(self.num_power_units):
            presence = self.power_unit_api.get_presence(platform_api_conn, i)
            name = self.power_unit_api.get_name(platform_api_conn, i)
            if self.expect(presence is not None,
                           f"Unable to retrieve {self.power_unit_label} {i} presence"):
                if self.expect(isinstance(presence, bool),
                               f"{self.power_unit_label} {i} presence appears incorrect"):
                    if name not in self.power_unit_skip_list:
                        self.expect(presence is True, f"{self.power_unit_label} {i} is not present")
        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):   # noqa: F811
        for i in range(self.num_power_units):
            if self._skip_absent_power_unit(i, platform_api_conn):
                continue
            model = self.power_unit_api.get_model(platform_api_conn, i)
            if self.expect(model is not None, f"Unable to retrieve {self.power_unit_label} {i} model"):
                self.expect(isinstance(model, STRING_TYPE),
                            f"{self.power_unit_label} {i} model appears incorrect")
        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        for i in range(self.num_power_units):
            if self._skip_absent_power_unit(i, platform_api_conn):
                continue
            serial = self.power_unit_api.get_serial(platform_api_conn, i)
            if self.expect(serial is not None,
                           f"Unable to retrieve {self.power_unit_label} {i} serial number"):
                self.expect(isinstance(serial, STRING_TYPE),
                            f"{self.power_unit_label} {i} serial number appears incorrect")
        self.assert_expectations()

    def test_get_revision(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release(duthost, ["201811", "201911", "202012"])
        for i in range(self.num_power_units):
            if self._skip_absent_power_unit(i, platform_api_conn):
                continue
            revision = self.power_unit_api.get_revision(platform_api_conn, i)
            if self.expect(revision is not None,
                           f"Unable to retrieve {self.power_unit_label} {i} revision"):
                self.expect(isinstance(revision, STRING_TYPE),
                            f"{self.power_unit_label} {i} revision appears incorrect")
        self.assert_expectations()

    def test_get_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        for i in range(self.num_power_units):
            if self._skip_absent_power_unit(i, platform_api_conn):
                continue
            status = self.power_unit_api.get_status(platform_api_conn, i)
            if self.expect(status is not None, f"Unable to retrieve {self.power_unit_label} {i} status"):
                self.expect(isinstance(status, bool),
                            f"{self.power_unit_label} {i} status appears incorrect")
                self.expect(status is True,
                            f"{self.power_unit_label} {i} status is not True (Power Not Good)")
        self.assert_expectations()

    def test_thermals(self, platform_api_conn):   # noqa: F811
        for device_id in range(self.num_power_units):
            if self._skip_absent_power_unit(device_id, platform_api_conn):
                continue
            try:
                num_thermals = int(self.power_unit_api.get_num_thermals(platform_api_conn, device_id))
            except Exception:
                pytest.fail(f"{self.power_unit_label} {device_id}: num_thermals is not an integer")

            thermal_list = self.power_unit_api.get_all_thermals(platform_api_conn, device_id)
            pytest_assert(thermal_list is not None,
                          f"Failed to retrieve thermals for {self.power_unit_label} {device_id}")
            pytest_assert(isinstance(thermal_list, list) and len(thermal_list) == num_thermals,
                          f"Thermals appear to be incorrect for {self.power_unit_label} {device_id}")

            for i in range(num_thermals):
                thermal = self.power_unit_api.get_thermal(platform_api_conn, device_id, i)
                self.expect(thermal and thermal == thermal_list[i],
                            f"Thermal {i} is incorrect for {self.power_unit_label} {device_id}")

        self.assert_expectations()
