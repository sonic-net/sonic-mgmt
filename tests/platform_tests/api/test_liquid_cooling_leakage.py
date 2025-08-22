import logging
import pytest


from tests.common.helpers.platform_api import chassis, liquid_cooling_leakage
from .platform_api_test_base import PlatformApiTestBase
from tests.common.platform.device_utils import platform_api_conn    # noqa: F401
from tests.common.platform.device_utils import start_platform_api_service    # noqa: F401
from tests.common.mellanox_data import get_platform_data

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]


class TestLiquidCoolingLeakage(PlatformApiTestBase):
    ''' Platform API test cases for the Liquid Cooling Leakage class'''

    leak_sensors_num = None
    chassis_facts = None

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):  # noqa: F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_data = get_platform_data(duthost)
        self.leak_sensors_num = platform_data['leak_sensors']['number']

    def test_get_name(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(0, self.leak_sensors_num):
            name = liquid_cooling_leakage.get_name(platform_api_conn, leak_sensor_id)
            if self.expect(name is not None, f"Unable to retrieve liquid cooling leakage {leak_sensor_id} name"):
                self.expect(
                    isinstance(name, str), f"The value type of leakage{leak_sensor_id} is not str")
            if name != f"leakage{leak_sensor_id + 1}":
                self.expect(False, f"leakage{leak_sensor_id} name is incorrect, \
                 expected: leakage{leak_sensor_id + 1}, actual: {name}")
        self.assert_expectations()

    def test_is_leak(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(0, self.leak_sensors_num):
            is_leak = liquid_cooling_leakage.is_leak(platform_api_conn, leak_sensor_id)
            if self.expect(is_leak is not None, f"Unable to retrieve liquid cooling leakage {leak_sensor_id} is leak"):
                self.expect(
                    isinstance(is_leak, bool), f"The value type of leakage{leak_sensor_id} is not bool")
            if is_leak:
                self.expect(False, f"leakage{leak_sensor_id} is incorrect, \
                 expected: False, actual: {is_leak}")
        self.assert_expectations()

    def test_get_leak_sensor_status(self, platform_api_conn):    # noqa: F811
        leak_sensor_status_list = liquid_cooling_leakage.get_leak_sensor_status(platform_api_conn)
        if leak_sensor_status_list:
            self.expect(False, f"There is a leak sensor with status {leak_sensor_status_list}")
        self.assert_expectations()

    def test_get_num_leak_sensors(self, platform_api_conn):    # noqa: F811
        api_leak_sensor_num = liquid_cooling_leakage.get_num_leak_sensors(platform_api_conn)
        assert api_leak_sensor_num == self.leak_sensors_num, \
            f"Leak sensor number mismatch, expected: {self.leak_sensors_num}, actual: {api_leak_sensor_num}"

    def test_get_all_leak_sensors(self, platform_api_conn):    # noqa: F811
        api_leak_sensor_list = liquid_cooling_leakage.get_all_leak_sensors(platform_api_conn)
        logger.info(f"Leak sensor list: {api_leak_sensor_list}")
        assert len(api_leak_sensor_list) == self.leak_sensors_num, \
            f"Leak sensor list length mismatch, expected: {self.leak_sensors_num}, actual: {len(api_leak_sensor_list)}"
