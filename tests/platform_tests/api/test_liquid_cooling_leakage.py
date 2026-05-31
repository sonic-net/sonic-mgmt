"""Platform API tests for the Liquid Cooling Leakage class."""
import logging
import pytest


from tests.common.helpers.platform_api import liquid_cooling, leak_sensor
from .platform_api_test_base import PlatformApiTestBase
from tests.common.platform.device_utils import platform_api_conn    # noqa: F401
from tests.common.platform.device_utils import start_platform_api_service    # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
    pytest.mark.device_type('physical')
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


class TestLiquidCoolingLeakage(PlatformApiTestBase):
    ''' Platform API test cases for the Liquid Cooling Leakage class'''

    leak_sensors = None
    leak_sensors_num = None

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn, duthosts, enum_rand_one_per_hwsku_hostname):  # noqa: F811
        """Resolve expected leak sensors from chassis.leak_sensors in platform.json."""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        chassis_facts = duthost.facts.get("chassis") or {}
        self.leak_sensors = chassis_facts.get("leak_sensors") or []
        self.leak_sensors_num = len(self.leak_sensors)
        if self.leak_sensors_num == 0:
            pytest.skip("No leak sensors declared in platform.json")

    def test_get_name(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(self.leak_sensors_num):
            name = leak_sensor.get_name(platform_api_conn, leak_sensor_id)
            if self.expect(name is not None, f"Unable to retrieve leak sensor {leak_sensor_id} name"):
                self.expect(isinstance(name, str),
                            f"The value type of leakage{leak_sensor_id} is not str")
                expected_name = self.leak_sensors[leak_sensor_id].get("name")
                if expected_name is not None:
                    self.expect(name == expected_name,
                                f"leakage{leak_sensor_id} name mismatch, "
                                f"expected: {expected_name}, actual: {name}")
        self.assert_expectations()

    def test_is_leak(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(self.leak_sensors_num):
            is_leak = leak_sensor.is_leak(platform_api_conn, leak_sensor_id)
            if self.expect(is_leak is not None, f"Unable to retrieve leak sensor {leak_sensor_id} is_leak"):
                self.expect(isinstance(is_leak, bool),
                            f"The value type of leakage{leak_sensor_id} is not bool")
                self.expect(is_leak is False,
                            f"leakage{leak_sensor_id} reports a leak (is_leak=True)")
        self.assert_expectations()

    def test_get_leak_sensor_status(self, platform_api_conn):    # noqa: F811
        leak_sensor_status_list = liquid_cooling.get_leak_sensor_status(platform_api_conn)
        if leak_sensor_status_list:
            self.expect(False, f"There is a leak sensor with status {leak_sensor_status_list}")
        self.assert_expectations()

    def test_get_num_leak_sensors(self, platform_api_conn):    # noqa: F811
        api_leak_sensor_num = liquid_cooling.get_num_leak_sensors(platform_api_conn)
        if self.expect(api_leak_sensor_num is not None, "Unable to retrieve number of leak sensors"):
            self.expect(api_leak_sensor_num == self.leak_sensors_num,
                        f"Number of leak sensors mismatch, expected: {self.leak_sensors_num}, "
                        f"actual: {api_leak_sensor_num}")
        self.assert_expectations()

    def test_get_all_leak_sensors(self, platform_api_conn):    # noqa: F811
        api_leak_sensor_list = liquid_cooling.get_all_leak_sensors(platform_api_conn)
        logger.info(f"Leak sensor list: {api_leak_sensor_list}")
        assert len(api_leak_sensor_list) == self.leak_sensors_num, \
            f"Leak sensor list length mismatch, expected: {self.leak_sensors_num}, actual: {len(api_leak_sensor_list)}"
