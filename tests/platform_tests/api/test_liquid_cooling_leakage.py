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

    num_leak_sensors = None

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):  # noqa: F811
        """Resolve number of leak sensors from the platform API; skip if unavailable or 0."""
        try:
            self.num_leak_sensors = liquid_cooling.get_num_leak_sensors(platform_api_conn)
        except Exception as e:
            pytest.skip(f"Platform API get_num_leak_sensors not available: {e}")
        if not self.num_leak_sensors:
            pytest.skip("No leak sensors reported by platform API")

    def test_get_name(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(self.num_leak_sensors):
            name = leak_sensor.get_name(platform_api_conn, leak_sensor_id)
            if self.expect(name is not None, f"Unable to retrieve leak sensor {leak_sensor_id} name"):
                self.expect(isinstance(name, str) and len(name) > 0,
                            f"leakage{leak_sensor_id} name must be a non-empty string, got {name!r}")
        self.assert_expectations()

    def test_is_leak(self, platform_api_conn):    # noqa: F811
        for leak_sensor_id in range(self.num_leak_sensors):
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
            details = []
            for idx, sensor in enumerate(leak_sensor_status_list):
                sensor_name = getattr(sensor, 'name', None) or getattr(sensor, 'sensor_name', None)
                sensor_status = getattr(sensor, 'status', None) or getattr(sensor, 'leak_sensor_status', None)
                sensor_is_leak = getattr(sensor, 'is_leak', None)
                details.append(
                    f"[{idx}] type={type(sensor).__name__} "
                    f"name={sensor_name!r} status={sensor_status!r} "
                    f"is_leak={sensor_is_leak!r} repr={sensor!r}"
                )
            self.expect(
                False,
                "There is a leak sensor with active status:\n{}".format("\n".join(details))
            )
        self.assert_expectations()

    def test_get_all_leak_sensors(self, platform_api_conn):    # noqa: F811
        api_leak_sensor_list = liquid_cooling.get_all_leak_sensors(platform_api_conn)
        logger.info(f"Leak sensor list: {api_leak_sensor_list}")
        assert len(api_leak_sensor_list) == self.num_leak_sensors, \
            f"Leak sensor list length mismatch, expected: {self.num_leak_sensors}, actual: {len(api_leak_sensor_list)}"
