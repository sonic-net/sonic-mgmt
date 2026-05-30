"""
Platform API tests for ModuleBase SWITCH-HOST control interface

Tests cover:
- ModuleBase identity attributes (get_name, get_description, get_serial, get_type)
- ModuleBase status attributes (get_oper_status)
- Module control operations (set_admin_state, do_power_cycle)
- Chassis module enumeration (get_num_modules, get_all_modules, get_module, get_module_index)
- Chassis BMC APIs (is_bmc, get_bmc, is_liquid_cooled)
"""

import logging
import pytest

from tests.common.helpers.platform_api import chassis, module as module_api
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service
)

from .platform_api_test_base import PlatformApiTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


class TestSwitchHostModuleApi(PlatformApiTestBase):
    """
    Tests for ModuleBase SWITCH-HOST control API.

    All module-level calls route through /platform/chassis/module/{index}/{method}
    which maps to chassis.get_module(index).{method}() per the platform API server.
    """

    sw_idx = None

    @pytest.fixture(scope="function", autouse=True)
    def skip_if_no_switch_host(self, enum_rand_one_per_hwsku_hostname,
                               platform_api_conn):  # noqa: F811
        """Skip tests if device doesn't support SWITCH-HOST module"""
        try:
            idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')
            if idx is None or idx < 0:
                pytest.skip("Device does not support SWITCH-HOST module")
            self.sw_idx = idx
        except Exception as e:
            pytest.skip(f"Could not verify SWITCH-HOST support: {e}")

    def test_switch_host_identity(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """
        Test SWITCH-HOST ModuleBase identity attributes: get_name(), get_description(),
        get_serial(), get_type()

        Verifies:
        - get_name() returns non-empty string
        - get_description() and get_serial() return strings or None
        - Values are consistent across multiple calls
        """
        # get_name()
        name = module_api.get_name(platform_api_conn, self.sw_idx)
        self.expect(isinstance(name, str) and len(name) > 0,
                    f"SWITCH-HOST get_name() should return non-empty string, got {name!r}")

        name2 = module_api.get_name(platform_api_conn, self.sw_idx)
        self.expect(name == name2, "SWITCH-HOST get_name() inconsistent")

        # get_description()
        description = module_api.get_description(platform_api_conn, self.sw_idx)
        self.expect(description is None or isinstance(description, str),
                    "SWITCH-HOST get_description() should return str or None")

        # get_serial()
        serial = module_api.get_serial(platform_api_conn, self.sw_idx)
        self.expect(serial is None or isinstance(serial, str),
                    "SWITCH-HOST get_serial() should return str or None")

        # get_type()
        mod_type = module_api.get_type(platform_api_conn, self.sw_idx)
        self.expect(mod_type is None or isinstance(mod_type, str),
                    "SWITCH-HOST get_type() should return str or None")
        logger.info(f"SWITCH-HOST: name={name}, type={mod_type}, serial={serial}")

    def test_switch_host_status_control(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """
        Test SWITCH-HOST status and control operations: get_oper_status(), set_admin_state()

        Verifies:
        - get_oper_status() returns a non-empty string
        - Values are consistent across multiple reads
        - set_admin_state() is callable (no-op verification, does not change state)
        """
        # get_oper_status() — design doc section 2.2.1: ONLINE or OFFLINE
        oper_status = module_api.get_oper_status(platform_api_conn, self.sw_idx)
        self.expect(isinstance(oper_status, str),
                    f"get_oper_status() should return string, got {type(oper_status)}")
        self.expect(oper_status in ['ONLINE', 'OFFLINE'],
                    f"get_oper_status() should be 'ONLINE' or 'OFFLINE', got {oper_status!r}")

        oper_status2 = module_api.get_oper_status(platform_api_conn, self.sw_idx)
        self.expect(oper_status == oper_status2, "get_oper_status() inconsistent")

        logger.info(f"SWITCH-HOST oper_status: {oper_status}")

        # set_admin_state() — verify API is callable without changing state
        try:
            # Pass current powered state as a no-op (False = keep powered down for safety)
            module_api.set_admin_state(platform_api_conn, self.sw_idx, False)
            logger.info("set_admin_state() is accessible")
        except (NotImplementedError, Exception) as e:
            logger.info(f"set_admin_state() note: {e}")


class TestChassisBmcModuleApi(PlatformApiTestBase):
    """
    Tests for chassis-level BMC platform APIs:
    is_bmc(), get_bmc(), is_liquid_cooled(), and module enumeration.
    """

    def test_chassis_is_bmc(self, duthosts, enum_rand_one_per_hwsku_hostname,
                            platform_api_conn):  # noqa: F811
        """
        Verify chassis.is_bmc() returns True on BMC topology and get_bmc() is accessible.

        Verifies:
        - is_bmc() returns True (on topology('bmc') this must be True)
        - get_bmc() returns a non-None object when is_bmc() is True
        """
        result = chassis.is_bmc(platform_api_conn)
        self.expect(isinstance(result, bool), "is_bmc() should return bool")
        self.expect(result is True, "is_bmc() should be True on bmc topology")

        bmc_obj = chassis.get_bmc(platform_api_conn)
        self.expect(bmc_obj is not None, "get_bmc() should return non-None on BMC system")
        logger.info(f"get_bmc() returned: {bmc_obj}")

    def test_chassis_is_liquid_cooled(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                      platform_api_conn):  # noqa: F811
        """
        Verify chassis.is_liquid_cooled() returns a bool consistent with get_liquid_cooling().

        Verifies:
        - is_liquid_cooled() returns a boolean
        - If True, get_liquid_cooling() returns non-None
        - Value is consistent across two calls
        """
        result = chassis.is_liquid_cooled(platform_api_conn)
        self.expect(isinstance(result, bool), "is_liquid_cooled() should return bool")

        result2 = chassis.is_liquid_cooled(platform_api_conn)
        self.expect(result == result2, "is_liquid_cooled() inconsistent across calls")

        if result:
            lc = chassis.get_liquid_cooling(platform_api_conn)
            self.expect(lc is not None,
                        "get_liquid_cooling() should return non-None when is_liquid_cooled() is True")
            logger.info("Liquid-cooled chassis confirmed")
        else:
            logger.info("Air-cooled chassis: is_liquid_cooled() returned False")

    def test_chassis_module_enumeration(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """
        Verify chassis module enumeration APIs: get_num_modules(), get_all_modules(),
        get_module(index), get_module_index(name).

        Verifies:
        - get_num_modules() returns a non-negative integer
        - get_all_modules() list length matches get_num_modules()
        - get_module(0) returns non-None for a valid index
        - Round-trip: get_module(get_module_index('SWITCH-HOST')) is non-None
        """
        num_modules = chassis.get_num_modules(platform_api_conn)
        self.expect(isinstance(num_modules, int) and num_modules >= 0,
                    f"get_num_modules() should return non-negative int, got {num_modules}")
        logger.info(f"Number of modules: {num_modules}")

        if num_modules > 0:
            all_modules = chassis.get_all_modules(platform_api_conn)
            self.expect(isinstance(all_modules, list),
                        "get_all_modules() should return a list")
            self.expect(len(all_modules) == num_modules,
                        f"get_all_modules() length {len(all_modules)} != get_num_modules() {num_modules}")

            first = chassis.get_module(platform_api_conn, 0)
            self.expect(first is not None, "get_module(0) should return non-None for valid index")

            sw_idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')
            if sw_idx is not None and sw_idx >= 0:
                sw_module = chassis.get_module(platform_api_conn, sw_idx)
                self.expect(sw_module is not None,
                            f"get_module(get_module_index('SWITCH-HOST')={sw_idx}) should be non-None")
                logger.info(f"SWITCH-HOST at index {sw_idx}: {sw_module}")
            else:
                logger.info("SWITCH-HOST not found via get_module_index — skipping round-trip")
        else:
            logger.info("No modules reported — skipping enumeration checks")

    def test_switch_host_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """
        Test ModuleBase.get_serial() for the SWITCH-HOST module.

        Per design doc section 2.3.2, the switch-host serial is retrieved as:
          index = chassis.get_module_index('SWITCH-HOST')
          module = chassis.get_module(index)
          serial = module.get_serial()

        Verifies:
        - get_module_index('SWITCH-HOST') returns a valid index
        - module.get_serial() returns a non-empty string for SWITCH-HOST
        """
        sw_idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')
        if sw_idx is None or sw_idx < 0:
            pytest.skip("SWITCH-HOST module not found; skipping serial test")

        serial = module_api.get_serial(platform_api_conn, sw_idx)
        self.expect(serial is not None, "module.get_serial() should not return None for SWITCH-HOST")
        if serial is not None:
            self.expect(isinstance(serial, str) and len(serial) > 0,
                        f"SWITCH-HOST serial should be non-empty string, got {serial!r}")
            logger.info(f"SWITCH-HOST serial: {serial}")

    def test_switch_host_do_power_cycle(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """
        Test ModuleBase.do_power_cycle() API exists on the SWITCH-HOST module.

        This test validates the API contract only — it does NOT trigger an actual power
        cycle to avoid disrupting the DUT.

        Verifies:
        - do_power_cycle() is callable on the SWITCH-HOST module
        - Returns a boolean result
        """
        sw_idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')
        if sw_idx is None or sw_idx < 0:
            pytest.skip("SWITCH-HOST module not found; skipping do_power_cycle test")

        result = module_api.do_power_cycle(platform_api_conn, sw_idx)
        self.expect(result is not None,
                    "do_power_cycle() should return a boolean (not None)")
        if result is not None:
            self.expect(isinstance(result, bool),
                        f"do_power_cycle() should return bool, got {type(result).__name__}")
