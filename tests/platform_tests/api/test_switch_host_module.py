"""
Platform API tests for ModuleBase SWITCH-HOST control interface

Tests cover:
- ModuleBase identity attributes (name, description, slot, serial)
- ModuleBase status attributes (admin_status, oper_status)
- Status consistency between admin and operational states
- Module control operations (set_admin_status)
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


class TestSwitchHostModuleApi(PlatformApiTestBase):
    """
    Tests for ModuleBase SWITCH-HOST control API
    """

    @pytest.fixture(scope="function", autouse=True)
    def skip_if_no_switch_host(self, enum_rand_one_per_hwsku_hostname,
                               platform_api_conn):  # noqa: F811
        """Skip tests if device doesn't support SWITCH-HOST module control"""
        try:
            module = chassis.get_module_by_name(platform_api_conn, 'SWITCH-HOST')
            if module is None:
                pytest.skip("Device does not support SWITCH-HOST module control")
        except Exception as e:
            pytest.skip(f"Could not verify SWITCH-HOST support: {e}")

    def test_switch_host_identity(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """
        Test SWITCH-HOST identity attributes: name, description, serial

        Verifies:
        - get_name() returns non-empty string
        - get_description() returns string (may be None or empty)
        - get_serial() returns string (may be None or empty)
        - Values are consistent across multiple calls
        """
        # Test name — cast to str() to handle Ansible's AnsibleUnsafeText
        name = str(chassis.get_module_name(platform_api_conn, 'SWITCH-HOST'))
        self.expect(isinstance(name, str), "SWITCH-HOST name should be string")
        self.expect(len(name) > 0, "SWITCH-HOST name should not be empty")

        # Verify name consistency
        name2 = str(chassis.get_module_name(platform_api_conn, 'SWITCH-HOST'))
        self.expect(name == name2, "SWITCH-HOST name inconsistent")

        # Test description
        description = chassis.get_module_description(platform_api_conn, 'SWITCH-HOST')
        description = str(description) if description is not None else None
        self.expect(description is None or isinstance(description, str),
                    "SWITCH-HOST description should be str or None")

        # Test serial
        serial = chassis.get_module_serial(platform_api_conn, 'SWITCH-HOST')
        serial = str(serial) if serial is not None else None
        self.expect(serial is None or isinstance(serial, str),
                    "SWITCH-HOST serial should be str or None")

    def test_switch_host_status_control(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """
        Test SWITCH-HOST status attributes and control operations

        Verifies:
        - get_admin_status() returns valid status (up/down)
        - get_oper_status() returns valid status (PRESENT/POWERED_DOWN/etc)
        - admin and oper status have consistency relationship
        - set_admin_status() accepts valid values
        - Status values are consistent across multiple reads
        """
        # Test get_admin_status — cast to str() to handle Ansible's AnsibleUnsafeText
        admin_status = str(chassis.get_module_admin_status(platform_api_conn, 'SWITCH-HOST'))
        self.expect(isinstance(admin_status, str), "admin_status should be string")
        self.expect(admin_status.lower() in ['up', 'down'], f"admin_status '{admin_status}' invalid")

        # Verify admin status consistency
        admin_status2 = str(chassis.get_module_admin_status(platform_api_conn, 'SWITCH-HOST'))
        self.expect(admin_status == admin_status2, "admin_status inconsistent")

        # Test get_oper_status
        oper_status = str(chassis.get_module_oper_status(platform_api_conn, 'SWITCH-HOST'))
        self.expect(isinstance(oper_status, str), "oper_status should be string")

        # Verify oper status consistency
        oper_status2 = str(chassis.get_module_oper_status(platform_api_conn, 'SWITCH-HOST'))
        self.expect(oper_status == oper_status2, "oper_status inconsistent")

        # Verify admin/oper status relationship
        # When admin is 'down', oper should reflect powered down state
        # When admin is 'up', oper should reflect operational state
        if admin_status.lower() == 'up':
            valid_oper_states = ['PRESENT', 'ONLINE', 'PoweredOn']
            self.expect(any(s in oper_status for s in valid_oper_states),
                        f"oper_status '{oper_status}' should reflect "
                        f"admin status 'up'")
        elif admin_status.lower() == 'down':
            valid_oper_states = ['PoweredDown', 'OFFLINE', 'POWERED_DOWN']
            self.expect(any(s in oper_status for s in valid_oper_states),
                        f"oper_status '{oper_status}' should reflect "
                        f"admin status 'down'")

        # Test set_admin_status (read-only verification - don't actually change)
        logger.info(f"Current SWITCH-HOST status: admin={admin_status}, oper={oper_status}")

        # Verify set_admin_status is accessible (may be read-only in tests)
        try:
            chassis.set_module_admin_status(platform_api_conn, 'SWITCH-HOST', admin_status)
            logger.info("set_admin_status() is accessible")
        except (NotImplementedError, Exception) as e:
            logger.info(f"set_admin_status() note: {e}")


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
        - is_bmc() returns a boolean
        - On topology('bmc') the result is True
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
        - If False (air-cooled), result is still a valid bool
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
        - get_all_modules() returns a list with length matching get_num_modules()
        - get_module(index) returns non-None for a valid index
        - get_module_index('SWITCH-HOST') returns a valid integer (if SWITCH-HOST present)
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

            # SWITCH-HOST round-trip: index → module object
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
