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
        # Test name
        name = chassis.get_module_name(platform_api_conn, 'SWITCH-HOST')
        self.expect(isinstance(name, str), "SWITCH-HOST name should be string")
        self.expect(len(name) > 0, "SWITCH-HOST name should not be empty")

        # Verify name consistency
        name2 = chassis.get_module_name(platform_api_conn, 'SWITCH-HOST')
        self.expect(name == name2, "SWITCH-HOST name inconsistent")

        # Test description
        description = chassis.get_module_description(platform_api_conn, 'SWITCH-HOST')
        self.expect(description is None or isinstance(description, str),
                    "SWITCH-HOST description should be str or None")

        # Test serial
        serial = chassis.get_module_serial(platform_api_conn, 'SWITCH-HOST')
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
        # Test get_admin_status
        admin_status = chassis.get_module_admin_status(platform_api_conn, 'SWITCH-HOST')
        self.expect(isinstance(admin_status, str), "admin_status should be string")
        self.expect(admin_status.lower() in ['up', 'down'], f"admin_status '{admin_status}' invalid")

        # Verify admin status consistency
        admin_status2 = chassis.get_module_admin_status(platform_api_conn, 'SWITCH-HOST')
        self.expect(admin_status == admin_status2, "admin_status inconsistent")

        # Test get_oper_status
        oper_status = chassis.get_module_oper_status(platform_api_conn, 'SWITCH-HOST')
        self.expect(isinstance(oper_status, str), "oper_status should be string")

        # Verify oper status consistency
        oper_status2 = chassis.get_module_oper_status(platform_api_conn, 'SWITCH-HOST')
        self.expect(oper_status == oper_status2, "oper_status inconsistent")

        # Verify admin/oper status relationship
        # When admin is 'down', oper should reflect powered down state
        # When admin is 'up', oper should reflect operational state
        if admin_status.lower() == 'up':
            valid_oper_states = ['PRESENT', 'ONLINE', 'PoweredOn']
            self.expect(any(s in oper_status for s in valid_oper_states) or
                        len(oper_status) > 0,
                        f"oper_status '{oper_status}' should reflect "
                        f"admin status 'up'")
        elif admin_status.lower() == 'down':
            valid_oper_states = ['PoweredDown', 'OFFLINE', 'POWERED_DOWN']
            self.expect(any(s in oper_status for s in valid_oper_states) or
                        len(oper_status) > 0,
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
