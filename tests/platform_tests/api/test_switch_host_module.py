"""Platform API tests for ModuleBase SWITCH-HOST and chassis BMC APIs."""

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


@pytest.fixture(scope="module", autouse=True)
def skip_if_no_switch_host_module(duthosts, enum_rand_one_per_hwsku_hostname):
    """Skip the module if the chassis does not expose a SWITCH-HOST module."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    probe = (
        "from sonic_platform.chassis import Chassis; "
        "c = Chassis(); "
        "print(c.get_module_index('SWITCH-HOST'))"
    )
    out = duthost.shell(f"python3 -c \"{probe}\"", module_ignore_errors=True)
    if out.get('rc') != 0:
        pytest.skip(f"Could not verify SWITCH-HOST support: {out.get('stderr', '').strip()}")
    idx = -1
    try:
        idx = int(out.get('stdout', '').strip())
    except ValueError:
        pytest.skip("Device does not support SWITCH-HOST module")
    if idx < 0:
        pytest.skip("Device does not support SWITCH-HOST module")


class TestSwitchHostModuleApi(PlatformApiTestBase):
    """Tests for ModuleBase SWITCH-HOST control API."""

    sw_idx = None

    @pytest.fixture(scope="function", autouse=True)
    def resolve_switch_host_index(self, platform_api_conn):  # noqa: F811
        self.sw_idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')

    def test_switch_host_identity(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):  # noqa: F811
        """Verify get_name(), get_description(), get_serial(), get_type()."""
        # get_name()
        name = module_api.get_name(platform_api_conn, self.sw_idx)
        self.expect(isinstance(name, str) and len(name) > 0,
                    f"SWITCH-HOST get_name() should return non-empty string, got {name!r}")

        # get_description()
        description = module_api.get_description(platform_api_conn, self.sw_idx)
        self.expect(description is None or isinstance(description, str),
                    "SWITCH-HOST get_description() should return str or None")

        # get_serial()
        serial = module_api.get_serial(platform_api_conn, self.sw_idx)
        self.expect(isinstance(serial, str) and len(serial) > 0,
                    f"SWITCH-HOST get_serial() should return non-empty string, got {serial!r}")

        # get_type()
        mod_type = module_api.get_type(platform_api_conn, self.sw_idx)
        self.expect(mod_type is None or isinstance(mod_type, str),
                    "SWITCH-HOST get_type() should return str or None")
        logger.info(f"SWITCH-HOST: name={name}, type={mod_type}, serial={serial}")

    def test_switch_host_status_control(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """Disruptive: verify get_oper_status() and drive a real set_admin_state down→up cycle.

        get_oper_status() returns one of the MODULE_STATUS_* constants:
        'Empty', 'Offline', 'PoweredDown', 'Present', 'Fault', 'Online'.
        set_admin_state(up) takes a boolean and returns bool.
        """
        from tests.common.utilities import wait_until

        valid_oper = {'Empty', 'Offline', 'PoweredDown', 'Present', 'Fault', 'Online'}
        down_set = {'Offline', 'PoweredDown'}
        up_set = {'Present', 'Online'}

        oper_status = module_api.get_oper_status(platform_api_conn, self.sw_idx)
        self.expect(isinstance(oper_status, str),
                    f"get_oper_status() should return string, got {type(oper_status)}")
        self.expect(oper_status in valid_oper,
                    f"get_oper_status() should be one of {sorted(valid_oper)}, got {oper_status!r}")
        logger.info(f"SWITCH-HOST initial oper_status: {oper_status}")

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        host = duthost.get_bmc_host()
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()

        try:
            ret = module_api.set_admin_state(platform_api_conn, self.sw_idx, False)
            self.expect(ret is True, f"set_admin_state(False) should return True, got {ret!r}")
            wait_until(180, 10, 0,
                       lambda: module_api.get_oper_status(platform_api_conn, self.sw_idx) in down_set)

            ret = module_api.set_admin_state(platform_api_conn, self.sw_idx, True)
            self.expect(ret is True, f"set_admin_state(True) should return True, got {ret!r}")
            wait_until(420, 10, 30, lambda: host.critical_services_fully_started())

            post_boot = host.shell("uptime -s").get('stdout', '').strip()
            self.expect(post_boot and post_boot != pre_boot,
                        f"Paired switch uptime did not advance: pre={pre_boot!r} post={post_boot!r}")

            cause_out = host.show_and_parse('show reboot-cause')
            cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
            valid_causes = ('power down request from bmc', 'graceful shutdown from bmc', 'power loss')
            self.expect(any(c in cause for c in valid_causes),
                        f"reboot-cause {cause!r} not in expected BMC-initiated set {valid_causes}")

            final_oper = module_api.get_oper_status(platform_api_conn, self.sw_idx)
            self.expect(final_oper in up_set,
                        f"After admin-up, get_oper_status() should be in {sorted(up_set)}, got {final_oper!r}")
        finally:
            module_api.set_admin_state(platform_api_conn, self.sw_idx, True)


class TestChassisBmcModuleApi(PlatformApiTestBase):
    """Tests for chassis-level BMC platform APIs: is_bmc, get_bmc, is_liquid_cooled, module enumeration."""

    def test_chassis_is_bmc(self, duthosts, enum_rand_one_per_hwsku_hostname,
                            platform_api_conn):  # noqa: F811
        """Verify is_bmc() is True and get_bmc() returns non-None on BMC topology."""
        result = chassis.is_bmc(platform_api_conn)
        self.expect(isinstance(result, bool), "is_bmc() should return bool")
        self.expect(result is True, "is_bmc() should be True on bmc topology")

        bmc_obj = chassis.get_bmc(platform_api_conn)
        self.expect(bmc_obj is not None, "get_bmc() should return non-None on BMC system")
        logger.info(f"get_bmc() returned: {bmc_obj}")

    def test_chassis_is_liquid_cooled(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                      platform_api_conn):  # noqa: F811
        """Verify is_liquid_cooled() returns bool; if True, get_liquid_cooling() is non-None."""
        result = chassis.is_liquid_cooled(platform_api_conn)
        self.expect(isinstance(result, bool), "is_liquid_cooled() should return bool")

        if result:
            lc = chassis.get_liquid_cooling(platform_api_conn)
            self.expect(lc is not None,
                        "get_liquid_cooling() should return non-None when is_liquid_cooled() is True")
            logger.info("Liquid-cooled chassis confirmed")
        else:
            logger.info("Air-cooled chassis: is_liquid_cooled() returned False")

    def test_chassis_module_enumeration(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """Verify get_num_modules/get_all_modules/get_module/get_module_index round-trip."""
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

    def test_switch_host_do_power_cycle(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                        platform_api_conn):  # noqa: F811
        """Power-cycle the SWITCH-HOST and verify the paired switch actually came back up.

        Disruptive: triggers a real power cycle on the paired Switch-Host.
        """
        from tests.common.utilities import wait_until

        sw_idx = chassis.get_module_index(platform_api_conn, 'SWITCH-HOST')
        if sw_idx is None or sw_idx < 0:
            pytest.skip("SWITCH-HOST module not found; skipping do_power_cycle test")

        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        host = duthost.get_bmc_host()

        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()
        logger.info(f"Pre-cycle paired switch boot timestamp: {pre_boot!r}")

        result = module_api.do_power_cycle(platform_api_conn, sw_idx)
        self.expect(result is True,
                    f"do_power_cycle() should return True, got {result!r}")

        wait_until(420, 10, 30, lambda: host.critical_services_fully_started())

        post_boot = host.shell("uptime -s").get('stdout', '').strip()
        logger.info(f"Post-cycle paired switch boot timestamp: {post_boot!r}")
        self.expect(post_boot and post_boot != pre_boot,
                    f"Paired switch uptime did not advance: pre={pre_boot!r} post={post_boot!r}")

        cause_out = host.show_and_parse('show reboot-cause')
        self.expect(bool(cause_out), "show reboot-cause returned empty output")
        cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
        valid_causes = ('power down request from bmc', 'graceful shutdown from bmc', 'power loss')
        self.expect(any(c in cause for c in valid_causes),
                    f"reboot-cause {cause!r} not in expected BMC-initiated set {valid_causes}")
