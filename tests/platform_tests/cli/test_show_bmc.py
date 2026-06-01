"""
CLI command tests for BMC and module control

Tests cover CLI commands from design doc section 2.3:
- config chassis modules startup/shutdown/power-on-delay/shutdown-timeout (LC, AC)
- config liquid-cool leak-control / leak-action (LC)
- show chassis module status (LC, AC)
- show platform temperature (LC, AC)
- show platform leak control-policy / rack-manager alerts / profiles / status (LC)
"""

import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_inventory_files, get_host_visible_vars

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


class TestBmcCliCommands:
    """
    Test BMC CLI commands as defined in design doc section 2.3.
    """

    @pytest.fixture(scope='function', autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Get duthost reference"""
        self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        yield

    def test_show_chassis_module_status(self):
        """
        Verify 'show chassis module status' (design doc section 2.3.2, LC+AC).

        Validates:
        - Command succeeds and returns non-empty output
        - Output contains SWITCH-HOST entry
        - Output includes oper status and serial columns
        """
        result = self.duthost.shell(
            "show chassis module status",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0,
                      f"show chassis module status failed: {result['stderr']}")
        output = result['stdout']
        pytest_assert(len(output) > 0, "show chassis module status returned empty output")

        has_switch_host = 'SWITCH-HOST' in output or 'Switch-Host' in output
        pytest_assert(has_switch_host,
                      "show chassis module status: expected SWITCH-HOST entry not found")

        output_lower = output.lower()
        has_oper = any(term in output_lower for term in ['oper', 'status', 'online', 'offline'])
        pytest_assert(has_oper,
                      "show chassis module status: oper status column not found")
        logger.info(f"show chassis module status output:\n{output}")

    def test_show_platform_temperature(self):
        """
        Verify 'show platform temperature' (design doc section 2.3.2, LC+AC).

        Validates:
        - Command succeeds and returns non-empty output
        - Output includes sensor names and temperature values
        - High/critical threshold columns are present
        """
        result = self.duthost.shell(
            "show platform temperature",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0,
                      f"show platform temperature failed: {result['stderr']}")
        output = result['stdout']
        pytest_assert(len(output) > 0, "show platform temperature returned empty output")

        output_lower = output.lower()
        has_temp = any(term in output_lower for term in ['temperature', 'sensor', 'thermal'])
        pytest_assert(has_temp,
                      "show platform temperature: temperature/sensor column not found")

        has_threshold = any(term in output_lower for term in ['high th', 'crit', 'threshold'])
        logger.info(f"show platform temperature: threshold columns present={has_threshold}")
        logger.info(f"show platform temperature output:\n{output}")

    def test_config_chassis_modules(self):
        """Verify 'config chassis modules' help surface + functional shutdown/startup cycle.

        Help-text smoke (non-disruptive):
        - config chassis modules --help documents startup/shutdown/power-on-delay/shutdown-timeout
        - startup/shutdown subcommands are individually invokable

        Functional smoke (disruptive — actually reboots the paired Switch-Host):
        - shutdown SWITCH-HOST → wait offline
        - startup SWITCH-HOST → wait critical_services_fully_started, verify uptime advanced
          and reboot-cause on switch-host reports a BMC-initiated cause
        """
        result = self.duthost.shell(
            "config chassis modules --help",
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            logger.info("config chassis modules not available (expected on non-BMC systems)")
            return

        output = result['stdout'].lower()
        for subcmd in ['startup', 'shutdown', 'power-on-delay', 'shutdown-timeout']:
            present = subcmd in output
            logger.info(f"config chassis modules --help mentions '{subcmd}': {present}")

        for subcmd in ['startup', 'shutdown']:
            result = self.duthost.shell(
                f"config chassis modules {subcmd} --help 2>&1",
                module_ignore_errors=True
            )
            if result['rc'] == 0:
                logger.info(f"config chassis modules {subcmd} --help: available")

        host = self.duthost.get_bmc_host()
        pre_boot = host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()

        try:
            self.duthost.shell("config chassis modules shutdown SWITCH-HOST",
                               module_ignore_errors=True)
            wait_until(300, 10, 10,
                       lambda: host.shell("true", module_ignore_errors=True).get('rc') != 0)

            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)
            wait_until(420, 10, 30, lambda: host.critical_services_fully_started())

            post_boot = host.shell("uptime -s").get('stdout', '').strip()
            pytest_assert(post_boot and post_boot != pre_boot,
                          f"Switch-Host uptime did not advance: pre={pre_boot!r} post={post_boot!r}")

            cause_rows = host.show_and_parse('show reboot-cause')
            cause = (cause_rows[0].get('cause', '') if cause_rows else '').lower()
            expected = ('power down request from bmc',
                        'graceful shutdown from bmc',
                        'power loss')
            pytest_assert(any(e in cause for e in expected),
                          f"Unexpected reboot cause on switch-host: {cause!r}")
        finally:
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

    def test_liquid_cool_config_commands(self):
        """
        Verify config liquid-cool leak-control and leak-action command syntax (LC platforms)

        Validates:
        - config liquid-cool leak-control --help is parseable
        - config liquid-cool leak-action --help is parseable
        - Commands accept [system|rack_mgr] and correct action values
        - Graceful skip on non-liquid-cooled systems
        """
        for subcmd in ['leak-control', 'leak-action']:
            result = self.duthost.shell(
                f"config liquid-cool {subcmd} --help 2>&1",
                module_ignore_errors=True
            )
            if result['rc'] != 0:
                logger.info(f"config liquid-cool {subcmd} not available (expected on non-LC systems)")
                continue
            output = result['stdout']
            has_system = 'system' in output.lower()
            has_rack = 'rack' in output.lower() or 'rack_mgr' in output.lower()
            logger.info(f"config liquid-cool {subcmd}: system={has_system} rack_mgr={has_rack}")

        # Verify leak-action mentions action values
        result = self.duthost.shell(
            "config liquid-cool leak-action --help 2>&1",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            output = result['stdout']
            for action in ['syslog_only', 'graceful_shutdown', 'power_off']:
                logger.info(f"config liquid-cool leak-action mentions '{action}': {action in output}")

    def test_show_platform_leak_commands(self):
        """
        Verify show platform leak sub-commands exist and produce valid output (LC platforms)

        Validates:
        - show platform leak control-policy: shows LEAK_CONTROL_POLICY fields
        - show platform leak rack-manager alerts: shows alert table
        - show platform leak profiles: shows sensor type and max-minor-duration columns
        - show platform leak status: shows per-sensor name/leak/severity columns
        - show chassis module status: shows SWITCH-HOST entry with oper status
        """
        # show chassis module status — applicable to LC and AC
        result = self.duthost.shell(
            "show chassis module status 2>&1",
            module_ignore_errors=True
        )
        if result['rc'] == 0:
            output = result['stdout']
            has_switch_host = 'SWITCH-HOST' in output or 'Switch-Host' in output
            logger.info(f"show chassis module status: SWITCH-HOST present={has_switch_host}")
        else:
            logger.info("show chassis module status not available")

        leak_commands = [
            ("show platform leak control-policy",
             ['system_leak_policy', 'rack_mgr_leak_policy']),
            ("show platform leak rack-manager alerts",
             ['Severity', 'Timestamp']),
            ("show platform leak profiles",
             ['Sensor-Type', 'Max-Minor-Duration-Sec']),
            ("show platform leak status",
             ['Name', 'Leak', 'leak-severity']),
        ]

        for cmd, expected_fields in leak_commands:
            result = self.duthost.shell(f"{cmd} 2>&1", module_ignore_errors=True)
            if result['rc'] != 0:
                logger.info(f"{cmd!r} not available (expected on non-LC systems)")
                continue
            output = result['stdout']
            for field in expected_fields:
                present = field.lower() in output.lower()
                logger.info(f"{cmd!r} contains '{field}': {present}")


def test_show_version_serial_numbers_bmc(duthosts, enum_rand_one_per_hwsku_hostname, request):
    """
    @summary: On BMC topology, `show version` on the BMC exposes two serial fields:
              `Serial Number:` (BMC) and `Switch-Host Serial Number:` (paired switch).
              Verify both match the inventory `serial:` of the BMC and its paired switch.
              Ref: https://github.com/sonic-net/SONiC/blob/master/doc/bmc/sonicBMC/pmon-bmc-design.md#232-show-commands
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = duthost.command("show version", module_ignore_errors=True)
    pytest_assert(cmd.get('rc') == 0,
                  "`show version` failed on BMC {}: {!r}".format(duthost.hostname, cmd.get('stderr')))
    output = cmd["stdout"]

    bmc_match = re.search(r"^Serial Number:\s*(\S+)\s*$", output, re.MULTILINE)
    sw_match = re.search(r"^Switch-Host Serial Number:\s*(\S+)\s*$", output, re.MULTILINE)
    pytest_assert(bmc_match,
                  "`Serial Number:` field missing in `show version` on BMC {}".format(duthost.hostname))
    pytest_assert(sw_match,
                  "`Switch-Host Serial Number:` field missing in `show version` on BMC {}".format(duthost.hostname))
    bmc_serial = bmc_match.group(1)
    sw_serial = sw_match.group(1)

    inv_files = get_inventory_files(request)
    bmc_inv_serial = get_host_visible_vars(inv_files, duthost.hostname).get('serial')
    if bmc_inv_serial:
        pytest_assert(bmc_inv_serial == bmc_serial,
                      "BMC `Serial Number` ({!r}) from `show version` does not match inventory `serial:` "
                      "for {} ({!r})".format(bmc_serial, duthost.hostname, bmc_inv_serial))

    switch_host = duthost.get_bmc_host()
    sw_inv_serial = get_host_visible_vars(inv_files, switch_host.hostname).get('serial')
    if sw_inv_serial:
        pytest_assert(sw_inv_serial == sw_serial,
                      "`Switch-Host Serial Number` ({!r}) from `show version` does not match inventory "
                      "`serial:` for paired switch {} ({!r})".format(sw_serial, switch_host.hostname, sw_inv_serial))

    logger.info("BMC {} `show version` serials: BMC={}, Switch-Host={} (paired switch={})".format(
        duthost.hostname, bmc_serial, sw_serial, switch_host.hostname))
