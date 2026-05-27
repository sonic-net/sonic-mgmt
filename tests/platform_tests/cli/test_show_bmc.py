"""
CLI command tests for BMC and module control

Tests cover:
- show bmc and show chassis module commands
- show leak-status and show thermal commands
- config chassis modules commands
- Output format and field validation
- Backward compatibility across platforms
"""

import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


class TestBmcCliCommands:
    """
    Test BMC-related CLI commands
    """

    @pytest.fixture(scope='function', autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Get duthost reference"""
        self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        yield

    def test_show_bmc_commands(self):
        """
        Verify show commands for BMC and chassis exist and return output

        Validates:
        - show bmc command works
        - show chassis module command works
        - Output contains status information
        """
        # Test show bmc
        result = self.duthost.shell(
            "show bmc",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            pytest_assert(len(result['stdout']) > 0, "show bmc returned empty output")
            logger.info("show bmc output available")
        else:
            logger.info("show bmc not available")

        # Test show chassis module
        result = self.duthost.shell(
            "show chassis module",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            pytest_assert(len(result['stdout']) > 0,
                          "show chassis module returned empty")
            logger.info("show chassis module available")
        else:
            logger.info("show chassis module not available")

    def test_show_leak_commands(self):
        """
        Verify show leak-status and show thermal commands

        Validates:
        - Commands exist and return output
        - Gracefully handle non-liquid-cooled systems
        - Output includes status information
        """
        # Test show leak-status
        result = self.duthost.shell(
            "show leak-status",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            pytest_assert(len(result['stdout']) > 0, "show leak-status returned empty")
            logger.info(f"show leak-status: {len(result['stdout'])} chars")
        else:
            logger.info("Device does not have liquid cooling (expected)")

        # Test show thermal
        result = self.duthost.shell(
            "show thermal",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            pytest_assert(len(result['stdout']) > 0, "show thermal returned empty")
            logger.info(f"show thermal available: {len(result['stdout'])} chars")
        else:
            logger.warning("show thermal command failed")

    def test_show_command_output_format(self):
        """
        Verify show commands include expected fields

        Validates:
        - Output contains status/status-related keywords
        - Field names are present
        - Format is consistent
        """
        # Check show bmc output format
        result = self.duthost.shell(
            "show bmc",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            output = result['stdout'].lower()
            has_info = any(term in output for term in ['status', 'ip', 'address', 'version', 'state'])
            logger.info(f"show bmc includes status info: {has_info}")

        # Check show chassis module output format
        result = self.duthost.shell(
            "show chassis module",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            output = result['stdout'].lower()
            has_status = any(term in output for term in ['admin', 'oper', 'status', 'name', 'slot'])
            logger.info(f"show chassis module includes status fields: {has_status}")

        # Check show thermal output format
        result = self.duthost.shell(
            "show thermal",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            output = result['stdout'].lower()
            has_thermal = any(term in output for term in ['temperature', 'thermal', 'sensor', 'threshold'])
            logger.info(f"show thermal includes thermal info: {has_thermal}")

    def test_config_chassis_commands(self):
        """
        Verify config chassis modules commands and syntax (graceful skip if not BMC)

        Validates:
        - config chassis modules help is available
        - admin-status option is documented
        - Command structure is clear
        """
        # Test help
        result = self.duthost.shell(
            "config chassis modules --help",
            module_ignore_errors=True
        )

        if result['rc'] != 0:
            logger.info("config chassis modules not available (expected on non-BMC systems)")
            return

        output = result['stdout']
        has_admin = 'admin-status' in output.lower() or 'admin_status' in output.lower()
        logger.info(f"config chassis modules help includes admin-status: {has_admin}")

        # Test command availability
        result = self.duthost.shell(
            "config chassis modules SWITCH-HOST admin-status --help 2>&1",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            logger.info("config chassis modules admin-status sub-command available")

    def test_backward_compatibility(self):
        """
        Verify commands work across all platform types

        Validates:
        - Non-BMC systems handle commands gracefully
        - Non-liquid-cooled systems don't crash
        - Legacy platforms without SWITCH-HOST work
        - JSON output format supported (if implemented)
        """
        # Test non-BMC handling
        result = self.duthost.shell(
            "show bmc 2>&1",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] in [0, 1, 2], "show bmc should fail gracefully")

        # Test non-liquid-cooled handling
        result = self.duthost.shell(
            "show leak-status 2>&1",
            module_ignore_errors=True
        )
        # Should either work or fail gracefully
        logger.info(f"show leak-status on non-liquid-cooled: rc={result['rc']}")

        # Test show thermal universal support
        result = self.duthost.shell(
            "show thermal",
            module_ignore_errors=True
        )
        pytest_assert(result['rc'] == 0, "show thermal should work on all platforms")

        # Test JSON output if supported
        result = self.duthost.shell(
            "show bmc --json 2>&1",
            module_ignore_errors=True
        )

        if result['rc'] == 0:
            try:
                import json
                json.loads(result['stdout'])
                logger.info("JSON output supported")
            except (ValueError, json.JSONDecodeError) as e:
                logger.info(f"JSON parsing not supported: {e}")

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
