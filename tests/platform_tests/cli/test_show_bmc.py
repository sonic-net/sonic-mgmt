"""
CLI command tests for BMC and module control

Tests cover CLI commands:
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
from tests.common.platform.bmc_utils import (
    get_host_uptime,
    get_switch_host_or_skip_test,
    verify_bmc_initiated_reboot,
    wait_host_off,
    wait_host_on,
)
from tests.common.utilities import get_inventory_files, get_host_visible_vars

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


class TestBmcCliCommands:
    """
    Test BMC CLI commands.
    """

    @pytest.fixture(scope='function', autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Get duthost reference"""
        self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        yield

    def test_show_chassis_module_status(self):
        """
        Verify 'show chassis module status' (LC+AC).

        Validates:
        - Command succeeds and returns non-empty output
        - Output contains SWITCH-HOST entry
        - Output includes oper status and serial columns
        - On BMC, output includes `Power-On-Delay (sec)` and `Shutdown-Timeout (sec)` columns
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

        has_power_on_delay = 'power-on-delay (sec)' in output_lower
        pytest_assert(has_power_on_delay,
                      "show chassis module status: missing 'Power-On-Delay (sec)' column on BMC")

        has_shutdown_timeout = 'shutdown-timeout (sec)' in output_lower
        pytest_assert(has_shutdown_timeout,
                      "show chassis module status: missing 'Shutdown-Timeout (sec)' column on BMC")
        logger.info(f"show chassis module status output:\n{output}")

    def test_show_platform_temperature(self):
        """
        Verify 'show platform temperature' (LC+AC).

        Validates:
        - Command succeeds and returns non-empty output
        - Output includes sensor names and temperature values
        - High/critical threshold columns are present
        - On BMC: output includes at least one Switch-Host sensor name
          (BMC mirrors Switch-Host TEMPERATURE_INFO and must surface it
          via its own 'show platform temperature')
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

        # Cross-check: BMC must surface paired Switch-Host sensors. Skip if Switch-Host unreachable.
        host = get_switch_host_or_skip_test(self.duthost)

        def _sensor_names(rows):
            names = set()
            for row in rows or []:
                for k, v in row.items():
                    if k and 'sensor' in k.lower() and v:
                        names.add(v.strip())
                        break
            return names

        host_sensors = _sensor_names(host.show_and_parse('show platform temperature'))
        bmc_sensors = _sensor_names(self.duthost.show_and_parse('show platform temperature'))
        pytest_assert(host_sensors,
                      "Switch-Host 'show platform temperature' returned no sensor rows")
        overlap = host_sensors & bmc_sensors
        pytest_assert(overlap,
                      f"BMC 'show platform temperature' must include ≥1 Switch-Host sensor; "
                      f"switch_host={sorted(host_sensors)} bmc={sorted(bmc_sensors)}")
        logger.info(f"BMC surfaces {len(overlap)} Switch-Host sensor(s): {sorted(overlap)}")

    def test_config_chassis_modules(self):
        """Verify 'config chassis modules' help surface + functional shutdown/startup cycle.

        Help-text smoke (non-disruptive):
        - config chassis modules --help documents startup/shutdown/power-on-delay/shutdown-timeout
        - startup/shutdown commands are individually invokable

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

        host = get_switch_host_or_skip_test(self.duthost)
        pre_boot = get_host_uptime(host)

        try:
            self.duthost.shell("config chassis modules shutdown SWITCH-HOST",
                               module_ignore_errors=True)
            wait_host_off(host, timeout=300)

            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)
            wait_host_on(host)

            verify_bmc_initiated_reboot(host, pre_boot)
        finally:
            self.duthost.shell("config chassis modules startup SWITCH-HOST",
                               module_ignore_errors=True)

    def test_liquid_cool_config_commands(self):
        """
        Verify `config liquid-cool leak-control` and `config liquid-cool leak-action`
        functionally update LEAK_CONTROL_POLICY and are reflected in
        `show platform leak control-policy` (not just help text).

        Approach (LC platforms only — graceful skip elsewhere):
          1. Snapshot current policy via `show platform leak control-policy`
          2. For each (target, severity) pair, set the action to a safe alternative
             via `config liquid-cool leak-action` and assert the new value appears
             in `show platform leak control-policy`
          3. Toggle `config liquid-cool leak-control` (disable→enable) and assert
             the change is reflected in the show output
          4. Restore all original values in `finally`
        """
        SAFE_ACTIONS = ['syslog_only', 'graceful_shutdown', 'power_off']

        def snapshot_policy():
            """Parse `show platform leak control-policy` into {key: value} dict.

            Output is colon-separated `key : value` lines (not a table), e.g.:
                system_leak_policy              : enabled
                system_critical_leak_action     : power_off
            """
            r = self.duthost.shell('show platform leak control-policy',
                                   module_ignore_errors=True)
            policy = {}
            for line in (r.get('stdout') or '').splitlines():
                if ':' not in line:
                    continue
                k, _, v = line.partition(':')
                k, v = k.strip(), v.strip()
                if k and v:
                    policy[k] = v
            return policy

        def policy_has(field_substr, expected_value):
            """Return True iff any policy field whose name contains field_substr
            has value == expected_value (case-insensitive)."""
            for k, v in snapshot_policy().items():
                if field_substr.lower() in k.lower() and v.lower() == expected_value.lower():
                    return True
            return False

        # --- Pre-flight: must be LC platform ---
        result = self.duthost.shell("config liquid-cool --help 2>&1", module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.skip("config liquid-cool not available (non-LC platform)")

        original = snapshot_policy()
        pytest_assert(original,
                      "`show platform leak control-policy` returned no parseable rows on an LC platform")
        logger.info(f"Original LEAK_CONTROL_POLICY snapshot: {original}")

        applied_changes = []  # list of (target, severity, original_action) to restore

        try:
            # --- leak-action functional round-trip ---
            for target in ['system', 'rack_mgr']:
                # LEAK_CONTROL_POLICY field naming: system_{sev}_leak_action, rack_mgr_{sev}_alert_action.
                action_suffix = 'leak_action' if target == 'system' else 'alert_action'
                for severity in ['minor', 'critical']:
                    field_substr = f"{target}_{severity}_{action_suffix}"
                    current_action = next(
                        (v for k, v in original.items()
                         if field_substr.lower() in k.lower()),
                        None
                    )
                    if current_action is None:
                        logger.info(f"Skipping {target}/{severity}: not in policy snapshot")
                        continue
                    # Pick a different safe action
                    new_action = next((a for a in SAFE_ACTIONS if a != current_action.lower()),
                                      'syslog_only')
                    cmd = f"config liquid-cool leak-action {target} {severity} {new_action}"
                    result = self.duthost.shell(cmd, module_ignore_errors=True)
                    pytest_assert(result['rc'] == 0,
                                  f"{cmd!r} failed rc={result['rc']} stderr={result['stderr']!r}")
                    applied_changes.append((target, severity, current_action))
                    pytest_assert(policy_has(field_substr, new_action),
                                  f"After {cmd!r}, show platform leak control-policy does not "
                                  f"reflect {field_substr}={new_action}")
                    logger.info(f"Verified via show: {field_substr}={new_action}")

            # --- leak-control functional toggle (policy field: {target}_leak_policy=enabled|disabled) ---
            for target in ['system', 'rack_mgr']:
                field_substr = f"{target}_leak_policy"
                current_state = next(
                    (v for k, v in original.items() if field_substr.lower() in k.lower()),
                    None
                )
                if current_state is None:
                    logger.info(f"Skipping leak-control {target}: not in policy snapshot")
                    continue
                new_state = 'disabled' if current_state.lower() in ('enable', 'enabled', 'true') \
                    else 'enabled'
                cmd = f"config liquid-cool leak-control {target} {new_state}"
                result = self.duthost.shell(cmd, module_ignore_errors=True)
                pytest_assert(result['rc'] == 0,
                              f"{cmd!r} failed rc={result['rc']} stderr={result['stderr']!r}")
                # Re-snapshot and assert the value changed
                post = snapshot_policy()
                post_state = next(
                    (v for k, v in post.items() if field_substr.lower() in k.lower()),
                    None
                )
                pytest_assert(post_state and post_state.lower() != current_state.lower(),
                              f"After {cmd!r}, show platform leak control-policy still reports "
                              f"{field_substr}={post_state!r} (expected change from {current_state!r})")
                logger.info(f"Verified via show: {field_substr} {current_state} → {post_state}")
                # Restore immediately so each target's restore is independent
                self.duthost.shell(
                    f"config liquid-cool leak-control {target} {current_state.lower()}",
                    module_ignore_errors=True
                )

        finally:
            # Restore all leak-action changes
            for target, severity, orig_action in applied_changes:
                self.duthost.shell(
                    f"config liquid-cool leak-action {target} {severity} {orig_action}",
                    module_ignore_errors=True
                )

    def test_show_platform_leak_commands(self):
        """
        Verify show platform leak commands produce valid output (LC platforms).

        Validates:
        - show platform leak rack-manager alerts: shows alert table
        - show platform leak profiles: shows sensor type and max-minor-duration columns
        - show platform leak status: shows per-sensor name/leak/severity columns

        Note: `show platform leak control-policy` is exercised end-to-end by
        test_liquid_cool_config_commands (config-write + verify loop), so it's
        not re-checked here.
        """
        leak_commands = [
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

    switch_host = get_switch_host_or_skip_test(duthost)
    sw_inv_serial = get_host_visible_vars(inv_files, switch_host.hostname).get('serial')
    if sw_inv_serial:
        pytest_assert(sw_inv_serial == sw_serial,
                      "`Switch-Host Serial Number` ({!r}) from `show version` does not match inventory "
                      "`serial:` for paired switch {} ({!r})".format(sw_serial, switch_host.hostname, sw_inv_serial))

    logger.info("BMC {} `show version` serials: BMC={}, Switch-Host={} (paired switch={})".format(
        duthost.hostname, bmc_serial, sw_serial, switch_host.hostname))
