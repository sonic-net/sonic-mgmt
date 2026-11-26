"""Exercise BMC critical-process recovery without testbed dependencies."""

import ast
from collections import namedtuple
import os
from pathlib import Path
import re
import shlex
import unittest
from unittest.mock import Mock, call, patch

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / 'process_monitoring' / 'test_critical_process_monitoring.py'
BMC_HELPER_PATH = Path(__file__).resolve().parents[1] / 'platform' / 'bmc_utils.py'


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def _load_function(name, namespace, module_path=MODULE_PATH):
    helper_tree = ast.parse(BMC_HELPER_PATH.read_text(encoding='utf-8'))
    hwskus = next(node.value for node in helper_tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'PSU_SYSTEM_POWER_CYCLE_HWSKUS'
                          for target in node.targets))
    namespace.setdefault('PSU_SYSTEM_POWER_CYCLE_HWSKUS', ast.literal_eval(hwskus))
    tree = ast.parse(module_path.read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    function.decorator_list = []
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(module_path), 'exec'), namespace)
    return namespace[name]


class TestBmcSystemCycle(unittest.TestCase):
    """Verify capability checks, expected disconnects, and restart evidence."""

    def setUp(self):
        self.bmc = Mock(hostname='bmc-dut', facts={'hwsku': 'Arista-7060XE7-64PRS'})
        self.switch_host = Mock(hostname='inventory-switch-cpu')
        self.switch_host.shell.side_effect = [{'stdout': 'switch-before'}, {'stdout': 'switch-after'}]
        self.bmc.get_bmc_host.return_value = self.switch_host
        self.bmc.shell.side_effect = [{}, {'stdout': 'before'}, {}, {'stdout': 'after'}]
        self.localhost = Mock()
        self.namespace = dict(shlex=shlex, logger=Mock(), pytest_assert=_assert,
                              wait_for_shutdown=Mock(), wait_for_startup=Mock(),
                              wait_until=lambda timeout, interval, delay, check: check())
        _load_function('check_power_cycle_via_psu', self.namespace, BMC_HELPER_PATH)
        self.helper = _load_function('power_cycle_via_psu', self.namespace, BMC_HELPER_PATH)

    def recover(self):
        self.helper(self.bmc, self.localhost, startup_timeout=1200)

    def test_cycle_and_restart(self):
        """Call the system cycle once and verify shutdown and startup."""
        self.recover()
        self.assertIn('host.do_system_power_cycle()', self.bmc.shell.call_args_list[2].args[0])
        self.assertNotIn('do_chassis_power_cycle', self.bmc.shell.call_args_list[2].args[0])
        self.namespace['wait_for_shutdown'].assert_called_once_with(
            self.bmc, self.localhost, delay=0, timeout=180)
        self.bmc.get_bmc_host.assert_called_once_with()
        self.assertEqual(self.namespace['wait_for_startup'].call_args_list, [
            call(self.bmc, self.localhost, delay=10, timeout=1200),
            call(self.switch_host, self.localhost, delay=10, timeout=1200)])

    def test_missing_switch_host_mapping(self):
        """Fail before cycling if the testbed cannot resolve bmc_host."""
        self.bmc.get_bmc_host.side_effect = AssertionError('bmc_host field not defined in testbed YAML')
        with self.assertRaisesRegex(AssertionError, 'bmc_host field not defined'):
            self.recover()
        self.bmc.shell.assert_not_called()

    def test_switch_host_startup_failure(self):
        """A returned BMC must not hide a switch CPU that remains down."""
        self.namespace['wait_for_startup'].side_effect = [None, RuntimeError('switch host timeout')]
        with self.assertRaisesRegex(RuntimeError, 'switch host timeout'):
            self.recover()

    def test_unsupported_api(self):
        """A failed capability probe prevents the destructive call."""
        self.bmc.shell.side_effect = RuntimeError('unsupported API')
        with self.assertRaisesRegex(RuntimeError, 'unsupported API'):
            self.recover()
        self.assertEqual(self.bmc.shell.call_count, 1)

    def test_unlisted_helper_rejected(self):
        """The reusable helper must not probe or cycle any unlisted SKU."""
        for hwsku in ('Nokia-IXR7220-H6-128', 'Arista-7060X6-64PE', 'arista-7060XE7-64PRS', None):
            with self.subTest(hwsku=hwsku):
                self.setUp()
                self.bmc.facts = {'hwsku': hwsku}
                with self.assertRaisesRegex(AssertionError, 'restricted to allowlisted SKUs'):
                    self.recover()
                self.bmc.shell.assert_not_called()
                self.switch_host.shell.assert_not_called()

    def test_future_allowlisted_sku(self):
        """Adding a SKU to the shared list enables the reusable helper."""
        self.namespace['PSU_SYSTEM_POWER_CYCLE_HWSKUS'].append('Arista-Future-SKU')
        self.bmc.facts['hwsku'] = 'Arista-Future-SKU'
        self.recover()

    def test_expected_disconnect(self):
        """SSH disconnect during the cycle still requires restart verification."""
        self.bmc.shell.side_effect = [
            {}, {'stdout': 'before'}, RuntimeError('disconnected'), {'stdout': 'after'}]
        self.recover()
        self.assertEqual(self.namespace['wait_for_startup'].call_count, 2)

    def test_unchanged_boot_id(self):
        """SSH availability alone cannot prove that the cycle occurred."""
        self.bmc.shell.side_effect = [{}, {'stdout': 'before'}, {}, {'stdout': 'before'}]
        with self.assertRaisesRegex(AssertionError, 'boot ID did not change'):
            self.recover()

    def test_missing_boot_id(self):
        """Require a baseline boot ID before cycling power."""
        self.bmc.shell.side_effect = [{}, {'stdout': ''}]
        with self.assertRaisesRegex(AssertionError, 'Could not read boot ID'):
            self.recover()
        self.assertEqual(self.bmc.shell.call_count, 2)

    def test_missing_switch_boot_id(self):
        """Do not cycle without a baseline for both devices."""
        self.switch_host.shell.side_effect = [{'stdout': ''}]
        with self.assertRaisesRegex(AssertionError, 'Could not read boot ID'):
            self.recover()
        self.assertEqual(self.bmc.shell.call_count, 2)

    def test_unchanged_switch_boot_id(self):
        """A BMC reboot alone is not a full-chassis power cycle."""
        self.switch_host.shell.side_effect = [{'stdout': 'switch-before'}, {'stdout': 'switch-before'}]
        with self.assertRaisesRegex(AssertionError, 'Switch host .* boot ID did not change'):
            self.recover()

    def test_transient_boot_id_read_failure(self):
        """Retry transient SSH failures while collecting restart evidence."""
        self.bmc.shell.side_effect = [
            {}, {'stdout': 'before'}, {}, RuntimeError('SSH not ready'), {'stdout': 'after'}]

        def retry(timeout, interval, delay, check):
            return check() or check()

        self.namespace['wait_until'] = retry
        self.recover()

    def test_shutdown_and_startup_failures(self):
        """Propagate a failure to observe either edge of the restart."""
        for operation in ('wait_for_shutdown', 'wait_for_startup'):
            with self.subTest(operation=operation):
                self.setUp()
                self.namespace[operation].side_effect = RuntimeError('timeout')
                with self.assertRaisesRegex(RuntimeError, 'timeout'):
                    self.recover()


class TestPsuSystemPowerCycleSupport(unittest.TestCase):
    """Execute the remote probe against the platform's system power-cycle API."""

    def test_capability_contract(self):
        """Require a callable system-cycle operation without invoking it."""
        for operation in (Mock(), None, False):
            with self.subTest(operation=operation):
                host = Mock(spec=[])
                host.get_name = Mock(return_value='SWITCH-HOST')
                host.do_power_cycle = Mock()
                if operation is not None:
                    host.do_system_power_cycle = operation
                chassis = Mock()
                chassis.get_all_modules.return_value = [host]
                bmc = Mock(facts={'hwsku': 'Arista-7060XE7-64PRS'})
                namespace = dict(shlex=shlex, pytest_assert=_assert)
                check = _load_function('check_power_cycle_via_psu', namespace, BMC_HELPER_PATH)
                check(bmc)
                command = shlex.split(bmc.shell.call_args.args[0])[-1]
                with patch.dict('sys.modules', {
                        'sonic_platform': Mock(),
                        'sonic_platform.chassis': Mock(Chassis=Mock(return_value=chassis))}):
                    if callable(operation):
                        exec(command, {})
                    else:
                        with self.assertRaisesRegex(AssertionError, 'Platform does not support system'):
                            exec(command, {})
                if callable(operation):
                    operation.assert_not_called()
                host.do_power_cycle.assert_not_called()


class TestRecoveryRouting(unittest.TestCase):
    """Run the production fixture teardown until its startup wait."""

    def setUp(self):
        self.duthost = Mock(hostname='dut', facts={'hwsku': 'Arista-7060XE7-64PRS'})
        self.duthost.command.return_value = {
            'rc': 0, 'stdout': '00000000-0000-0000-0000-000000000001'}
        self.localhost = Mock()
        self.namespace = dict(
            logger=Mock(), os=os, re=re, pytest=pytest,
            DatabaseRecovery=namedtuple('DatabaseRecovery', 'method controller boot_id'),
            BOOT_ID_COMMAND='cat /proc/sys/kernel/random/boot_id',
            get_skip_containers=Mock(return_value=[]), get_containers_namespace_ids=Mock(return_value={}),
            is_vs_device=Mock(return_value=False), power_cycle_via_psu=Mock(),
            check_power_cycle_via_psu=Mock(),
            _submit_os_reboot_and_wait_for_shutdown=Mock(return_value=None),
            get_pdu_controller=Mock(return_value=None), pdu_reboot=Mock(return_value=True), pytest_assert=_assert,
            wait_for_shutdown=Mock(), wait_for_startup=Mock(side_effect=RuntimeError('startup boundary')),
            wait_until=lambda timeout, interval, delay, check, *args: check(*args),
            REBOOT_SHUTDOWN_TIMEOUT_SEC=300, REBOOT_TYPE_COLD='cold',
            reboot_ctrl_dict={'cold': {'timeout': 300}}, get_plt_reboot_ctrl=Mock(return_value={}))
        for function in ('_read_boot_id', '_admit_database_recovery', '_boot_id_changed'):
            _load_function(function, self.namespace)
        self.fixture = _load_function('recover_critical_processes', self.namespace)

    def start_recovery(self, tbinfo):
        return self.fixture(
            {'dut': self.duthost}, 'dut', tbinfo, [],
            get_pdu_controller=self.namespace['get_pdu_controller'], localhost=self.localhost)

    def recover(self, tbinfo):
        generator = self.start_recovery(tbinfo)
        next(generator)
        with self.assertRaisesRegex(RuntimeError, 'startup boundary'):
            next(generator)

    def test_bmc_dual_mgmt(self):
        """The exact BMC topology uses Arista system cycling without a PDU."""
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['get_pdu_controller'].assert_called_once_with(self.duthost, require_complete=True)
        self.namespace['check_power_cycle_via_psu'].assert_called_once_with(self.duthost)
        self.namespace['pdu_reboot'].assert_not_called()
        self.namespace['power_cycle_via_psu'].assert_called_once_with(
            self.duthost, self.localhost, startup_timeout=1200)
        self.duthost.shell.assert_not_called()
        self.assertEqual(self.namespace['wait_for_startup'].call_args.kwargs['timeout'], 1200)

    def test_bmc_with_pdu(self):
        """An available PDU takes precedence over the BMC system cycle."""
        controller = Mock()
        self.namespace['get_pdu_controller'].return_value = controller
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['pdu_reboot'].assert_called_once_with(controller)
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.namespace['check_power_cycle_via_psu'].assert_not_called()
        self.duthost.shell.assert_not_called()
        self.assertEqual(self.namespace['wait_for_startup'].call_args.kwargs['timeout'], 300)

    def test_unsupported_platform_fails_before_test(self):
        """Reject unsupported recovery before yielding to the destructive test."""
        self.namespace['check_power_cycle_via_psu'].side_effect = RuntimeError('unsupported API')
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        with self.assertRaisesRegex(RuntimeError, 'unsupported API'):
            next(generator)
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.duthost.shell.assert_not_called()

    def test_database_skipped_needs_no_power_cycle(self):
        """Do not require power-cycle support when database is excluded."""
        self.namespace['get_skip_containers'].return_value = ['database']
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        next(generator)
        self.namespace['check_power_cycle_via_psu'].assert_not_called()
        self.namespace['get_pdu_controller'].assert_not_called()
        generator.close()

    def test_unlisted_and_missing_sku(self):
        """All unlisted SKUs, including other Arista models, retain software recovery."""
        for hwsku in ('Nokia-IXR7220-H6-128', 'Mellanox-SN3800', 'Arista-7060X6-64PE',
                      'Arista-7060XE7-64PRS-P128X4', 'arista-7060XE7-64PRS', ''):
            with self.subTest(hwsku=hwsku):
                self.setUp()
                self.duthost.facts = {'hwsku': hwsku} if hwsku else {}
                self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
                self.namespace['check_power_cycle_via_psu'].assert_not_called()
                self.namespace['power_cycle_via_psu'].assert_not_called()
                self.namespace['pdu_reboot'].assert_not_called()
                self.namespace['_submit_os_reboot_and_wait_for_shutdown'].assert_called_once_with(
                    self.duthost, self.localhost)
                self.duthost.shell.assert_not_called()
                self.assertEqual(self.namespace['wait_for_startup'].call_args.kwargs['timeout'], 300)

    def test_allowlist_initial_contents(self):
        """The initial allowlist contains exactly the requested SKU."""
        self.assertEqual(self.namespace['PSU_SYSTEM_POWER_CYCLE_HWSKUS'], ['Arista-7060XE7-64PRS'])

    def test_additional_sku_uses_same_allowlist(self):
        """Adding a future SKU enables fixture routing without another code change."""
        self.namespace['PSU_SYSTEM_POWER_CYCLE_HWSKUS'].append('Arista-Future-SKU')
        self.duthost.facts['hwsku'] = 'Arista-Future-SKU'
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['power_cycle_via_psu'].assert_called_once()

    def test_non_arista_pdu_preserved(self):
        """An available BMC PDU remains usable without an Arista API probe."""
        self.duthost.facts['hwsku'] = 'Nokia-IXR7220-H6-128'
        controller = Mock()
        self.namespace['get_pdu_controller'].return_value = controller
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['pdu_reboot'].assert_called_once_with(controller)
        self.namespace['check_power_cycle_via_psu'].assert_not_called()
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.duthost.shell.assert_not_called()

    def test_pdu_failure_stops_recovery(self):
        """A failed PDU cycle must not fall through to BMC cycling or startup."""
        self.namespace['get_pdu_controller'].return_value = Mock()
        self.namespace['pdu_reboot'].return_value = False
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        next(generator)
        with self.assertRaisesRegex(AssertionError, 'PDU reboot failed'):
            next(generator)
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.namespace['wait_for_startup'].assert_not_called()

    def test_shared_helper_import(self):
        """Process monitoring must import the reusable helper instead of duplicating it."""
        tree = ast.parse(MODULE_PATH.read_text(encoding='utf-8'))
        self.assertTrue(any(
            isinstance(node, ast.ImportFrom) and node.module == 'tests.common.platform.bmc_utils'
            and any(alias.name == 'power_cycle_via_psu' for alias in node.names)
            for node in tree.body))
        self.assertFalse(any(
            isinstance(node, ast.FunctionDef) and node.name == 'power_cycle_via_psu'
            for node in tree.body))

    def test_other_topologies(self):
        """Preserve regular reboot for other or missing topology names."""
        for topology in ('t1', 'bmc', 'bmc-single-mgmt', ''):
            with self.subTest(topology=topology):
                self.setUp()
                self.recover({'topo': {'name': topology, 'type': 'bmc'}})
                self.namespace['power_cycle_via_psu'].assert_not_called()
                self.namespace['get_pdu_controller'].assert_called_once_with(self.duthost, require_complete=True)
                self.namespace['_submit_os_reboot_and_wait_for_shutdown'].assert_called_once_with(
                    self.duthost, self.localhost)
                self.duthost.shell.assert_not_called()

    def test_missing_topology(self):
        """Absent metadata must not enable system power cycling."""
        self.recover({})
        self.namespace['power_cycle_via_psu'].assert_not_called()

    def test_platform_timeout_preserved(self):
        """The real helper's first SSH wait must use the effective timeout."""
        for platform_timeout, effective_timeout in ((300, 1200), (900, 1200), (1800, 1800)):
            with self.subTest(platform_timeout=platform_timeout):
                self.setUp()
                self.namespace['get_plt_reboot_ctrl'].return_value = {'timeout': platform_timeout}
                self.duthost.shell.side_effect = [{}, {}, {'stdout': 'before'}, {}, {'stdout': 'after'}]
                self.namespace.update(
                    shlex=shlex, pytest_assert=_assert,
                    wait_until=lambda timeout, interval, delay, check: check())
                switch_host = self.duthost.get_bmc_host.return_value
                switch_host.shell.side_effect = [{'stdout': 'switch-before'}, {'stdout': 'switch-after'}]
                _load_function('check_power_cycle_via_psu', self.namespace, BMC_HELPER_PATH)
                self.namespace['power_cycle_via_psu'] = _load_function(
                    'power_cycle_via_psu', self.namespace, BMC_HELPER_PATH)
                self.namespace['wait_for_startup'].side_effect = [None, None, RuntimeError('startup boundary')]
                self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
                startup_calls = self.namespace['wait_for_startup'].call_args_list
                self.assertEqual(len(startup_calls), 3)
                self.assertIs(startup_calls[1].args[0], self.duthost.get_bmc_host.return_value)
                for startup_call in startup_calls:
                    self.assertEqual(startup_call.kwargs['timeout'], effective_timeout)

    def test_virtual_switch_unchanged(self):
        """Non-BMC virtual switches retain the existing SysRq reboot."""
        self.namespace['is_vs_device'].return_value = True
        self.recover({'topo': {'name': 't0'}})
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.assertIn('/proc/sysrq-trigger', self.duthost.shell.call_args.args[0])

    def test_cycle_failure_stops_recovery(self):
        """Never continue startup checks after an unverified system cycle."""
        self.namespace['power_cycle_via_psu'].side_effect = RuntimeError('cycle failed')
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        next(generator)
        with self.assertRaisesRegex(RuntimeError, 'cycle failed'):
            next(generator)
        self.namespace['wait_for_startup'].assert_not_called()

    def test_pdu_lookup_failure_aborts_admission(self):
        """A configured PDU failure is not absence, even on an allowlisted SKU."""
        self.namespace['get_pdu_controller'].side_effect = ValueError('incomplete configured PDU')
        with self.assertRaisesRegex(ValueError, 'incomplete configured PDU'):
            next(self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}}))
        self.namespace['check_power_cycle_via_psu'].assert_not_called()
        self.namespace['power_cycle_via_psu'].assert_not_called()
        self.duthost.command.assert_not_called()

    def test_admitted_psu_route_is_frozen(self):
        """Do not resolve a different controller after destructive work begins."""
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        next(generator)
        self.namespace['get_pdu_controller'].return_value = Mock()
        with self.assertRaisesRegex(RuntimeError, 'startup boundary'):
            next(generator)
        self.namespace['get_pdu_controller'].assert_called_once_with(self.duthost, require_complete=True)
        self.namespace['power_cycle_via_psu'].assert_called_once_with(
            self.duthost, self.localhost, startup_timeout=1200)
        self.namespace['pdu_reboot'].assert_not_called()

    def test_psu_recovery_preserves_upstream_health_gates(self):
        """A full-system cycle must still satisfy authenticated boot and database checks."""
        self.duthost.command.side_effect = [
            {'rc': 0, 'stdout': '00000000-0000-0000-0000-000000000001'},
            {'rc': 0, 'stdout': '00000000-0000-0000-0000-000000000002'},
        ]
        self.duthost.shell.return_value = {'rc': 0, 'stdout': 'PONG'}
        self.duthost.critical_services_fully_started.return_value = True
        self.namespace['wait_for_startup'].side_effect = None
        self.namespace.update(
            POST_CHECK_THRESHOLD_SECS=600, config_reload=Mock(),
            get_config_reload_wait=Mock(return_value=120),
            ensure_all_critical_processes_running=Mock(),
            postcheck_critical_processes_status=Mock(return_value=True))
        generator = self.start_recovery({'topo': {'name': 'bmc-dual-mgmt'}})
        next(generator)
        with self.assertRaises(StopIteration):
            next(generator)
        self.namespace['power_cycle_via_psu'].assert_called_once()
        self.namespace['config_reload'].assert_called_once()
        self.namespace['ensure_all_critical_processes_running'].assert_called_once()
        self.duthost.critical_services_fully_started.assert_called_once()
        self.namespace['postcheck_critical_processes_status'].assert_called_once()


if __name__ == '__main__':
    unittest.main()