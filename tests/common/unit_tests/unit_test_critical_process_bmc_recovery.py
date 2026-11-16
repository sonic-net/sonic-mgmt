"""Exercise BMC critical-process recovery without testbed dependencies."""

import ast
import logging
import os
from pathlib import Path
import shlex
import unittest
from unittest.mock import Mock, call


MODULE_PATH = Path(__file__).resolve().parents[2] / 'process_monitoring' / 'test_critical_process_monitoring.py'
BMC_HELPER_PATH = Path(__file__).resolve().parents[1] / 'platform' / 'bmc_utils.py'


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def _load_function(name, namespace, module_path=MODULE_PATH):
    tree = ast.parse(module_path.read_text(encoding='utf-8'))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    function.decorator_list = []
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(module_path), 'exec'), namespace)
    return namespace[name]


class TestBmcSystemCycle(unittest.TestCase):
    """Verify capability checks, expected disconnects, and restart evidence."""

    def setUp(self):
        self.bmc = Mock(hostname='bmc-dut')
        self.switch_host = Mock(hostname='inventory-switch-cpu')
        self.bmc.get_bmc_host.return_value = self.switch_host
        self.bmc.shell.side_effect = [{}, {'stdout': 'before'}, {}, {'stdout': 'after'}]
        self.localhost = Mock()
        self.namespace = dict(shlex=shlex, logger=logging.getLogger(__name__), pytest_assert=_assert,
                              wait_for_shutdown=Mock(), wait_for_startup=Mock(),
                              wait_until=lambda timeout, interval, delay, check: check())
        self.helper = _load_function('power_cycle_via_bmc', self.namespace, BMC_HELPER_PATH)

    def recover(self):
        self.helper(self.bmc, self.localhost, startup_timeout=1200)

    def test_cycle_and_restart(self):
        """Call the system cycle once and verify shutdown and startup."""
        self.recover()
        self.assertIn('do_system_power_cycle()', self.bmc.shell.call_args_list[2].args[0])
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

    def test_shutdown_and_startup_failures(self):
        """Propagate a failure to observe either edge of the restart."""
        for operation in ('wait_for_shutdown', 'wait_for_startup'):
            with self.subTest(operation=operation):
                self.setUp()
                self.namespace[operation].side_effect = RuntimeError('timeout')
                with self.assertRaisesRegex(RuntimeError, 'timeout'):
                    self.recover()


class TestRecoveryRouting(unittest.TestCase):
    """Run the production fixture teardown until its startup wait."""

    def setUp(self):
        self.duthost = Mock(hostname='dut', facts={})
        self.localhost = Mock()
        self.namespace = dict(
            logger=logging.getLogger(__name__), os=os, pytest=Mock(),
            get_skip_containers=Mock(return_value=[]), get_containers_namespace_ids=Mock(return_value={}),
            is_vs_device=Mock(return_value=False), power_cycle_via_bmc=Mock(),
            get_pdu_controller=Mock(return_value=None), pdu_reboot=Mock(return_value=True), pytest_assert=_assert,
            wait_for_shutdown=Mock(), wait_for_startup=Mock(side_effect=RuntimeError('startup boundary')),
            REBOOT_SHUTDOWN_TIMEOUT_SEC=300, REBOOT_TYPE_COLD='cold',
            reboot_ctrl_dict={'cold': {'timeout': 300}}, get_plt_reboot_ctrl=Mock(return_value={}))
        self.fixture = _load_function('recover_critical_processes', self.namespace)

    def recover(self, tbinfo):
        generator = self.fixture(
            {'dut': self.duthost}, 'dut', tbinfo, [], self.localhost, self.namespace['get_pdu_controller'])
        next(generator)
        with self.assertRaisesRegex(RuntimeError, 'startup boundary'):
            next(generator)

    def test_bmc_dual_mgmt(self):
        """The exact BMC topology uses system power cycling without a PDU."""
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['get_pdu_controller'].assert_called_once_with(self.duthost)
        self.namespace['pdu_reboot'].assert_not_called()
        self.namespace['power_cycle_via_bmc'].assert_called_once_with(
            self.duthost, self.localhost, startup_timeout=1200)
        self.duthost.shell.assert_not_called()
        self.assertEqual(self.namespace['wait_for_startup'].call_args.kwargs['timeout'], 1200)

    def test_bmc_with_pdu(self):
        """An available PDU takes precedence over the BMC system cycle."""
        controller = Mock()
        self.namespace['get_pdu_controller'].return_value = controller
        self.recover({'topo': {'name': 'bmc-dual-mgmt'}})
        self.namespace['pdu_reboot'].assert_called_once_with(controller)
        self.namespace['power_cycle_via_bmc'].assert_not_called()
        self.duthost.shell.assert_not_called()
        self.assertEqual(self.namespace['wait_for_startup'].call_args.kwargs['timeout'], 300)

    def test_pdu_failure_stops_recovery(self):
        """A failed PDU cycle must not fall through to BMC cycling or startup."""
        self.namespace['get_pdu_controller'].return_value = Mock()
        self.namespace['pdu_reboot'].return_value = False
        generator = self.fixture(
            {'dut': self.duthost}, 'dut', {'topo': {'name': 'bmc-dual-mgmt'}}, [], self.localhost,
            self.namespace['get_pdu_controller'])
        next(generator)
        with self.assertRaisesRegex(AssertionError, 'PDU reboot failed'):
            next(generator)
        self.namespace['power_cycle_via_bmc'].assert_not_called()
        self.namespace['wait_for_startup'].assert_not_called()

    def test_shared_helper_import(self):
        """Process monitoring must import the reusable helper instead of duplicating it."""
        tree = ast.parse(MODULE_PATH.read_text(encoding='utf-8'))
        self.assertTrue(any(
            isinstance(node, ast.ImportFrom) and node.module == 'tests.common.platform.bmc_utils'
            and any(alias.name == 'power_cycle_via_bmc' for alias in node.names)
            for node in tree.body))
        self.assertFalse(any(
            isinstance(node, ast.FunctionDef) and node.name == 'power_cycle_via_bmc'
            for node in tree.body))

    def test_other_topologies(self):
        """Preserve regular reboot for other or missing topology names."""
        for topology in ('t1', 'bmc', 'bmc-single-mgmt', ''):
            with self.subTest(topology=topology):
                self.setUp()
                self.recover({'topo': {'name': topology, 'type': 'bmc'}})
                self.namespace['power_cycle_via_bmc'].assert_not_called()
                self.namespace['get_pdu_controller'].assert_not_called()
                self.assertIn('sudo reboot', self.duthost.shell.call_args.args[0])
                self.namespace['wait_for_shutdown'].assert_called_once()

    def test_missing_topology(self):
        """Absent metadata must not enable system power cycling."""
        self.recover({})
        self.namespace['power_cycle_via_bmc'].assert_not_called()

    def test_platform_timeout_preserved(self):
        """The real helper's first SSH wait must use the effective timeout."""
        for platform_timeout, effective_timeout in ((300, 1200), (900, 1200), (1800, 1800)):
            with self.subTest(platform_timeout=platform_timeout):
                self.setUp()
                self.namespace['get_plt_reboot_ctrl'].return_value = {'timeout': platform_timeout}
                self.duthost.shell.side_effect = [{}, {'stdout': 'before'}, {}, {'stdout': 'after'}]
                self.namespace.update(
                    shlex=shlex, pytest_assert=_assert,
                    wait_until=lambda timeout, interval, delay, check: check())
                self.namespace['power_cycle_via_bmc'] = _load_function(
                    'power_cycle_via_bmc', self.namespace, BMC_HELPER_PATH)
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
        self.namespace['power_cycle_via_bmc'].assert_not_called()
        self.assertIn('/proc/sysrq-trigger', self.duthost.shell.call_args.args[0])

    def test_cycle_failure_stops_recovery(self):
        """Never continue startup checks after an unverified system cycle."""
        self.namespace['power_cycle_via_bmc'].side_effect = RuntimeError('cycle failed')
        generator = self.fixture(
            {'dut': self.duthost}, 'dut', {'topo': {'name': 'bmc-dual-mgmt'}}, [], self.localhost,
            self.namespace['get_pdu_controller'])
        next(generator)
        with self.assertRaisesRegex(RuntimeError, 'cycle failed'):
            next(generator)
        self.namespace['wait_for_startup'].assert_not_called()


if __name__ == '__main__':
    unittest.main()