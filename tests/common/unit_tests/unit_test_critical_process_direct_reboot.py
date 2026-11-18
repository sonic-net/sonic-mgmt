"""Inert direct-/sbin/reboot controls; execution requires named source gate."""

import ast
from collections import namedtuple
import logging
import os
from pathlib import Path
import re
import unittest
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[2] / 'process_monitoring' / 'test_critical_process_monitoring.py'
BEFORE = '00000000-0000-0000-0000-000000000001'
AFTER = '00000000-0000-0000-0000-000000000002'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fail(message):
    require(False, message)


fail.Exception = AssertionError


class AnsibleConnectionFailure(Exception):
    """Inert stand-in for the inspected pytest_ansible.errors transport class."""


class DirectRebootControls(unittest.TestCase):
    def setUp(self):
        self.boot = BEFORE
        self.probe_rc = 0
        self.reboot_rc = 0
        self.reboot_error = None
        self.failed_ping = None
        self.missing_file = None
        self.dut = Mock(hostname='dut')
        self.dut.facts = {'num_asic': 1, 'platform': 'arbitrary-platform'}
        self.dut.command.side_effect = self.command
        self.dut.shell.side_effect = self.shell
        self.controller = Mock(return_value=None)
        self.ns = {
            'namedtuple': namedtuple, 're': re, 'os': os, 'logger': logging.getLogger(__name__),
            'pytest_assert': require, 'pytest': Mock(fail=fail),
            'AnsibleConnectionFailure': AnsibleConnectionFailure,
            'is_vs_device': Mock(return_value=False), 'get_skip_containers': Mock(return_value=[]),
            'get_containers_namespace_ids': Mock(return_value={'database': [None]}),
            'wait_until': lambda timeout, interval, delay, fn, *args: fn(*args),
            'wait_for_shutdown': Mock(), 'wait_for_startup': Mock(), 'pdu_reboot': Mock(return_value=True),
            'get_plt_reboot_ctrl': Mock(return_value={}), 'REBOOT_TYPE_COLD': 'cold',
            'reboot_ctrl_dict': {'cold': {'timeout': 300}}, 'config_reload': Mock(),
            'get_config_reload_wait': Mock(return_value=120),
            'ensure_all_critical_processes_running': Mock(),
            'postcheck_critical_processes_status': Mock(return_value=True),
            'POST_CHECK_THRESHOLD_SECS': 600,
        }
        tree = ast.parse(SOURCE.read_text())
        names = {'_read_boot_id', '_admit_database_recovery', '_boot_id_changed', 'recover_critical_processes'}
        constants = {'DatabaseRecovery', 'BOOT_ID_COMMAND', 'REBOOT_SHUTDOWN_TIMEOUT_SEC',
                     'MULTI_ASIC_VS_REBOOT_DELAY_SEC'}
        nodes = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                node.decorator_list = []
                nodes.append(node)
            elif isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id in constants for target in node.targets):
                nodes.append(node)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), self.ns)
        self.topology = {'topo': {'name': 'bmc', 'type': 'bmc'}}

    def command(self, command, **kwargs):
        if command == 'cat /proc/sys/kernel/random/boot_id':
            return {'rc': 0, 'stdout': self.boot}
        if command == 'test -x /sbin/reboot':
            return {'rc': self.probe_rc}
        if command == '/sbin/reboot':
            if self.reboot_error:
                raise self.reboot_error
            return {'rc': self.reboot_rc}
        raise AssertionError('Unexpected command: ' + command)

    def shell(self, command, **kwargs):
        if command.startswith('test -f '):
            return {'rc': int(self.missing_file is not None and self.missing_file in command)}
        if command.startswith('sonic-db-cli'):
            return {'rc': int(command == self.failed_ping),
                    'stdout': 'bad' if command == self.failed_ping else 'PONG'}
        if 'sysrq-trigger' in command:
            return {'rc': 0}
        raise AssertionError('Unexpected shell: ' + command)

    def fixture(self):
        return self.ns['recover_critical_processes'](
            {'dut': self.dut}, 'dut', self.topology, [], self.controller, Mock())

    def finish(self, generator, boot=AFTER):
        self.boot = boot
        with self.assertRaises(StopIteration):
            next(generator)

    def test_one_normal_absolute_reboot_then_existing_health_gates(self):
        generator = self.fixture()
        next(generator)
        self.controller.assert_called_once_with(self.dut, require_complete=True)
        self.assertNotIn('/sbin/reboot', [call.args[0] for call in self.dut.command.call_args_list])
        self.finish(generator)
        commands = [call.args[0] for call in self.dut.command.call_args_list]
        self.assertEqual(commands.count('/sbin/reboot'), 1)
        self.assertFalse(any('-f' in command or 'prepare-recovery' in command for command in commands))
        self.ns['wait_for_shutdown'].assert_called_once()
        self.ns['wait_for_startup'].assert_called_once()
        self.ns['config_reload'].assert_called_once()
        self.ns['ensure_all_critical_processes_running'].assert_called_once()
        self.ns['postcheck_critical_processes_status'].assert_called_once()

    def test_current_dual_mgmt_without_pdu_uses_one_normal_bmc_reboot_trial(self):
        self.topology['topo']['name'] = 'bmc-dual-mgmt'
        generator = self.fixture()
        next(generator)
        self.controller.assert_called_once_with(self.dut, require_complete=True)
        self.dut.command.assert_any_call('test -x /sbin/reboot', module_ignore_errors=True)
        self.assertNotIn('/sbin/reboot', [call.args[0] for call in self.dut.command.call_args_list])
        self.finish(generator)
        self.assertEqual([call.args[0] for call in self.dut.command.call_args_list].count('/sbin/reboot'), 1)
        self.ns['wait_for_shutdown'].assert_called_once()
        self.ns['wait_for_startup'].assert_called_once()
        self.ns['config_reload'].assert_called_once()
        self.ns['postcheck_critical_processes_status'].assert_called_once()
        self.ns['pdu_reboot'].assert_not_called()

    def test_probe_failure_prevents_yield(self):
        self.probe_rc = 1
        with self.assertRaisesRegex(AssertionError, 'unavailable'):
            next(self.fixture())
        self.assertEqual([call.args[0] for call in self.dut.command.call_args_list], ['test -x /sbin/reboot'])

    def test_rejection_and_exception_no_retry_forced_fallback_or_health_success(self):
        for failure in [1, RuntimeError('dispatch failed'), ConnectionError('SSH outcome unknown')]:
            self.setUp()
            generator = self.fixture()
            next(generator)
            if isinstance(failure, Exception):
                self.reboot_error = failure
            else:
                self.reboot_rc = failure
            with self.assertRaises((AssertionError, RuntimeError, ConnectionError)):
                next(generator)
            self.assertEqual([call.args[0] for call in self.dut.command.call_args_list].count('/sbin/reboot'), 1)
            self.ns['wait_for_startup'].assert_not_called()
            self.ns['config_reload'].assert_not_called()

    def test_explicit_failed_or_unreachable_result_is_not_transport_exception(self):
        for result in [{'rc': 0, 'failed': True}, {'rc': 0, 'unreachable': True}]:
            self.setUp()
            generator = self.fixture()
            next(generator)
            original = self.dut.command.side_effect
            self.dut.command.side_effect = lambda command, **kwargs: (
                result if command == '/sbin/reboot' else original(command, **kwargs))
            with self.assertRaises(AssertionError):
                next(generator)
            self.ns['wait_for_shutdown'].assert_not_called()
            self.ns['wait_for_startup'].assert_not_called()

    def test_known_dispatch_disconnect_requires_full_verification_without_resend(self):
        disconnect = AnsibleConnectionFailure('transport interrupted during dispatch')
        generator = self.fixture()
        next(generator)
        self.reboot_error = disconnect
        self.finish(generator)
        self.assertEqual([call.args[0] for call in self.dut.command.call_args_list].count('/sbin/reboot'), 1)
        self.ns['wait_for_shutdown'].assert_called_once()
        self.ns['wait_for_startup'].assert_called_once()
        self.ns['config_reload'].assert_called_once()
        self.ns['ensure_all_critical_processes_running'].assert_called_once()
        self.ns['postcheck_critical_processes_status'].assert_called_once()

    def test_dispatch_disconnect_then_timeout_or_unchanged_boot_preserves_cause(self):
        for boundary in ['shutdown', 'startup', 'unchanged', 'database', 'critical', 'postcheck']:
            self.setUp()
            generator = self.fixture()
            next(generator)
            disconnect = AnsibleConnectionFailure('original dispatch disconnect')
            self.reboot_error = disconnect
            if boundary == 'shutdown':
                self.ns['wait_for_shutdown'].side_effect = TimeoutError('no bounded shutdown')
            elif boundary == 'startup':
                self.ns['wait_for_startup'].side_effect = TimeoutError('no bounded startup')
            elif boundary == 'database':
                self.failed_ping = 'sonic-db-cli PING'
            elif boundary == 'critical':
                self.ns['ensure_all_critical_processes_running'].side_effect = RuntimeError('critical not ready')
            elif boundary == 'postcheck':
                self.ns['postcheck_critical_processes_status'].return_value = False
            self.boot = BEFORE if boundary == 'unchanged' else AFTER
            with self.assertRaises((AssertionError, TimeoutError, RuntimeError)) as caught:
                next(generator)
            self.assertIs(caught.exception.__cause__, disconnect)
            self.assertEqual([call.args[0] for call in self.dut.command.call_args_list].count('/sbin/reboot'), 1)

    def test_known_connection_error_outside_dispatch_is_not_reclassified(self):
        disconnect = AnsibleConnectionFailure('admission lookup failed')
        self.controller.side_effect = disconnect
        with self.assertRaises(AnsibleConnectionFailure) as caught:
            next(self.fixture())
        self.assertIs(caught.exception, disconnect)
        self.ns['wait_for_shutdown'].assert_not_called()
        self.dut.command.assert_not_called()

    def test_pdu_preferred_frozen_and_operation_failure_never_software_falls_back(self):
        pdu = Mock()
        self.controller.return_value = pdu
        generator = self.fixture()
        next(generator)
        self.controller.return_value = None
        self.ns['pdu_reboot'].return_value = False
        with self.assertRaisesRegex(AssertionError, 'PDU reboot failed'):
            next(generator)
        self.ns['pdu_reboot'].assert_called_once_with(pdu)
        self.assertNotIn('/sbin/reboot', [call.args[0] for call in self.dut.command.call_args_list])

    def test_strict_pdu_resolution_failure_is_not_absence(self):
        self.controller.side_effect = ValueError('incomplete configured PDU')
        with self.assertRaises(ValueError):
            next(self.fixture())
        self.dut.command.assert_not_called()

    def test_changed_authenticated_boot_is_required(self):
        generator = self.fixture()
        next(generator)
        with self.assertRaisesRegex(AssertionError, 'boot ID did not change'):
            self.finish(generator, BEFORE)
        self.ns['config_reload'].assert_not_called()

    def test_all_asic_ping_and_config_gates_retained(self):
        for missing, failed in [('redis1/', None), (None, 'sonic-db-cli -n asic1 PING')]:
            self.setUp()
            self.dut.facts['num_asic'] = 2
            self.missing_file, self.failed_ping = missing, failed
            generator = self.fixture()
            next(generator)
            with self.assertRaisesRegex(AssertionError, 'not ready'):
                self.finish(generator)
            self.ns['config_reload'].assert_not_called()

    def test_vs_single_and_multi_asic_dispatch_unchanged(self):
        for asics in [1, 2]:
            self.setUp()
            self.ns['is_vs_device'].return_value = True
            self.dut.facts['num_asic'] = asics
            generator = self.fixture()
            next(generator)
            self.finish(generator)
            self.controller.assert_not_called()
            self.assertNotIn('/sbin/reboot', [call.args[0] for call in self.dut.command.call_args_list])
            self.assertEqual(sum('sysrq-trigger' in call.args[0] for call in self.dut.shell.call_args_list),
                             1 if asics == 1 else 0)

    def test_no_database_test_has_no_reboot_admission(self):
        self.ns['get_skip_containers'].return_value = ['database']
        generator = self.fixture()
        next(generator)
        self.finish(generator)
        self.controller.assert_not_called()
        self.dut.command.assert_not_called()
        self.ns['config_reload'].assert_called_once()

    def test_aborted_body_does_not_invent_reset_or_metadata_cleanup(self):
        generator = self.fixture()
        next(generator)
        generator.close()
        self.assertNotIn('/sbin/reboot', [call.args[0] for call in self.dut.command.call_args_list])
        self.ns['config_reload'].assert_not_called()


class PowerGraphAbsenceControls(unittest.TestCase):
    def setUp(self):
        self.harness = DirectRebootControls()
        self.harness.setUp()
        self.dut = self.harness.dut
        self.inventory_host = Mock()
        self.inventory_host.get_vars.return_value = {}
        self.dut.host.options = {'inventory_manager': Mock(_sources=['private-existing-inventory'])}
        self.dut.host.options['inventory_manager'].get_host.return_value = self.inventory_host
        self.ns = {'logger': logging.getLogger(__name__), 'get_graph_facts': Mock(),
                   'get_pdu_visible_vars': Mock(return_value={}), 'pdu_manager_factory': Mock(return_value=None)}
        path = SOURCE.parents[1] / 'common' / 'plugins' / 'pdu_controller' / '__init__.py'
        names = {'_validate_power_graph', '_get_pdu_controller', 'get_pdu_controller'}
        nodes = []
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                node.decorator_list = []
                nodes.append(node)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), self.ns)
        self.initial = {'device_info': {}, 'device_conn': {}, 'device_port_vlans': {}}

    def resolver(self, returned):
        self.ns['get_graph_facts'].return_value = returned
        self.fixture = self.ns['get_pdu_controller'](self.initial, Mock())
        return next(self.fixture)

    def test_successful_unrecognized_empty_graph_reaches_normal_reboot(self):
        resolver = self.resolver(dict(self.initial))
        self.harness.controller = resolver
        generator = self.harness.fixture()
        next(generator)
        self.harness.finish(generator)
        commands = [call.args[0] for call in self.dut.command.call_args_list]
        self.assertIn('test -x /sbin/reboot', commands)
        self.assertEqual(commands.count('/sbin/reboot'), 1)
        self.ns['pdu_manager_factory'].assert_called_once_with('dut', {}, {}, {}, require_complete=True)

    def test_successful_recognized_empty_pdu_maps_are_absence(self):
        resolver = self.resolver({'device_pdu_links': {'dut': {}}, 'device_pdu_info': {'dut': {}}})
        self.assertIsNone(resolver(self.dut, require_complete=True))

    def test_failed_or_unreachable_graph_and_lookup_exception_are_not_absence(self):
        for returned in [dict(self.initial, failed=True), dict(self.initial, unreachable=True),
                         dict(self.initial, rc=2)]:
            with self.subTest(returned=returned):
                resolver = self.resolver(returned)
                with self.assertRaises(ValueError):
                    resolver(self.dut, require_complete=True)
        resolver = self.resolver(dict(self.initial))
        self.ns['get_graph_facts'].side_effect = RuntimeError('actual graph lookup failure')
        with self.assertRaises(RuntimeError):
            resolver(self.dut, require_complete=True)

    def test_malformed_graph_does_not_become_absence(self):
        for returned in [None, {}, {'device_pdu_links': []},
                         {'device_pdu_links': {'dut': []}}, dict(self.initial, device_info=None)]:
            resolver = self.resolver(returned)
            with self.assertRaises(ValueError):
                resolver(self.dut, require_complete=True)

    def test_configured_inventory_pdu_without_graph_mapping_is_error(self):
        self.inventory_host.get_vars.return_value = {'pdu_host': 'configured-pdu'}
        resolver = self.resolver(dict(self.initial))
        with self.assertRaisesRegex(ValueError, 'Configured inventory PDU'):
            resolver(self.dut, require_complete=True)
        self.ns['pdu_manager_factory'].assert_not_called()

    def test_partial_or_unresolved_links_preserve_factory_coverage_error(self):
        resolver = self.resolver({'device_pdu_links': {'dut': {'PSU1': {'Feed1': {'peerdevice': 'pdu'}}}},
                                  'device_pdu_info': {'dut': {}}})
        self.ns['pdu_manager_factory'].side_effect = ValueError('incomplete configured power coverage')
        with self.assertRaisesRegex(ValueError, 'incomplete configured power'):
            resolver(self.dut, require_complete=True)
        self.assertTrue(self.ns['pdu_manager_factory'].call_args.kwargs['require_complete'])


if __name__ == '__main__':
    unittest.main()
