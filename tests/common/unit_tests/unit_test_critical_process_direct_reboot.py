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


class Failed(BaseException):
    """Match pytest.fail.Exception inheritance, not AssertionError."""


def require(condition, message):
    if not condition:
        raise Failed(message)


def fail(message):
    raise Failed(message)


fail.Exception = Failed


class InertFuture:
    def __init__(self, function, args, kwargs):
        self.collected = []
        self.pending = False
        self.error = None
        try:
            self.result = function(*args, **kwargs)
        except Exception as error:
            self.error = error

    def get(self, timeout=None):
        self.collected.append(timeout)
        if self.pending:
            raise TimeoutError('submission still pending')
        if self.error is not None:
            raise self.error
        return self.result

    def ready(self):
        return not self.pending


class InertPool:
    def __init__(self):
        self.closed = False
        self.future = None

    def apply_async(self, function, args, kwargs):
        self.future = InertFuture(function, args, kwargs)
        return self.future

    def close(self):
        self.closed = True


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
            'ThreadPool': self.make_pool, 'monotonic': lambda: 0,
        }
        helper_path = SOURCE.parents[1] / 'common' / 'platform' / 'bmc_utils.py'
        helper_tree = ast.parse(helper_path.read_text())
        hwskus = next(node.value for node in helper_tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'PSU_SYSTEM_POWER_CYCLE_HWSKUS'
                              for target in node.targets))
        self.ns.update(PSU_SYSTEM_POWER_CYCLE_HWSKUS=ast.literal_eval(hwskus),
                       check_power_cycle_via_psu=Mock(), power_cycle_via_psu=Mock())
        tree = ast.parse(SOURCE.read_text())
        names = {'_read_boot_id', '_admit_database_recovery', '_boot_id_changed',
                 '_submit_os_reboot_and_wait_for_shutdown', 'recover_critical_processes'}
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
        self.pools = []

    def make_pool(self, processes):
        self.assertEqual(processes, 1)
        pool = InertPool()
        self.pools.append(pool)
        return pool

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
        self.assertTrue(self.pools[0].closed)
        self.assertEqual(len(self.pools[0].future.collected), 1)

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
        with self.assertRaisesRegex(Failed, 'unavailable'):
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
            with self.assertRaises((Failed, RuntimeError, ConnectionError)):
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
            with self.assertRaises(Failed):
                next(generator)
            self.ns['wait_for_shutdown'].assert_called_once()
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
            with self.assertRaises((Failed, TimeoutError, RuntimeError)) as caught:
                next(generator)
            if boundary in ['shutdown', 'startup', 'unchanged']:
                self.assertIs(caught.exception.__cause__, disconnect)
            else:
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.reboot_dispatch_diagnostic['authenticated_changed_boot_verified'])
            self.assertEqual([call.args[0] for call in self.dut.command.call_args_list].count('/sbin/reboot'), 1)

    def test_known_connection_error_outside_dispatch_is_not_reclassified(self):
        disconnect = AnsibleConnectionFailure('admission lookup failed')
        self.controller.side_effect = disconnect
        with self.assertRaises(AnsibleConnectionFailure) as caught:
            next(self.fixture())
        self.assertIs(caught.exception, disconnect)
        self.ns['wait_for_shutdown'].assert_not_called()
        self.dut.command.assert_not_called()

    def test_blocked_submission_down_up_window_observed_before_result_collection(self):
        events = []
        error = AnsibleConnectionFailure('delivered after SSH was back')
        future = Mock()
        future.ready.return_value = True

        def get(timeout):
            self.assertEqual(events, ['submitted', 'ssh-down-up-observed'])
            self.assertGreater(timeout, 0)
            events.append('collected')
            raise error

        future.get.side_effect = get
        pool = Mock()
        pool.apply_async.side_effect = lambda *args: events.append('submitted') or future
        self.ns['ThreadPool'] = Mock(return_value=pool)
        self.ns['wait_for_shutdown'].side_effect = lambda *args, **kwargs: events.append('ssh-down-up-observed')
        result = self.ns['_submit_os_reboot_and_wait_for_shutdown'](self.dut, Mock())
        self.assertIs(result, error)
        self.assertEqual(events, ['submitted', 'ssh-down-up-observed', 'collected'])
        pool.apply_async.assert_called_once_with(self.dut.command, ('/sbin/reboot',), {'module_ignore_errors': True})
        pool.close.assert_called_once()
        pool.join.assert_not_called()
        pool.terminate.assert_not_called()

    def test_pending_submission_timeout_retains_owner_and_prevents_health_success(self):
        pool = Mock()
        future = Mock()
        future.ready.return_value = False
        future.get.side_effect = TimeoutError('pending dispatch')
        pool.apply_async.return_value = future
        self.ns['ThreadPool'] = Mock(return_value=pool)
        generator = self.fixture()
        next(generator)
        with self.assertRaises(TimeoutError) as caught:
            next(generator)
        self.assertIs(caught.exception.reboot_dispatch_future, future)
        self.assertIs(caught.exception.reboot_dispatch_pool, pool)
        self.ns['wait_for_startup'].assert_not_called()
        pool.apply_async.assert_called_once()
        pool.close.assert_called_once()
        pool.join.assert_not_called()
        pool.terminate.assert_not_called()

    def test_submission_result_uses_remaining_shutdown_deadline(self):
        self.ns['monotonic'] = Mock(side_effect=[0.25, 5.75, 299.5])
        self.assertIsNone(self.ns['_submit_os_reboot_and_wait_for_shutdown'](self.dut, Mock()))
        self.assertEqual(self.pools[0].future.collected, [0.75])
        self.assertTrue(self.pools[0].closed)
        self.assertEqual(self.ns['wait_for_shutdown'].call_args.kwargs['timeout'], 294)
        self.assertIs(type(self.ns['wait_for_shutdown'].call_args.kwargs['timeout']), int)
        self.assertEqual(self.ns['wait_for_shutdown'].call_args.kwargs['delay'], 0)

    def test_subsecond_or_expired_shutdown_budget_never_calls_ansible_with_zero(self):
        for elapsed in [299.5, 300.0, 300.5]:
            self.setUp()
            self.ns['monotonic'] = Mock(side_effect=[0.0, elapsed, elapsed])
            with self.assertRaisesRegex(TimeoutError, 'positive integer timeout'):
                self.ns['_submit_os_reboot_and_wait_for_shutdown'](self.dut, Mock())
            self.ns['wait_for_shutdown'].assert_not_called()
            self.assertEqual(self.pools[0].future.collected, [max(0, 300.0 - elapsed)])
            self.assertTrue(self.pools[0].closed)
            self.assertEqual([call.args[0] for call in self.dut.command.call_args_list], ['/sbin/reboot'])

    def test_expired_integer_shutdown_budget_still_collects_disconnect_cause(self):
        disconnect = AnsibleConnectionFailure('original dispatch error')
        self.reboot_error = disconnect
        self.ns['monotonic'] = Mock(side_effect=[0.0, 299.5, 299.75])
        with self.assertRaises(TimeoutError) as caught:
            self.ns['_submit_os_reboot_and_wait_for_shutdown'](self.dut, Mock())
        self.assertIs(caught.exception.__cause__, disconnect)
        self.assertEqual(self.pools[0].future.collected, [0.25])
        self.ns['wait_for_shutdown'].assert_not_called()

    def test_expired_shutdown_and_pending_result_preserve_both_failures_and_owner(self):
        future = Mock()
        future.ready.return_value = False
        pending = TimeoutError('submission still pending')
        future.get.side_effect = pending
        pool = Mock()
        pool.apply_async.return_value = future
        self.ns['ThreadPool'] = Mock(return_value=pool)
        self.ns['monotonic'] = Mock(side_effect=[0.0, 300.5, 300.75])
        with self.assertRaisesRegex(TimeoutError, 'positive integer timeout') as caught:
            self.ns['_submit_os_reboot_and_wait_for_shutdown'](self.dut, Mock())
        self.assertIs(caught.exception.__cause__, pending)
        self.assertIs(caught.exception.reboot_dispatch_future, future)
        future.get.assert_called_once_with(timeout=0)
        self.ns['wait_for_shutdown'].assert_not_called()
        pool.close.assert_called_once()

    def classifier(self):
        path = SOURCE.parents[1] / 'common' / 'helpers' / 'host_failure_utils.py'
        tree = ast.parse(path.read_text())
        functions = {'_iter_exception_chain', '_get_dark_hosts', '_get_message', '_is_unreachable_failure',
                     'is_testbed_unreachable_exception'}
        constants = {'MAX_INSPECTED_MESSAGE_LENGTH', 'UNREACHABLE_MARKERS', 'CONNECTIVITY_FAILURE_MARKERS'}
        nodes = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in functions:
                nodes.append(node)
            elif isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id in constants for target in node.targets):
                nodes.append(node)
        namespace = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
        return namespace['is_testbed_unreachable_exception']

    def test_recovered_disconnect_does_not_classify_later_functional_failure_as_unreachable(self):
        classify = self.classifier()
        for boundary in ['database', 'critical', 'postcheck']:
            self.setUp()
            generator = self.fixture()
            next(generator)
            disconnect = AnsibleConnectionFailure('Host unreachable in the inventory')
            disconnect.dark = {'dut': {'unreachable': True}}
            self.reboot_error = disconnect
            self.boot = AFTER
            if boundary == 'database':
                self.failed_ping = 'sonic-db-cli PING'
            elif boundary == 'critical':
                self.ns['ensure_all_critical_processes_running'].side_effect = RuntimeError(
                    'critical process not ready')
            else:
                self.ns['postcheck_critical_processes_status'].return_value = False
            with self.assertRaises((Failed, RuntimeError)) as caught:
                next(generator)
            self.assertFalse(classify(caught.exception, (AnsibleConnectionFailure,)))
            self.assertEqual(caught.exception.reboot_dispatch_diagnostic,
                             {'submission_connection_lost': True, 'authenticated_changed_boot_verified': True})
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_still_unreachable_or_new_connection_failure_remains_classified(self):
        classify = self.classifier()
        for boundary in ['startup', 'after_verified_boot']:
            self.setUp()
            generator = self.fixture()
            next(generator)
            disconnect = AnsibleConnectionFailure('Host unreachable in the inventory')
            disconnect.dark = {'dut': {}}
            self.reboot_error = disconnect
            self.boot = AFTER
            actual = AnsibleConnectionFailure('Host unreachable in the inventory')
            actual.dark = {'dut': {}}
            if boundary == 'startup':
                self.ns['wait_for_startup'].side_effect = actual
            else:
                self.ns['config_reload'].side_effect = actual
            with self.assertRaises(AnsibleConnectionFailure) as caught:
                next(generator)
            self.assertIs(caught.exception, actual)
            self.assertTrue(classify(caught.exception, (AnsibleConnectionFailure,)))
            if boundary == 'startup':
                self.assertIs(caught.exception.__cause__, disconnect)

    def test_boot_poll_retries_specific_failed_outcomes_and_eventually_changes(self):
        responses = [{'rc': 1}, {'rc': 0, 'stdout': 'malformed'}, {'rc': 0, 'stdout': BEFORE},
                     {'rc': 0, 'stdout': AFTER}]
        self.dut.command.side_effect = responses
        self.assertFalse(issubclass(Failed, Exception))
        self.assertEqual([self.ns['_boot_id_changed'](self.dut, BEFORE) for _ in responses],
                         [False, False, False, True])

    def test_boot_poll_cancellation_is_not_swallowed(self):
        for error in [KeyboardInterrupt(), SystemExit(2)]:
            self.dut.command.side_effect = error
            with self.assertRaises(type(error)):
                self.ns['_boot_id_changed'](self.dut, BEFORE)

    def test_unchanged_boot_poll_exhaustion_after_disconnect_retains_cause(self):
        generator = self.fixture()
        next(generator)
        disconnect = AnsibleConnectionFailure('submitted once')
        self.reboot_error = disconnect
        attempts = []

        def poll(timeout, interval, delay, function, *args):
            if function is self.ns['_boot_id_changed']:
                for _ in range(3):
                    attempts.append(function(*args))
                return any(attempts)
            return function(*args)

        self.ns['wait_until'] = poll
        with self.assertRaises(Failed) as caught:
            next(generator)
        self.assertEqual(attempts, [False, False, False])
        self.assertIs(caught.exception.__cause__, disconnect)
        self.ns['config_reload'].assert_not_called()

    def test_pdu_preferred_frozen_and_operation_failure_never_software_falls_back(self):
        pdu = Mock()
        self.controller.return_value = pdu
        generator = self.fixture()
        next(generator)
        self.controller.return_value = None
        self.ns['pdu_reboot'].return_value = False
        with self.assertRaisesRegex(Failed, 'PDU reboot failed'):
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
        with self.assertRaisesRegex(Failed, 'boot ID did not change'):
            self.finish(generator, BEFORE)
        self.ns['config_reload'].assert_not_called()

    def test_all_asic_ping_and_config_gates_retained(self):
        for missing, failed in [('redis1/', None), (None, 'sonic-db-cli -n asic1 PING')]:
            self.setUp()
            self.dut.facts['num_asic'] = 2
            self.missing_file, self.failed_ping = missing, failed
            generator = self.fixture()
            next(generator)
            with self.assertRaisesRegex(Failed, 'not ready'):
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
