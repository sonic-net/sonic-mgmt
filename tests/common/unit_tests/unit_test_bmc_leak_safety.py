"""Source-isolated regression controls. Do not run until the named source review clears.

No SONiC module is imported: only selected helper/method ASTs are loaded after
review. Fake hosts reject writes. These are not hardware/daemon acceptance tests.
"""

import argparse
import ast
import logging
from pathlib import Path
import random
import re
import shlex
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


TESTS = Path(__file__).resolve().parents[2]
UTILS = TESTS / 'common/platform/bmc_utils.py'
BMC = TESTS / 'platform_tests/daemon/test_bmcctld.py'
THERMAL = TESTS / 'platform_tests/daemon/test_thermalctld.py'
POLICY_KEYS = ('LEAK_CONTROL_POLICY|policy', 'LEAK_CONTROL_POLICY|LEAK_CONTROL_POLICY', 'LEAK_CONTROL_POLICY')


def _assert(condition, message):
    assert condition, message


def _load(path, names):
    tree = ast.parse(path.read_text())
    nodes = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    namespace = dict(argparse=argparse, ast=ast, shlex=shlex, pytest=pytest, pytest_assert=_assert,
                     CONFIG_DB='CONFIG_DB', STATE_DB='STATE_DB', random=random, logger=logging.getLogger(__name__))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


@pytest.fixture
def helpers():
    return _load(UTILS, ('read_bmc_hash', 'get_effective_leak_policy', 'action_is_syslog_only',
                         '_read_pmon_daemon_source', 'is_major_leak_supported', 'get_power_on_block_reason',
                         'get_platform_major_leak_num_min_sensors', 'get_major_leak_min_sensors'))


def _host(rows=None, failure=None):
    rows = rows or {}

    def shell(command, **kwargs):
        args = shlex.split(command)
        assert args[:3] == ['sonic-db-cli', 'CONFIG_DB', 'HGETALL'], 'Unexpected operation: ' + command
        key = args[3]
        if failure is not None and key == failure:
            return {'rc': 1, 'stdout': ''}
        return {'rc': 0, 'stdout': repr(rows.get(key, {}))}

    return SimpleNamespace(shell=Mock(side_effect=shell))


@pytest.mark.parametrize('row_index', [0, 1, 2])
@pytest.mark.parametrize('action,enabled,expected', [
    ('syslog_only', 'enabled', True), ('power_off', 'enabled', False),
    ('graceful_shutdown', 'enabled', False), ('unknown', 'enabled', False),
    ('', 'enabled', False), ('syslog_only', 'disabled', False), ('syslog_only', '', False),
])
def test_effective_policy_admission(helpers, row_index, action, enabled, expected):
    host = _host({POLICY_KEYS[row_index]: {'system_major_leak_action': action, 'system_leak_policy': enabled}})
    assert helpers['action_is_syslog_only'](host, 'system_major_leak_action') is expected


def test_policy_defaults_and_first_existing_row(helpers):
    assert helpers['action_is_syslog_only'](_host(), 'system_major_leak_action')
    assert not helpers['action_is_syslog_only'](_host(), 'system_critical_leak_action')
    # A canonical row containing only an unrelated field still wins; do not merge legacy rows.
    host = _host({POLICY_KEYS[0]: {'other': 'value'}, POLICY_KEYS[1]: {'system_major_leak_action': 'power_off'}})
    assert helpers['action_is_syslog_only'](host, 'system_major_leak_action')
    assert host.shell.call_count == 1


@pytest.mark.parametrize('key', POLICY_KEYS)
def test_failed_read_is_not_absence(helpers, key):
    with pytest.raises(AssertionError, match='Cannot read'):
        helpers['action_is_syslog_only'](_host(failure=key), 'system_major_leak_action')


@pytest.mark.parametrize('output', ['one-field', '{broken}', '{"x": null}', 'a\n1\na\n2'])
def test_malformed_hash_is_not_admitted(helpers, output):
    host = SimpleNamespace(shell=Mock(return_value={'rc': 0, 'stdout': output}))
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        helpers['get_effective_leak_policy'](host)


@pytest.mark.parametrize('daemon,source,expected', [
    ('bmcctld', 'if False:\n    pass\nelif leak_status == SystemLeakStatus.MAJOR:\n'
     '    dispatch("MAJOR_SYSTEM_LEAK")', True),
    ('bmcctld', 'SYSTEM_LEAK_CRITICAL = "CRITICAL"\nSYSTEM_LEAK_MINOR = "MINOR"', False),
    ('thermalctld', 'def _resolve_major_leak_min():\n    return SystemLeakStatus.MAJOR', True),
    ('thermalctld', 'escalated_to_critical = True\nsensor_leak_severity = LeakSeverity.CRITICAL', False),
])
def test_daemon_contract_not_cli_version(helpers, daemon, source, expected):
    host = SimpleNamespace(shell=Mock(return_value={'rc': 0, 'stdout': source}))
    assert helpers['is_major_leak_supported'](host, daemon) is expected
    assert host.shell.call_args.args[0] == 'docker exec pmon cat /usr/local/bin/' + daemon


@pytest.mark.parametrize('result', [
    {'rc': 1, 'stdout': ''}, {'rc': 0, 'stdout': 'unknown = True'},
    {'rc': 0, 'stdout': 'not valid python !'},
])
def test_unknown_capability_is_failure_not_legacy(helpers, result):
    host = SimpleNamespace(shell=Mock(return_value=result))
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        helpers['is_major_leak_supported'](host)


@pytest.mark.parametrize('source,reason', [
    ('POWER_ON_BLOCK_REASON = "POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE"',
     'POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE'),
    ('self._set_cmd_status(key, CMD_STATUS_FAILED, "CRITICAL_LEAK_PRESENT")', 'CRITICAL_LEAK_PRESENT'),
])
def test_power_on_contract_selected_before_command(helpers, source, reason):
    host = SimpleNamespace(shell=Mock(return_value={'rc': 0, 'stdout': source}))
    assert helpers['get_power_on_block_reason'](host) == reason


@pytest.mark.parametrize('result,expected', [
    ({'rc': 0, 'stdout': 'UNSUPPORTED'}, None), ({'rc': 0, 'stdout': '0'}, 0),
    ({'rc': 0, 'stdout': '2'}, 2), ({'rc': 0, 'stdout': '4294967295'}, 4294967295),
])
def test_platform_threshold_response(helpers, result, expected):
    host = SimpleNamespace(shell=Mock(return_value=result))
    assert helpers['get_platform_major_leak_num_min_sensors'](host, default=None) == expected


@pytest.mark.parametrize('result', [
    {'rc': 1, 'stdout': ''}, {'rc': 0, 'stdout': ''},
    {'rc': 0, 'stdout': '1'}, {'rc': 0, 'stdout': 'None'}, {'rc': 0, 'stdout': '4294967296'},
])
def test_platform_threshold_error_not_unsupported(helpers, result):
    with pytest.raises(AssertionError):
        helpers['get_platform_major_leak_num_min_sensors'](SimpleNamespace(shell=Mock(return_value=result)))


def test_live_telemetry_scenario_is_unconditionally_skipped():
    tree = ast.parse(BMC.read_text())
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == 'test_bmcctld_rack_manager_alert_cleared_by_telemetry')
    assert any(ast.unparse(d.func) == 'pytest.mark.skip' for d in method.decorator_list)
    calls = [ast.unparse(n.func) for n in ast.walk(ast.Module(body=method.body, type_ignores=[]))
             if isinstance(n, ast.Call)]
    assert calls == ['pytest.skip']  # No reads, snapshots, writes, finalizers or stale restores.


def test_capacity_rejected_before_min_n_allocation():
    namespace = _load(THERMAL, ('_select_leak_sensor_indices', '_is_eligible_leak_sensor_duration'))
    mocker = SimpleNamespace(sensor_names=['one'], sensors={'one': {'max_minor_duration_sec': 10}})
    with pytest.raises(pytest.skip.Exception):
        namespace['_select_leak_sensor_indices'](mocker, 4294967295, None, None)
    source = THERMAL.read_text()
    method = source[source.index('    def test_thermalctld_leak_severity_aggregation'):]
    assert method.index('_select_leak_sensor_indices(') < method.index("['MINOR'] * len(sensor_indices)")
    assert "['MINOR'] * min_n" not in method


def test_timer_assertion_selects_current_and_legacy_contract():
    source = THERMAL.read_text()
    assert "is_major_leak_supported(self.duthost, 'thermalctld')" in source
    assert "escalation_status = 'MAJOR' if major_supported else 'CRITICAL'" in source
    assert 'leak_mocker, escalation_status, 2 * poll_interval, poll_interval)' in source
    assert 'pytest_assert(\n                    escalated,' in source


@pytest.mark.parametrize('original', [None, '', ' ', '0', '1', '2', '4294967295'])
@pytest.mark.parametrize('failure', [None, 'show', 'partial-write', 'restore-rc', 'readback'])
def test_threshold_cleanup_preserves_raw_presence(helpers, original, failure):
    """Exercise the complete CLI caller with capture-only, local dictionary state."""
    path = TESTS / 'platform_tests/cli/test_show_bmc.py'
    namespace = _load(path, ('test_liquid_cool_config_commands',))
    namespace['read_bmc_hash'] = helpers['read_bmc_hash']
    field = 'system_major_leak_num_min_sensors'
    row = {} if original is None else {field: original}
    changed = False
    restore_attempted = False

    def shell(command, **kwargs):
        nonlocal changed, restore_attempted
        args = shlex.split(command)
        if command == 'show platform leak control-policy':
            value = row.get(field, 'none')
            if changed and failure == 'show':
                value = 'unexpected'
            return {'rc': 0, 'stdout': '{} : {}'.format(field, value if value.strip() else 'none')}
        if args[:3] == ['sonic-db-cli', 'CONFIG_DB', 'HGETALL']:
            if restore_attempted and failure == 'readback':
                return {'rc': 0, 'stdout': repr({field: 'wrong-readback'})}
            return {'rc': 0, 'stdout': repr(row)}
        if args[:3] == ['sonic-db-cli', 'CONFIG_DB', 'HSET']:
            assert args[4] == field
            restore_attempted = True
            if failure == 'restore-rc':
                return {'rc': 1, 'stdout': ''}
            row[field] = args[5]
            return {'rc': 0, 'stdout': '0'}
        if args[:3] == ['sonic-db-cli', 'CONFIG_DB', 'HDEL']:
            assert args[4] == field
            restore_attempted = True
            if failure == 'restore-rc':
                return {'rc': 1, 'stdout': ''}
            row.pop(field, None)
            return {'rc': 0, 'stdout': '1'}
        if '--help' in args:
            return {'rc': 0, 'stdout': ''}
        assert args[:3] == ['config', 'liquid-cool', 'major-leak-threshold'], command
        assert 2 <= int(args[3]) <= 4294967295
        row[field] = args[3]
        changed = True
        return {'rc': 1 if failure == 'partial-write' else 0, 'stdout': '', 'stderr': ''}

    instance = SimpleNamespace(duthost=SimpleNamespace(shell=Mock(side_effect=shell)))
    errors = {'show': 'does not reflect', 'partial-write': 'failed rc=1',
              'restore-rc': 'Failed raw threshold restoration',
              'readback': 'Raw threshold presence/value was not restored'}
    if failure:
        with pytest.raises(AssertionError, match=errors[failure]):
            namespace['test_liquid_cool_config_commands'](instance)
    else:
        namespace['test_liquid_cool_config_commands'](instance)
    assert restore_attempted
    if failure == 'restore-rc':
        assert row != ({} if original is None else {field: original})
    else:
        assert row == ({} if original is None else {field: original})


@pytest.mark.parametrize('raw,expected,platform_calls', [
    (None, 0, 1), ('0', 0, 1), ('1', 0, 1), ('invalid', 0, 1),
    ('2', 2, 0), ('4294967295', 4294967295, 0),
])
def test_min_n_override_follows_thermal_contract(helpers, raw, expected, platform_calls):
    field = 'system_major_leak_num_min_sensors'
    row = {} if raw is None else {field: raw}
    helpers['get_platform_major_leak_num_min_sensors'] = Mock(return_value=0)
    host = _host({POLICY_KEYS[0]: row})
    assert helpers['get_major_leak_min_sensors'](host) == expected
    assert helpers['get_platform_major_leak_num_min_sensors'].call_count == platform_calls


@pytest.mark.parametrize('raw,expected', [
    ('{}', {}), ('  {}\n', {}),
    ("{'first': 'value', 'last': ''}", {'first': 'value', 'last': ''}),
    ("{'first': 'value', 'last': '  '}", {'first': 'value', 'last': '  '}),
    ("{'last': '\\t\\n'}\n", {'last': '\t\n'}),
    ("{'': ' ', '  ': ''}", {'': ' ', '  ': ''}),
])
def test_native_hash_preserves_final_empty_and_whitespace(helpers, raw, expected):
    host = SimpleNamespace(shell=Mock(return_value={'rc': 0, 'stdout': raw}))
    assert helpers['read_bmc_hash'](host, 'CONFIG_DB', POLICY_KEYS[0]) == expected


@pytest.mark.parametrize('raw', [
    '', ' ', '\t\n', 'field\n', 'field\nvalue', 'field\nvalue\nlast\n',
    'field\nvalue\nlast\n  ', 'a\n1\na\n2', 'a\n1\nlast',
    "{'a': 'power_off', 'a': 'syslog_only'}", "{'a': 'x', '\\x61': 'y'}",
    "{'a': None}", "{None: 'a'}", "{'a': 0}", "{'a': 1}", "{0: 'a'}", "{1: 'a'}",
    "{'a': True}", "{'a': b'value'}", "{**{'a': 'value'}}", 'None', '[]',
])
def test_unsupported_or_ambiguous_hash_output_fails(helpers, raw):
    host = SimpleNamespace(shell=Mock(return_value={'rc': 0, 'stdout': raw}))
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        helpers['get_effective_leak_policy'](host)
    assert host.shell.call_count == 1  # Never fall back after an undecodable canonical row.


@pytest.mark.parametrize('result', [
    {'rc': 0}, {'rc': 0, 'stdout': None}, {'rc': 0, 'stdout': 0},
    {'rc': 0, 'stdout': 1}, {'rc': 0, 'stdout': {}}, {'rc': 0, 'stdout': b'{}'},
])
def test_missing_or_nonstring_stdout_is_not_absence(helpers, result):
    host = SimpleNamespace(shell=Mock(return_value=result))
    with pytest.raises(AssertionError, match='Missing hash output'):
        helpers['get_effective_leak_policy'](host)
    assert host.shell.call_count == 1


@pytest.mark.parametrize('selector,line,expected', [
    ('minor_in_eventlog', 'bmcctld.event_log[1] Event MINOR_SYSTEM_LEAK', True),
    ('minor_in_eventlog', 'thermalctld.event_log[1] MINOR_SYSTEM_LEAK', False),
    ('minor_in_eventlog', 'bmcctld.event_log[1] MAJOR SYSTEM LEAK', False),
    ('major_in_eventlog', 'bmcctld.event_log[1] MAJOR SYSTEM LEAK detected', True),
    ('major_in_eventlog', 'thermalctld.event_log[1] MAJOR SYSTEM LEAK detected', False),
    ('major_in_eventlog', 'bmcctld.event_log[1] CRITICAL SYSTEM LEAK detected', False),
    ('major_in_eventlog', 'start-LogAnalyzer-bmcctld-MAJOR SYSTEM LEAK', False),
    ('rack_in_eventlog', 'bmcctld.event_log[1] MAJOR RACK MGR ALERT (key=test_trigger_alert)', True),
    ('rack_in_eventlog', 'bmcctld.event_log[1] RACK_MGR_MAJOR_EVENT key=test_trigger_alert', True),
    ('rack_in_eventlog', 'bmcctld.event_log[1] MAJOR RACK MGR ALERT key=test_trigger_alert_extra', False),
    ('rack_in_eventlog', 'bmcctld.event_log[1] MAJOR RACK MGR ALERT key=other', False),
    ('rack_in_eventlog', 'thermalctld.event_log[1] MAJOR RACK MGR ALERT key=test_trigger_alert', False),
    ('rack_in_eventlog', 'bmcctld.event_log[1] CRITICAL RACK MGR ALERT key=test_trigger_alert', False),
    ('rack_in_eventlog', 'LogAnalyzer-bmcctld MAJOR RACK MGR ALERT key=test_trigger_alert', False),
])
def test_actual_event_log_selectors(selector, line, expected):
    """Compile only the actual list comprehension, not the disruptive enclosing caller."""
    tree = ast.parse(BMC.read_text())
    assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == selector for target in node.targets))
    result = {'match_messages': {'event.log': [line]}}
    namespace = dict(re=re, BMC_EVENT_LOG='event.log', r2_ev=result, r2a_ev=result, r3_ev=result,
                     alert_severity='MAJOR', alert_key='test_trigger_alert')
    isolated = ast.Module(body=[assignment], type_ignores=[])
    exec(compile(isolated, str(BMC), 'exec'), namespace)
    assert namespace[selector] == ([line] if expected else [])


@pytest.fixture
def publisher_helpers():
    return _load(UTILS, ('is_liquid_cooling_updater_enabled', 'require_liquid_cooling_publisher'))


def _publisher_host(namespace, capability='False', override=False, source=True, argv=None, rc=0):
    # Independent installed-source-shaped fixture, not values lifted from the guard.
    contract = """parser.add_argument('--enable_liquid_cooling', action='store_true', default=False)
if not enable_liquid_cooling:
    enable_liquid_cooling = bool(self.chassis.is_liquid_cooled())
self.liquid_cooling_updater = LiquidCoolingUpdater(self.chassis, liquid_cooling_update_interval) \
if enable_liquid_cooling else None
"""
    namespace['_read_pmon_daemon_source'] = Mock(return_value=contract if source else 'unknown = True')
    if argv is None:
        argv = ['/usr/bin/python3', '/usr/local/bin/thermalctld',
                '--thermal-monitor-update-interval', '60']
        if override:
            argv += ['--enable_liquid_cooling']

    def shell(command, **kwargs):
        if command == 'docker exec pmon cat /proc/73/cmdline':
            return {'rc': 0, 'stdout': '\x00'.join(argv) + '\x00'}
        assert command.startswith('docker exec pmon python3 -B -c '), command
        return {'rc': rc, 'stdout': capability}

    return SimpleNamespace(shell=Mock(side_effect=shell),
                           get_pmon_daemon_status=Mock(return_value=('RUNNING', 73)))


@pytest.mark.parametrize('capability,expected', [('False', False), ('True', True)])
def test_publisher_enablement_boolean(publisher_helpers, capability, expected):
    host = _publisher_host(publisher_helpers, capability=capability)
    assert publisher_helpers['is_liquid_cooling_updater_enabled'](host) is expected
    assert host.shell.call_count == 2


@pytest.mark.parametrize('capability,rc', [('False', 0), ('None', 0), ('', 1)])
def test_startup_override_precedes_capability(publisher_helpers, capability, rc):
    host = _publisher_host(publisher_helpers, capability=capability, rc=rc, override=True)
    assert publisher_helpers['is_liquid_cooling_updater_enabled'](host) is True
    assert host.shell.call_count == 1  # No capability invocation when overridden.


@pytest.mark.parametrize('capability,rc', [('False', 1), ('', 0), ('None', 0), ('0', 0),
                                           ('unknown', 0), (None, 0), ('False\nextra', 0)])
def test_platform_errors_do_not_become_disabled(publisher_helpers, capability, rc):
    host = _publisher_host(publisher_helpers, capability=capability, rc=rc)
    with pytest.raises(AssertionError, match='Cannot establish platform'):
        publisher_helpers['is_liquid_cooling_updater_enabled'](host)


def test_unknown_source_stops_before_query(publisher_helpers):
    host = _publisher_host(publisher_helpers, source=False)
    with pytest.raises(AssertionError, match='Unrecognized thermalctld'):
        publisher_helpers['is_liquid_cooling_updater_enabled'](host)
    host.shell.assert_not_called()


@pytest.mark.parametrize('argv', [[], ['thermalctld'], ['/usr/bin/python3', '/other/thermalctld'],
                                  ['/usr/bin/python3', '/usr/local/bin/thermalctld', '--unknown'],
                                  ['/usr/bin/python3', '/usr/local/bin/thermalctld', '--enable_liquid']])
def test_unknown_startup_is_not_disabled(publisher_helpers, argv):
    host = _publisher_host(publisher_helpers, argv=argv)
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        publisher_helpers['is_liquid_cooling_updater_enabled'](host)
    assert host.shell.call_count == 1


def test_startup_read_error_stops_before_capability(publisher_helpers):
    host = _publisher_host(publisher_helpers)
    host.shell.side_effect = None
    host.shell.return_value = {'rc': 1, 'stdout': ''}
    with pytest.raises(AssertionError, match='Cannot read thermalctld'):
        publisher_helpers['is_liquid_cooling_updater_enabled'](host)
    assert host.shell.call_count == 1


@pytest.mark.parametrize('override', [False, True])
def test_daemon_restart_invalidates_query(publisher_helpers, override):
    host = _publisher_host(publisher_helpers, override=override)
    host.get_pmon_daemon_status.side_effect = [('RUNNING', 73), ('RUNNING', 74)]
    with pytest.raises(AssertionError, match='changed during applicability'):
        publisher_helpers['is_liquid_cooling_updater_enabled'](host)


@pytest.mark.parametrize('enabled,row,outcome', [
    (False, {}, 'skip'), (True, {}, 'fail'), (True, {'device_leak_status': ''}, 'fail'),
    (True, {'device_leak_status': 'None'}, 'None'),
    (True, {'device_leak_status': 'MINOR'}, 'MINOR'),
    (True, {'device_leak_status': 'MAJOR'}, 'MAJOR'),
    (True, {'device_leak_status': 'CRITICAL'}, 'CRITICAL'),
])
def test_publisher_missing_row_is_not_normal(publisher_helpers, enabled, row, outcome):
    publisher_helpers['is_liquid_cooling_updater_enabled'] = Mock(return_value=enabled)
    read = publisher_helpers['read_bmc_hash'] = Mock(return_value=row)
    host = object()
    if outcome == 'skip':
        with pytest.raises(pytest.skip.Exception, match='not enabled'):
            publisher_helpers['require_liquid_cooling_publisher'](host)
        read.assert_not_called()
    elif outcome == 'fail':
        with pytest.raises(AssertionError, match='missing/unknown'):
            publisher_helpers['require_liquid_cooling_publisher'](host)
    else:
        assert publisher_helpers['require_liquid_cooling_publisher'](host) == outcome


def test_original_event_node_has_case_local_admission():
    tree = ast.parse(BMC.read_text())
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == 'test_bmcctld_event_trigger')
    assert ast.literal_eval(method.decorator_list[0].args[1]) == [
        'system_leak', 'rack_alert', 'admin', 'critical_leak']
    gate = method.body[1]
    assert isinstance(gate, ast.If)
    assert ast.literal_eval(gate.test.comparators[0]) == ('system_leak', 'critical_leak')
    assert 'require_liquid_cooling_publisher' in ast.unparse(gate)
    # No applicability fixture can skip the independent cases or start API service.
    assert [a.arg for a in method.args.args] == ['self', 'event']
    text = ast.unparse(method)
    assert text.index('require_liquid_cooling_publisher') < text.index('make_bmc_loganalyzer')
    assert text.index('require_liquid_cooling_publisher') < text.index('redis_hset')


def test_thermal_admission_precedes_mocker_construction():
    tree = ast.parse(THERMAL.read_text())
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                  and n.name == 'test_thermalctld_leak_severity_aggregation')
    text = ast.unparse(method)
    assert text.index('require_liquid_cooling_publisher') < text.index('mocker_factory(')
    assert "baseline in ('MINOR', 'MAJOR', 'CRITICAL')" in text


@pytest.mark.parametrize('event', ['system_leak', 'critical_leak'])
def test_original_event_disabled_stops_before_writes(event):
    namespace = _load(BMC, ('test_bmcctld_event_trigger',))

    def disabled(host):
        pytest.skip('publisher not enabled')

    namespace['require_liquid_cooling_publisher'] = disabled
    # No logger, Redis helper, policy reader or power helper is supplied: reaching
    # one instead of skipping fails this control. Execute only after source review.
    with pytest.raises(pytest.skip.Exception, match='not enabled'):
        namespace['test_bmcctld_event_trigger'](SimpleNamespace(duthost=object()), event)


def test_rack_consumer_does_not_query_publisher():
    namespace = _load(BMC, ('test_bmcctld_event_trigger',))
    namespace['require_liquid_cooling_publisher'] = Mock(side_effect=AssertionError('wrong scope'))
    namespace['is_major_leak_supported'] = Mock(return_value=True)
    namespace['action_is_syslog_only'] = Mock(return_value=False)
    with pytest.raises(pytest.skip.Exception, match='rack_mgr_minor_alert_action'):
        namespace['test_bmcctld_event_trigger'](SimpleNamespace(duthost=object()), 'rack_alert')
    namespace['require_liquid_cooling_publisher'].assert_not_called()
