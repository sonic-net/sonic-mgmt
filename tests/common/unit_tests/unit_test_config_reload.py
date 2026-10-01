"""Isolated regressions for minigraph reload's zebra and golden link-training restoration.

Run from the repository root with::

    python -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_config_reload.py \
        -o log_format='%(message)s' -o log_cli_format='%(message)s' -v

The collection boundary also avoids importing the parent tests.common package,
which requires Linux-only integration dependencies.
"""

import importlib.util
import json
import logging
import shlex
import sys
import types
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest


MODEL_COMMAND = 'cat /usr/local/yang-models/sonic-device_metadata.yang'
WRITE_COMMAND = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" zebra_nexthop '
SUPPORTED_MODEL = 'module sonic-device_metadata { leaf zebra_nexthop { type string; } }'


@pytest.fixture
def reload_module(monkeypatch):
    """Load the real reload code without importing device/integration dependencies."""
    def assert_condition(condition, message):
        assert condition, message

    dependencies = {
        'tests.common.helpers.assertions': {'pytest_assert': assert_condition},
        'tests.common.helpers.parallel_utils': {'synchronized_config_reload': lambda fn: fn},
        'tests.common.plugins.loganalyzer.utils': {'support_ignore_loganalyzer': lambda fn: fn},
        'tests.common.platform.processes_utils': {'wait_critical_processes': Mock()},
        'tests.common.utilities': {'wait_until': Mock(side_effect=lambda timeout, interval, delay, fn: fn())},
        'tests.common.constants': {'GOLDEN_CONFIG_DB_PATH_ORI': '/etc/sonic/golden_config_db.json.origin.backup'},
        'tests.common.configlet.utils': {'chk_for_pfc_wd': Mock()},
        'tests.common.platform.interface_utils': {'check_interface_status_of_up_ports': Mock()},
        'tests.common.helpers.dut_utils': {'ignore_t2_syslog_msgs': Mock()},
        'tests.common.vs_data': {'is_vs_device': Mock(return_value=False)},
    }
    stubs = {}
    for name, attributes in dependencies.items():
        stub = types.ModuleType(name)
        stub.__dict__.update(attributes)
        stubs[name] = stub
    with patch.dict(sys.modules, stubs):
        path = Path(__file__).resolve().parents[1] / 'config_reload.py'
        spec = importlib.util.spec_from_file_location('unit_target_config_reload', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    monkeypatch.setattr(module.time, 'sleep', Mock())
    monkeypatch.setattr(module, 'is_upstream_t2', Mock(return_value=False))
    return module


@pytest.fixture
def sonic_host():
    """Mock only the device interactions needed for a normal minigraph reload."""
    host = Mock()
    host.hostname = 'unit-test-dut'
    host.facts = {'asic_type': 'broadcom'}
    host.is_multi_asic = False
    host.duthosts.request.config.getoption.return_value = False
    host.get_facts.return_value = {'modular_chassis': False}
    host.dut_basic_facts.return_value = {'ansible_facts': {'dut_basic_facts': {}}}
    host.minigraph_facts.return_value = {
        'ansible_facts': {'minigraph_device_metadata': {'zebra_nexthop': 'disabled'}}}
    host.shell.return_value = {'rc': 0, 'stdout': SUPPORTED_MODEL, 'stderr': ''}
    host.yang_validate.return_value = True
    return host


def _reload_and_check_validation(reload_module, sonic_host):
    reload_module.config_reload(sonic_host, config_source='minigraph', override_config=True)
    commands = [entry.args[0] for entry in sonic_host.shell.call_args_list]
    assert commands[0].startswith('config load_minigraph -y -o')
    assert commands[-2:] == ['config bgp startup all', 'config save -y']
    reload_module.time.sleep.assert_has_calls([call(60), call(120)])
    reload_module.wait_until.assert_called_once_with(120, 30, 0, sonic_host.yang_validate)
    sonic_host.yang_validate.assert_called_once_with()
    return commands


@pytest.mark.parametrize('model', [
    'module old { leaf hostname { type string; } }',
    '// leaf zebra_nexthop { type string; }\nmodule old {}',
    '/*\nleaf zebra_nexthop { type string; }\n*/ module old {}',
    'description "example: leaf zebra_nexthop { type string; }";',
    "description 'example: leaf zebra_nexthop { type string; }';",
    'leaf zebra_nexthop_extra { type string; }',
    'leaf-list zebra_nexthop { type string; }',
])
def test_unsupported_schema_skips_write_but_validates(reload_module, sonic_host, caplog, model):
    """An unsupported leaf is logged and never written; reload and YANG still run."""
    sonic_host.shell.return_value = {'rc': 0, 'stdout': model, 'stderr': ''}
    with caplog.at_level(logging.INFO, logger=reload_module.__name__):
        commands = _reload_and_check_validation(reload_module, sonic_host)
    assert MODEL_COMMAND in commands
    assert not any(command.startswith(WRITE_COMMAND) for command in commands)
    assert 'Skipping zebra_nexthop restoration' in caplog.text
    assert 'does not support the zebra_nexthop leaf' in caplog.text
    assert not any('hdel' in command.lower() for command in commands)


@pytest.mark.parametrize('value', ['enabled', 'disabled'])
@pytest.mark.parametrize('declaration', [
    'leaf zebra_nexthop {',
    'leaf "zebra_nexthop" {',
    "leaf 'zebra_nexthop' {",
    'leaf /* comment */ zebra_nexthop\n{',
])
def test_supported_schema_restores_value(reload_module, sonic_host, value, declaration):
    """Both supported values are restored, including the truthy string disabled."""
    sonic_host.minigraph_facts.return_value['ansible_facts']['minigraph_device_metadata']['zebra_nexthop'] = value
    sonic_host.shell.return_value = {'rc': 0, 'stdout': declaration + ' type string; }', 'stderr': ''}
    commands = _reload_and_check_validation(reload_module, sonic_host)
    assert commands.count(MODEL_COMMAND) == 1
    assert commands.count(WRITE_COMMAND + value) == 1
    assert commands.index(MODEL_COMMAND) < commands.index(WRITE_COMMAND + value)


@pytest.mark.parametrize('facts', [
    {},
    {'minigraph_device_metadata': {}},
    {'minigraph_device_metadata': {'zebra_nexthop': None}},
])
def test_absent_metadata_does_not_probe_or_write(reload_module, sonic_host, facts):
    """No schema read or restoration is needed when minigraph has no value."""
    sonic_host.minigraph_facts.return_value = {'ansible_facts': facts}
    commands = _reload_and_check_validation(reload_module, sonic_host)
    assert MODEL_COMMAND not in commands
    assert not any(command.startswith(WRITE_COMMAND) for command in commands)


@pytest.mark.parametrize('failure', [
    {'rc': 1, 'stdout': '', 'stderr': 'Permission denied'},
    RuntimeError('device connection failed'),
])
def test_schema_read_failure_is_surfaced(reload_module, sonic_host, caplog, failure):
    """Probe errors fail explicitly rather than being reported as unsupported."""
    def shell(command, **kwargs):
        if command == MODEL_COMMAND:
            if isinstance(failure, Exception):
                raise failure
            return failure
        return {'rc': 0, 'stdout': '', 'stderr': ''}

    sonic_host.shell.side_effect = shell
    error = RuntimeError if isinstance(failure, Exception) else AssertionError
    message = 'device connection failed' if isinstance(failure, Exception) else 'Failed to read.*Permission denied'
    with pytest.raises(error, match=message):
        reload_module.config_reload(sonic_host, config_source='minigraph')
    commands = [entry.args[0] for entry in sonic_host.shell.call_args_list]
    assert not any(command.startswith(WRITE_COMMAND) for command in commands)
    assert 'Skipping zebra_nexthop restoration' not in caplog.text
    sonic_host.yang_validate.assert_not_called()


def test_restored_value_is_shell_quoted(reload_module, sonic_host):
    """A metadata value cannot introduce extra shell commands during restoration."""
    value = "disabled; echo 'unexpected'"
    sonic_host.minigraph_facts.return_value['ansible_facts']['minigraph_device_metadata']['zebra_nexthop'] = value
    commands = _reload_and_check_validation(reload_module, sonic_host)
    write = next(command for command in commands if command.startswith(WRITE_COMMAND))
    assert shlex.split(write) == [
        'sonic-db-cli', 'CONFIG_DB', 'hset', 'DEVICE_METADATA|localhost', 'zebra_nexthop', value]


def test_unsupported_schema_does_not_bypass_yang_failure(reload_module, sonic_host):
    """Unrelated or pre-existing invalid config still fails strict YANG validation."""
    sonic_host.shell.return_value = {'rc': 0, 'stdout': 'module old {}', 'stderr': ''}
    sonic_host.yang_validate.return_value = False
    with pytest.raises(AssertionError, match='Yang validation failed after config_reload'):
        reload_module.config_reload(sonic_host, config_source='minigraph')
    sonic_host.yang_validate.assert_called_once_with()


def test_config_db_reload_does_not_probe_schema(reload_module, sonic_host):
    """The compatibility guard changes only minigraph metadata restoration."""
    reload_module.config_reload(sonic_host)
    commands = [entry.args[0] for entry in sonic_host.shell.call_args_list]
    assert commands == ['config reload -h', 'config reload -y']
    sonic_host.minigraph_facts.assert_not_called()
    sonic_host.yang_validate.assert_called_once_with()


@pytest.mark.parametrize('value,model,has_request', [
    ('disabled', SUPPORTED_MODEL, True),
    ('disabled', 'module old {}', True),
    (None, 'module old {}', False),
])
def test_link_training_restoration_is_independent_of_zebra(reload_module, sonic_host, value, model, has_request):
    """Keep golden PORT restoration after the entire zebra guard and before the settling wait."""
    sonic_host.minigraph_facts.return_value['ansible_facts']['minigraph_device_metadata']['zebra_nexthop'] = value
    if not has_request:
        sonic_host.duthosts.request = None
    operations = []
    golden = {'PORT': {
        'Ethernet0': {'link_training': 'on'},
        'Ethernet4': {'link_training': 'off'},
        'Ethernet8': {'link_training': 'on'},
    }}

    def shell(command, **kwargs):
        operations.append(command)
        if command == MODEL_COMMAND:
            return {'rc': 0, 'stdout': model}
        if command == 'cat ' + reload_module.GOLDEN_CONFIG_DB_PATH_ORI:
            return {'rc': 0, 'stdout': json.dumps(golden)}
        if command == 'sonic-db-cli CONFIG_DB keys "PORT|*"':
            return {'rc': 0, 'stdout_lines': ['PORT|Ethernet0', 'PORT|Ethernet4']}
        return {'rc': 0, 'stdout': '', 'stderr': ''}

    sonic_host.shell.side_effect = shell
    reload_module.time.sleep.side_effect = lambda seconds: operations.append(('sleep', seconds))
    reload_module.config_reload(sonic_host, config_source='minigraph')
    link_command = ('sonic-db-cli CONFIG_DB hset "PORT|Ethernet0" link_training on && '
                    'sonic-db-cli CONFIG_DB hset "PORT|Ethernet4" link_training off')
    assert operations.count(link_command) == 1
    assert operations.index(link_command) < operations.index(('sleep', 60))
    assert not any('hset "PORT|Ethernet8"' in str(operation) for operation in operations)
    if value and model == SUPPORTED_MODEL:
        assert operations.index(WRITE_COMMAND + value) < operations.index(link_command)
    else:
        assert not any(isinstance(operation, str) and operation.startswith(WRITE_COMMAND) for operation in operations)
    assert (MODEL_COMMAND in operations) is bool(value)
    sonic_host.yang_validate.assert_called_once_with()


@pytest.mark.parametrize('override_config,macsec_enabled,is_dut', [
    (True, False, True),
    (False, True, True),
    (False, False, False),
])
def test_link_training_keeps_upstream_override_and_device_gates(
        reload_module, sonic_host, override_config, macsec_enabled, is_dut):
    """Golden override and fanout reloads must not acquire the new PORT-restoration side effect."""
    sonic_host.duthosts.request.config.getoption.return_value = macsec_enabled
    with patch.object(reload_module, '_reapply_golden_link_training') as reapply:
        reload_module.config_reload(
            sonic_host, config_source='minigraph', override_config=override_config, is_dut=is_dut)
    reapply.assert_not_called()
    commands = [entry.args[0] for entry in sonic_host.shell.call_args_list]
    assert (' -o' in commands[0]) is (override_config or macsec_enabled)
    assert WRITE_COMMAND + 'disabled' in commands


def test_link_training_keeps_upstream_multi_asic_guard(reload_module, sonic_host):
    """The inherited link-training helper remains a no-op for multi-ASIC devices."""
    sonic_host.is_multi_asic = True
    reload_module._reapply_golden_link_training(sonic_host, reload_module.DEFAULT_GOLDEN_CONFIG_PATH)
    sonic_host.shell.assert_not_called()
