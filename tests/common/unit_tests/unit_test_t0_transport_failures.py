"""Regressions for local transport failures found by the frozen T0 run."""
import ast
from datetime import datetime
import io
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name, namespace, owner=None):
    path = ROOT / relative
    tree = ast.parse(path.read_text())
    body = tree.body
    if owner:
        body = next(n for n in body if isinstance(n, ast.ClassDef) and n.name == owner).body
    node = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('database', ['APPL_DB', 'CONFIG_DB', 'CHASSIS_APP_DB', 'CHASSIS_STATE_DB'])
@pytest.mark.parametrize('use_tcp,transport', [(False, 'unix_socket'), (True, 'tcp')])
@pytest.mark.parametrize('kind', ['host', 'single-asic', 'asic3'])
def test_table_dump_preserves_endpoint_namespace_and_result(database, use_tcp, transport, kind):
    class Asic:
        pass
    host = SimpleNamespace(command=Mock(return_value={'stdout': '{"row":{"value":{"field":"value"}}}'}))
    host.sonichost = host
    selected = host
    if kind != 'host':
        selected = Asic()
        selected.namespace = 'asic3' if kind == 'asic3' else None
        selected.sonichost = host
    method = load('common/helpers/sonic_db.py', 'dump',
                  {'json': json, 'SonicAsic': Asic, 'DEFAULT_NAMESPACE': None}, 'SonicDbCli')
    assert method(SimpleNamespace(host=selected, database=database, USE_TCP=use_tcp),
                  'TABLE:') == {'row': {'value': {'field': 'value'}}}
    argv = shlex.split(host.command.call_args.args[0])
    if kind == 'asic3':
        assert argv[:5] == ['sudo', 'ip', 'netns', 'exec', 'asic3']
        argv = argv[5:]
    assert argv == ['sonic-db-dump', '-t', transport, '-n', database, '-y', '-k', '*TABLE:*']


@pytest.fixture
def weight_source():
    tree = ast.parse((ROOT / 'bgp/test_bgp_route_weight.py').read_text())
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'CHECK_SCRIPT' for t in n.targets))


@pytest.mark.parametrize('namespace', ['', 'asic3'])
@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_weight_script_uses_socket_and_retains_route_assertion_inputs(tmp_path, weight_source, namespace, family):
    cli = tmp_path / 'sonic-db-cli'
    cli.write_text('''#!/usr/bin/env python3
import sys
args=sys.argv[1:]
assert args.pop(0)=='-s'
if args[0]=='-n':
 assert args[1]=='asic3'
 args=args[2:]
assert args.pop(0)=='APPL_DB'
if args[0]=='KEYS':print('ROUTE_TABLE:10.1.0.0/24\\nROUTE_TABLE:fc00:1::/64')
else:
 assert args[0]=='HGETALL'
 print({'protocol':'bgp','weight':'1,1','nexthop':'10.0.0.1,10.0.0.2'})
''')
    cli.chmod(0o755)
    result = subprocess.run(['python3', '-c', weight_source, family, namespace], env=dict(os.environ,
                            PATH=str(tmp_path)+':'+os.environ['PATH']), capture_output=True, text=True, check=True)
    data = json.loads(result.stdout)
    assert data['checked'] == 1
    assert data['missing'] == data['mismatched'] == data['invalid_weights'] == []


def test_weight_script_reports_command_failure_instead_of_empty_route_success(tmp_path, weight_source):
    cli = tmp_path / 'sonic-db-cli'
    cli.write_text('#!/bin/sh\nexit 9\n')
    cli.chmod(0o755)
    result = subprocess.run(['python3', '-c', weight_source, 'ipv4'], env=dict(os.environ,
                            PATH=str(tmp_path)+':'+os.environ['PATH']), capture_output=True, text=True)
    assert result.returncode != 0
    assert 'CalledProcessError' in result.stderr


@pytest.mark.parametrize('namespace', [None, 'asic3'])
@pytest.mark.parametrize('port', ['Ethernet0', 'PortChannel1', 'eth0'])
def test_snmp_fact_collection_retains_status_queries(namespace, port):
    host = Mock()
    host.interface_facts.return_value = {'ansible_facts': {'ansible_interface_facts': {port: {'mtu': 9100}}}}
    host.config_facts.return_value = {
        'ansible_facts': {
            'port_name_to_alias_map': {'Ethernet0': 'fortyGigE0/0'},
            'PORT': {'Ethernet0': {'speed': '100000', 'admin_status': 'up'}},
            'PORTCHANNEL': {'PortChannel1': {'admin_status': 'up'}},
            'MGMT_PORT': {'eth0': {'admin_status': 'up'}},
        },
    }
    host.shell.return_value = {'stdout': 'up'}
    method = load('snmp/test_snmp_interfaces.py', 'collect_all_facts', {})
    result = method(host, [port], namespace)
    cmd = shlex.split(host.shell.call_args.args[0])
    prefix = ['sonic-db-cli', '-s'] + (['-n', namespace] if namespace else [])
    assert cmd[:len(prefix)] == prefix
    assert cmd[len(prefix)] == ('STATE_DB' if port == 'eth0' else 'APPL_DB')
    assert list(result.values())[0]['operstatus'] == 'up'


@pytest.mark.parametrize('namespace', [None, 'asic3'])
@pytest.mark.parametrize('function', ['get_fib_info', 'get_t2_fib_info_per_asic'])
def test_fib_snapshot_preserves_namespace_key_and_fetch(namespace, function):
    asic = Mock(namespace=namespace)
    host = Mock(hostname='vlab-01', facts={'switch_type': 'switch'})
    host.asic_instance.return_value = asic
    values = {'datetime': datetime, 'json': json,
              'open': lambda *args: io.StringIO('{}'), 'logger': logging.getLogger(__name__)}
    method = load('common/fixtures/fib_utils.py', function, values)
    if function == 'get_fib_info':
        assert method(host, [(0, {})], {}, testname='test_decap') == {}
        assert host.fetch.call_count == 1
    else:
        hosts = SimpleNamespace(frontend_nodes=[host])
        assert method(hosts, {'vlab-01': [(0, {})]}, {'vlab-01': {}}, testname='test_decap') == [{}]
        assert host.fetch_no_slurp.call_count == 1
    cmd = shlex.split(asic.shell.call_args.args[0])
    assert cmd[:3] == ['sonic-db-dump', '-t', 'unix_socket']
    assert ('--netns' in cmd) == bool(namespace)
    if namespace:
        assert cmd[cmd.index('--netns')+1] == namespace
    assert cmd[cmd.index('-n')+1] == 'APPL_DB'
    assert cmd[cmd.index('-k')+1] == 'ROUTE_TABLE:*'


def test_pfcwd_fixture_reads_metadata_and_retains_original_restoration():
    method = load('generic_config_updater/test_pfcwd_status.py',
                  'set_default_pfcwd_config',
                  {'json': json,
                   'pytest_assert': lambda condition,
                   message: (_ for _ in ()).throw(AssertionError(message)) if not condition else None})
    host = Mock()
    host.shell.return_value = {
        'stdout': '{"DEVICE_METADATA|localhost":{"value":{"default_pfcwd_status":"enable"}}}', 'rc': 0}
    fixture = method(host)
    next(fixture)
    assert shlex.split(host.shell.call_args.args[0]) == [
        'sonic-db-dump', '-t', 'unix_socket', '-n', 'CONFIG_DB', '-y', '-k', 'DEVICE_METADATA|localhost',
    ]
    with pytest.raises(StopIteration):
        next(fixture)
    assert [call.args[0] for call in host.shell.call_args_list][-2:] == [
        'config pfcwd stop', 'config pfcwd start_default',
    ]


@pytest.mark.parametrize('multi', [False, True])
@pytest.mark.parametrize('relative,name', [
    ('generic_config_updater/test_static_route.py', 'setup_and_cleanup'),
    ('generic_config_updater/test_srv6.py', 'setup_and_cleanup'),
    ('srv6/test_srv6_static_config.py', 'test_uN_config'),
])
def test_route_and_srv6_configuration_commands_retain_namespace(relative, name, multi):
    import inspect

    class ObservedFirstCommand(Exception):
        pass
    host = Mock(is_multi_asic=multi)
    host.get_namespace_from_asic_id.return_value = 'asic3' if multi else None
    host.command.side_effect = ObservedFirstCommand
    method = load(relative, name, {'create_checkpoint': Mock()})
    arguments = {key: ({'vlab-01': host} if key == 'duthosts' else 'vlab-01' if 'hostname' in key else 3)
                 for key in inspect.signature(method).parameters}
    with pytest.raises(ObservedFirstCommand):
        result = method(**arguments)
        if inspect.isgenerator(result):
            next(result)
    argv = shlex.split(host.command.call_args.args[0])
    expected = ['sonic-db-cli', '-s'] + (['-n', 'asic3'] if multi else [])
    assert argv[:len(expected)] == expected
    assert argv[len(expected):len(expected)+2] == ['CONFIG_DB', 'HSET']


@pytest.mark.parametrize('multi', [False, True])
@pytest.mark.parametrize('interface', ['Ethernet0', 'PortChannel101'])
def test_mtu_observation_reads_socket_and_preserves_restoration(multi, interface):
    def require(condition, message):
        assert condition, message
    host = Mock(is_multi_asic=multi)
    host.get_namespace_from_asic_id.return_value = 'asic3'
    host.command.return_value = {'stdout': '9100'}
    observed = []

    def shell(command):
        observed.append(command)
        return {'stdout': str(len(observed)) if 'sonic-db-dump -t unix_socket' in command else '0'}
    host.shell.side_effect = shell
    method = load('drop_packets/test_drop_counters.py', 'mtu_config',
                  {'NAMESPACE_PREFIX': 'sudo ip netns exec {} ', 'pytest_assert': require,
                   'wait_until': lambda timeout, interval, delay, condition: condition()})
    fixture = method({'vlab-01': host}, 'vlab-01')
    config = next(fixture)
    config.set_mtu(1500, interface, 3 if multi else None)
    assert len(observed) == 2
    assert all('-t unix_socket -n ASIC_DB' in cmd for cmd in observed)
    assert all(cmd.startswith('sudo ip netns exec asic3 ') == multi for cmd in observed)
    with pytest.raises(StopIteration):
        next(fixture)
    assert host.command.call_args.args[0].endswith('mtu 9100')
